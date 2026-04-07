package service

// Copyright 2026 Yinuo. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"
)

const (
	PublicIPLibraryURL         = "https://blackip.ustc.edu.cn/list.php?txt"
	PublicIPLibraryFileName    = "public_malicious_ips.txt"
	PublicIPLibrarySource      = "public_ip_library"
	UpdateIntervalHours        = 24
	PublicIPLibraryAttribution = "恶意IP列表由中国科技大学（USTC）提供" // 公开IP库来源署名
)

var (
	ErrPublicIPLibraryNotEnabled = errors.New("public IP library is not enabled")
	ErrInvalidIPFormat           = errors.New("invalid IP format")
)

type PublicIPLibraryConfig struct {
	Enabled        bool
	LastUpdateTime time.Time
	IPCount        int
	UpdateError    string
}

type PublicIPLibraryService struct {
	db            *gorm.DB
	redisClient   RedisClient
	config        *PublicIPLibraryConfig
	configMu      sync.RWMutex
	stopChan      chan struct{}
	updateOnce    sync.Once
	ipListService *IPListService
}

type RedisClient interface {
	Get(key string) (string, error)
	Set(key string, value interface{}, expiration int64) error
	Del(key string) error
	SAdd(key string, members ...interface{}) error
	SMembers(key string) ([]string, error)
	Expire(key string, seconds int64) error
}

func NewPublicIPLibraryService(db *gorm.DB, redisClient RedisClient, ipListService *IPListService) *PublicIPLibraryService {
	return &PublicIPLibraryService{
		db:            db,
		redisClient:   redisClient,
		ipListService: ipListService,
		config: &PublicIPLibraryConfig{
			Enabled: false,
		},
		stopChan: make(chan struct{}),
	}
}

func (s *PublicIPLibraryService) SetEnabled(enabled bool) {
	s.configMu.Lock()
	defer s.configMu.Unlock()
	s.config.Enabled = enabled

	if enabled {
		s.updateOnce.Do(func() {
			go s.startScheduler()
		})
	}
}

func (s *PublicIPLibraryService) IsEnabled() bool {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	return s.config.Enabled
}

func (s *PublicIPLibraryService) GetConfig() PublicIPLibraryConfig {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	return *s.config
}

func (s *PublicIPLibraryService) startScheduler() {
	go func() {
		if err := s.Update(); err != nil {
			log.Printf("[PublicIPLibrary] Initial update failed: %v", err)
		}
	}()

	ticker := time.NewTicker(UpdateIntervalHours * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if s.IsEnabled() {
				if err := s.Update(); err != nil {
					log.Printf("[PublicIPLibrary] Scheduled update failed: %v", err)
				}
			}
		case <-s.stopChan:
			log.Println("[PublicIPLibrary] Scheduler stopped")
			return
		}
	}
}

func (s *PublicIPLibraryService) Stop() {
	close(s.stopChan)
}

func (s *PublicIPLibraryService) Update() error {
	s.configMu.RLock()
	if !s.config.Enabled {
		s.configMu.RUnlock()
		return ErrPublicIPLibraryNotEnabled
	}
	s.configMu.RUnlock()

	log.Println("[PublicIPLibrary] Starting IP list update...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, PublicIPLibraryURL, nil)
	if err != nil {
		s.recordUpdateError(err.Error())
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "WAF-PublicIPLibrary/1.0")

	client := &http.Client{
		Timeout: 5 * time.Minute,
	}

	resp, err := client.Do(req)
	if err != nil {
		s.recordUpdateError(err.Error())
		return fmt.Errorf("failed to fetch IP list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		s.recordUpdateError(fmt.Sprintf("HTTP %d", resp.StatusCode))
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	filePath, err := s.saveToFile(resp.Body)
	if err != nil {
		s.recordUpdateError(err.Error())
		return fmt.Errorf("failed to save IP list: %w", err)
	}

	ipCount, err := s.importFromFile(filePath)
	if err != nil {
		s.recordUpdateError(err.Error())
		return fmt.Errorf("failed to import IPs: %w", err)
	}

	s.configMu.Lock()
	s.config.LastUpdateTime = time.Now()
	s.config.IPCount = ipCount
	s.config.UpdateError = ""
	s.configMu.Unlock()

	log.Printf("[PublicIPLibrary] Update completed: %d IPs imported", ipCount)
	return nil
}

func (s *PublicIPLibraryService) saveToFile(body io.Reader) (string, error) {
	dataDir := s.getDataDirectory()
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create data directory: %w", err)
	}

	filePath := filepath.Join(dataDir, PublicIPLibraryFileName)

	file, err := os.Create(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	if _, err := writer.ReadFrom(body); err != nil {
		return "", fmt.Errorf("failed to write to file: %w", err)
	}

	if err := writer.Flush(); err != nil {
		return "", fmt.Errorf("failed to flush writer: %w", err)
	}

	return filePath, nil
}

func (s *PublicIPLibraryService) getDataDirectory() string {
	execPath, err := os.Executable()
	if err != nil {
		return "./data/public_ip_library"
	}
	dir := filepath.Dir(execPath)
	return filepath.Join(dir, "data", "public_ip_library")
}

func (s *PublicIPLibraryService) importFromFile(filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	importCount := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		ip := s.extractIP(line)
		if ip == "" {
			continue
		}

		if s.ipListService != nil {
			if err := s.ipListService.AddIPFromPublicLibrary(ip, PublicIPLibrarySource); err != nil {
				if !errors.Is(err, ErrIPAlreadyExists) {
					log.Printf("[PublicIPLibrary] Failed to add IP %s: %v", ip, err)
				}
			} else {
				importCount++
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return importCount, fmt.Errorf("error reading file: %w", err)
	}

	return importCount, nil
}

func (s *PublicIPLibraryService) extractIP(line string) string {
	line = strings.TrimSpace(line)

	parts := strings.Fields(line)
	if len(parts) > 0 {
		ip := parts[0]
		if s.isValidIP(ip) {
			return ip
		}
	}

	if s.isValidIP(line) {
		return line
	}

	return ""
}

func (s *PublicIPLibraryService) isValidIP(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}

	for _, part := range parts {
		var num int
		if _, err := fmt.Sscanf(part, "%d", &num); err != nil {
			return false
		}
		if num < 0 || num > 255 {
			return false
		}
	}

	return true
}

func (s *PublicIPLibraryService) recordUpdateError(errMsg string) {
	s.configMu.Lock()
	defer s.configMu.Unlock()
	s.config.UpdateError = errMsg
}

func (s *PublicIPLibraryService) GetLastUpdateTime() time.Time {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	return s.config.LastUpdateTime
}

func (s *PublicIPLibraryService) GetIPCount() int {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	return s.config.IPCount
}

func (s *PublicIPLibraryService) GetUpdateError() string {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	return s.config.UpdateError
}
