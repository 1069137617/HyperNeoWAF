package service

import (
	"errors"
	"fmt"
	"time"

	"github.com/waf-project/backend/internal/model"
	"github.com/waf-project/backend/internal/repository"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var (
	ErrIPNotFound      = errors.New("IP entry not found")
	ErrInvalidIPType   = errors.New("invalid IP list type")
	ErrIPAlreadyExists = errors.New("IP already exists in this list")
)

// IPListService handles IP blacklist/whitelist management
type IPListService struct {
	db          *gorm.DB
	redisClient repository.RedisClient
}

// NewIPListService creates a new IPListService instance
func NewIPListService(db *gorm.DB, redisClient repository.RedisClient) *IPListService {
	return &IPListService{
		db:          db,
		redisClient: redisClient,
	}
}

// AddIPRequest represents request to add an IP entry
type AddIPRequest struct {
	IP        string     `json:"ip" binding:"required,ip"`
	Type      string     `json:"type" binding:"required"`
	Reason    string     `json:"reason,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// ListIPResponse represents paginated IP list response
type ListIPResponse struct {
	Data       []model.IPListEntry `json:"data"`
	Total      int64               `json:"total"`
	Page       int                 `json:"page"`
	PageSize   int                 `json:"page_size"`
	TotalPages int                 `json:"total_pages"`
}

// AddIP adds a new IP to blacklist or whitelist
func (s *IPListService) AddIP(req *AddIPRequest, addedBy uint) (*model.IPListEntry, error) {
	if !isValidIPType(req.Type) {
		return nil, ErrInvalidIPType
	}

	// Check if IP already exists in the same type of list
	var existing model.IPListEntry
	result := s.db.Where("ip = ? AND type = ? AND deleted_at IS NULL", req.IP, req.Type).First(&existing)
	if result.Error == nil {
		return nil, ErrIPAlreadyExists
	}
	if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, result.Error
	}

	entry := model.IPListEntry{
		IP:        req.IP,
		Type:      req.Type,
		Reason:    req.Reason,
		ExpiresAt: req.ExpiresAt,
		AddedBy:   addedBy,
		Source:    model.IPListSources.API,
		IsActive:  true,
	}

	result = s.db.Create(&entry)
	if result.Error != nil {
		return nil, result.Error
	}

	// Sync to Redis
	s.syncIPToRedis(&entry)

	return &entry, nil
}

// AddIPFromPublicLibrary adds an IP from public IP library (without checking for duplicates)
func (s *IPListService) AddIPFromPublicLibrary(ip string, reason string) error {
	var existing model.IPListEntry
	result := s.db.Where("ip = ? AND type = ? AND source = ? AND deleted_at IS NULL", ip, model.IPListTypes.Blacklist, model.IPListSources.PublicLibrary).First(&existing)
	if result.Error == nil {
		return ErrIPAlreadyExists
	}
	if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return result.Error
	}

	entry := model.IPListEntry{
		IP:       ip,
		Type:     model.IPListTypes.Blacklist,
		Reason:   reason,
		AddedBy:  0,
		Source:   model.IPListSources.PublicLibrary,
		IsActive: true,
	}

	result = s.db.Create(&entry)
	if result.Error != nil {
		return result.Error
	}

	s.syncIPToRedis(&entry)
	return nil
}

// ListIPs retrieves paginated IP entries with filtering by type
func (s *IPListService) ListIPs(ipType string, page, pageSize int) (*ListIPResponse, error) {
	query := s.db.Model(&model.IPListEntry{}).Where("is_active = ?", true)

	if ipType != "" && (ipType == model.IPListTypes.Blacklist || ipType == model.IPListTypes.Whitelist) {
		query = query.Where("type = ?", ipType)
	}

	// Count total
	var total int64
	query.Count(&total)

	// Paginate
	offset := (page - 1) * pageSize
	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))

	var entries []model.IPListEntry
	result := query.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&entries)
	if result.Error != nil {
		return nil, result.Error
	}

	return &ListIPResponse{
		Data:       entries,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// GetIPByID retrieves a single IP entry by ID
func (s *IPListService) GetIPByID(entryID uint) (*model.IPListEntry, error) {
	var entry model.IPListEntry
	result := s.db.First(&entry, entryID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrIPNotFound
		}
		return nil, result.Error
	}
	return &entry, nil
}

// DeleteIP soft-deletes an IP entry and removes from Redis
func (s *IPListService) DeleteIP(entryID uint) error {
	var entry model.IPListEntry
	result := s.db.First(&entry, entryID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return ErrIPNotFound
		}
		return result.Error
	}

	// Soft delete
	result = s.db.Delete(&entry)
	if result.Error != nil {
		return result.Error
	}

	// Remove from Redis
	s.redisClient.Del(fmt.Sprintf("waf:%s:%s", entry.Type, entry.IP))

	return nil
}

// SyncAllIPsToRedis syncs all active IPs to Redis cache
func (s *IPListService) SyncAllIPsToRedis() error {
	types := []string{model.IPListTypes.Blacklist, model.IPListTypes.Whitelist}

	for _, ipType := range types {
		var entries []model.IPListEntry
		result := s.db.Where("type = ? AND is_active = ? AND (expires_at IS NULL OR expires_at > NOW())", ipType, true).Find(&entries)
		if result.Error != nil {
			continue
		}

		for _, entry := range entries {
			s.syncIPToRedis(&entry)
		}
	}

	logger.Info("Synced all active IP entries to Redis")
	return nil
}

// syncIPToRedis syncs a single IP entry to Redis
func (s *IPListService) syncIPToRedis(entry *model.IPListEntry) {
	redisKey := fmt.Sprintf("waf:%s:%s", entry.Type, entry.IP)

	value := fmt.Sprintf(`{"ip":"%s","reason":"%s","added_by":%d,"source":"%s"}`,
		entry.IP,
		entry.Reason,
		entry.AddedBy,
		entry.Source,
	)

	// Set TTL if expires_at is set
	var expireSeconds int64 = 0 // No expiry for permanent entries
	if entry.ExpiresAt != nil {
		expireSeconds = int64(time.Until(*entry.ExpiresAt).Seconds())
		if expireSeconds < 0 {
			expireSeconds = 0
		}
	}

	s.redisClient.Set(redisKey, value, expireSeconds)
}

// isValidIPType checks if the provided IP list type is valid
func isValidIPType(ipType string) bool {
	return ipType == model.IPListTypes.Blacklist || ipType == model.IPListTypes.Whitelist
}
