package analyzer

import (
	"encoding/json"
	"errors"
	"sync"
	"time"
)

type RateLimitConfig struct {
	Enabled           bool `json:"enabled"`
	IPLimit           int  `json:"ip_limit"`
	IPWindowSecs      int  `json:"ip_window_secs"`
	URLLimit          int  `json:"url_limit"`
	URLWindowSecs     int  `json:"url_window_secs"`
	UALimit           int  `json:"ua_limit"`
	UAWindowSecs      int  `json:"ua_window_secs"`
	BlockDurationSecs int  `json:"block_duration_secs"`
}

type AnalyzerSetting struct {
	Name        string      `json:"name"`
	Type        string      `json:"type"`
	Enabled     bool        `json:"enabled"`
	Threshold   float64     `json:"threshold,omitempty"`
	Description string      `json:"description,omitempty"`
	Metadata    interface{} `json:"metadata,omitempty"`
}

type AnalyzerSettings struct {
	mu sync.RWMutex

	analyzers map[string]*AnalyzerSetting
	rateLimit *RateLimitConfig

	persistFunc PersistFunc
	loadFunc    LoadFunc

	autoSave       bool
	autoSaveDelay  time.Duration
	lastSaveTime   time.Time
	pendingChanges bool
	stopChan       chan struct{}
}

type PersistFunc func(settings *AnalyzerSettings) error
type LoadFunc func() (*AnalyzerSettings, error)

type SettingsOption func(s *AnalyzerSettings)

func WithAutoSave(enabled bool, delay time.Duration) SettingsOption {
	return func(s *AnalyzerSettings) {
		s.autoSave = enabled
		s.autoSaveDelay = delay
	}
}

func WithPersistence(persist PersistFunc, load LoadFunc) SettingsOption {
	return func(s *AnalyzerSettings) {
		s.persistFunc = persist
		s.loadFunc = load
	}
}

func NewAnalyzerSettings(opts ...SettingsOption) *AnalyzerSettings {
	settings := &AnalyzerSettings{
		analyzers: make(map[string]*AnalyzerSetting),
		rateLimit: &RateLimitConfig{
			Enabled:           true,
			IPLimit:           60,
			IPWindowSecs:      60,
			URLLimit:          120,
			URLWindowSecs:     60,
			UALimit:           200,
			UAWindowSecs:      60,
			BlockDurationSecs: 300,
		},
		autoSave:      true,
		autoSaveDelay: 5 * time.Second,
		stopChan:      make(chan struct{}),
	}

	for _, opt := range opts {
		opt(settings)
	}

	settings.initDefaultAnalyzers()
	return settings
}

func (s *AnalyzerSettings) initDefaultAnalyzers() {
	defaults := []AnalyzerSetting{
		{
			Name:        "sql_injection_analyzer",
			Type:        "sql_injection",
			Enabled:     true,
			Threshold:   0.7,
			Description: "SQL Injection Detection",
		},
		{
			Name:        "xss_analyzer",
			Type:        "xss",
			Enabled:     true,
			Threshold:   0.6,
			Description: "Cross-Site Scripting Detection",
		},
		{
			Name:        "command_injection_analyzer",
			Type:        "command_injection",
			Enabled:     true,
			Threshold:   0.65,
			Description: "Command Injection Detection",
		},
		{
			Name:        "php_analyzer",
			Type:        "php_injection",
			Enabled:     true,
			Threshold:   0.65,
			Description: "PHP Injection Detection",
		},
		{
			Name:        "js_analyzer",
			Type:        "js_injection",
			Enabled:     true,
			Threshold:   0.65,
			Description: "JavaScript Injection Detection",
		},
	}

	for _, a := range defaults {
		analyzer := a
		s.analyzers[analyzer.Name] = &analyzer
	}
}

func (s *AnalyzerSettings) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.loadFunc != nil {
		loaded, err := s.loadFunc()
		if err != nil {
			return err
		}
		if loaded != nil {
			s.analyzers = loaded.analyzers
			s.rateLimit = loaded.rateLimit
			s.autoSave = loaded.autoSave
			s.autoSaveDelay = loaded.autoSaveDelay
		}
	}
	return nil
}

func (s *AnalyzerSettings) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.persistFunc != nil {
		return s.persistFunc(s)
	}
	return nil
}

func (s *AnalyzerSettings) scheduleAutoSave() {
	if !s.autoSave {
		return
	}

	s.mu.Lock()
	s.pendingChanges = true
	s.mu.Unlock()

	go func() {
		time.Sleep(s.autoSaveDelay)

		s.mu.Lock()
		if s.pendingChanges {
			s.pendingChanges = false
			s.lastSaveTime = time.Now()
		}
		s.mu.Unlock()

		if err := s.Save(); err != nil {
		}
	}()
}

func (s *AnalyzerSettings) SetAnalyzerEnabled(name string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	analyzer, exists := s.analyzers[name]
	if !exists {
		return ErrAnalyzerNotFound
	}

	analyzer.Enabled = enabled
	s.scheduleAutoSave()
	return nil
}

func (s *AnalyzerSettings) GetAnalyzerEnabled(name string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	analyzer, exists := s.analyzers[name]
	if !exists {
		return false, ErrAnalyzerNotFound
	}

	return analyzer.Enabled, nil
}

func (s *AnalyzerSettings) SetAnalyzerThreshold(name string, threshold float64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if threshold < 0 || threshold > 1 {
		return errors.New("threshold must be between 0 and 1")
	}

	analyzer, exists := s.analyzers[name]
	if !exists {
		return ErrAnalyzerNotFound
	}

	analyzer.Threshold = threshold
	s.scheduleAutoSave()
	return nil
}

func (s *AnalyzerSettings) GetAnalyzerThreshold(name string) (float64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	analyzer, exists := s.analyzers[name]
	if !exists {
		return 0, ErrAnalyzerNotFound
	}

	return analyzer.Threshold, nil
}

func (s *AnalyzerSettings) GetAllAnalyzerSettings() []*AnalyzerSetting {
	s.mu.RLock()
	defer s.mu.RUnlock()

	settings := make([]*AnalyzerSetting, 0, len(s.analyzers))
	for _, a := range s.analyzers {
		settings = append(settings, a)
	}
	return settings
}

func (s *AnalyzerSettings) GetAnalyzerSetting(name string) (*AnalyzerSetting, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	analyzer, exists := s.analyzers[name]
	if !exists {
		return nil, ErrAnalyzerNotFound
	}

	return analyzer, nil
}

func (s *AnalyzerSettings) SetAnalyzerSetting(name string, setting *AnalyzerSetting) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.analyzers[name]; !exists {
		return ErrAnalyzerNotFound
	}

	s.analyzers[name] = setting
	s.scheduleAutoSave()
	return nil
}

func (s *AnalyzerSettings) SetRateLimitConfig(config *RateLimitConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if config.IPLimit <= 0 || config.URLLimit <= 0 || config.UALimit <= 0 {
		return errors.New("rate limits must be positive")
	}

	if config.IPWindowSecs <= 0 || config.URLWindowSecs <= 0 || config.UAWindowSecs <= 0 {
		return errors.New("window seconds must be positive")
	}

	s.rateLimit = config
	s.scheduleAutoSave()
	return nil
}

func (s *AnalyzerSettings) GetRateLimitConfig() *RateLimitConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()

	config := *s.rateLimit
	return &config
}

func (s *AnalyzerSettings) SetRateLimitEnabled(enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.rateLimit.Enabled = enabled
	s.scheduleAutoSave()
	return nil
}

func (s *AnalyzerSettings) GetRateLimitEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.rateLimit.Enabled
}

func (s *AnalyzerSettings) SetIPRateLimit(limit int, windowSecs int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if limit <= 0 || windowSecs <= 0 {
		return errors.New("limit and window must be positive")
	}

	s.rateLimit.IPLimit = limit
	s.rateLimit.IPWindowSecs = windowSecs
	s.scheduleAutoSave()
	return nil
}

func (s *AnalyzerSettings) SetURLRateLimit(limit int, windowSecs int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if limit <= 0 || windowSecs <= 0 {
		return errors.New("limit and window must be positive")
	}

	s.rateLimit.URLLimit = limit
	s.rateLimit.URLWindowSecs = windowSecs
	s.scheduleAutoSave()
	return nil
}

func (s *AnalyzerSettings) SetUARateLimit(limit int, windowSecs int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if limit <= 0 || windowSecs <= 0 {
		return errors.New("limit and window must be positive")
	}

	s.rateLimit.UALimit = limit
	s.rateLimit.UAWindowSecs = windowSecs
	s.scheduleAutoSave()
	return nil
}

func (s *AnalyzerSettings) SetBlockDuration(seconds int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if seconds <= 0 {
		return errors.New("block duration must be positive")
	}

	s.rateLimit.BlockDurationSecs = seconds
	s.scheduleAutoSave()
	return nil
}

func (s *AnalyzerSettings) EnableAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, analyzer := range s.analyzers {
		analyzer.Enabled = true
	}
	s.rateLimit.Enabled = true
	s.scheduleAutoSave()
	return nil
}

func (s *AnalyzerSettings) DisableAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, analyzer := range s.analyzers {
		analyzer.Enabled = false
	}
	s.rateLimit.Enabled = false
	s.scheduleAutoSave()
	return nil
}

func (s *AnalyzerSettings) ResetToDefaults() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.analyzers = make(map[string]*AnalyzerSetting)
	s.initDefaultAnalyzers()

	s.rateLimit = &RateLimitConfig{
		Enabled:           true,
		IPLimit:           60,
		IPWindowSecs:      60,
		URLLimit:          120,
		URLWindowSecs:     60,
		UALimit:           200,
		UAWindowSecs:      60,
		BlockDurationSecs: 300,
	}

	s.scheduleAutoSave()
	return nil
}

func (s *AnalyzerSettings) ToJSON() (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data := struct {
		Analyzers []*AnalyzerSetting `json:"analyzers"`
		RateLimit *RateLimitConfig   `json:"rate_limit"`
	}{
		Analyzers: make([]*AnalyzerSetting, 0, len(s.analyzers)),
		RateLimit: s.rateLimit,
	}

	for _, a := range s.analyzers {
		data.Analyzers = append(data.Analyzers, a)
	}

	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
}

func (s *AnalyzerSettings) FromJSON(jsonStr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var data struct {
		Analyzers map[string]*AnalyzerSetting `json:"analyzers"`
		RateLimit *RateLimitConfig            `json:"rate_limit"`
	}

	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return err
	}

	if data.Analyzers != nil {
		s.analyzers = data.Analyzers
	}

	if data.RateLimit != nil {
		s.rateLimit = data.RateLimit
	}

	s.scheduleAutoSave()
	return nil
}

func (s *AnalyzerSettings) Close() error {
	select {
	case <-s.stopChan:
		return nil
	default:
		close(s.stopChan)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.pendingChanges {
		if err := s.Save(); err != nil {
			return err
		}
	}

	return nil
}

func (s *AnalyzerSettings) GetLastSaveTime() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastSaveTime
}

func (s *AnalyzerSettings) HasPendingChanges() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pendingChanges
}
