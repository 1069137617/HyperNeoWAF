package analyzer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type CacheStats struct {
	Hits        int64
	Misses      int64
	Evictions   int64
	CurrentSize int64
	MaxSize     int64
	AvgLatency  time.Duration
}

func (s *CacheStats) HitRate() float64 {
	total := atomic.LoadInt64(&s.Hits) + atomic.LoadInt64(&s.Misses)
	if total == 0 {
		return 0.0
	}
	return float64(atomic.LoadInt64(&s.Hits)) / float64(total)
}

type CacheEntry struct {
	Key         string
	Value       interface{}
	ExpiresAt   time.Time
	AccessedAt  time.Time
	AccessCount int64
	Size        int64
}

func (e *CacheEntry) IsExpired() bool {
	if e.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(e.ExpiresAt)
}

func (e *CacheEntry) UpdateAccess() {
	e.AccessedAt = time.Now()
	atomic.AddInt64(&e.AccessCount, 1)
}

type BaseCache struct {
	entries     map[string]*CacheEntry
	mu          sync.RWMutex
	maxSize     int64
	currentSize int64
	stats       *CacheStats
	evictPolicy EvictPolicy
	defaultTTL  time.Duration
	cleanupDone chan struct{}
}

type EvictPolicy int

const (
	LRU EvictPolicy = iota
	LFU
	FIFO
	TTL
)

type Cache interface {
	Get(key string) (interface{}, bool)
	Set(key string, value interface{}, ttl time.Duration)
	Delete(key string) bool
	Clear()
	Size() int64
	Stats() *CacheStats
}

func NewBaseCache(maxSize int, evictPolicy EvictPolicy, defaultTTL time.Duration) *BaseCache {
	c := &BaseCache{
		entries:     make(map[string]*CacheEntry),
		maxSize:     int64(maxSize),
		stats:       &CacheStats{MaxSize: int64(maxSize)},
		evictPolicy: evictPolicy,
		defaultTTL:  defaultTTL,
		cleanupDone: make(chan struct{}),
	}

	go c.cleanupLoop()

	return c
}

func (c *BaseCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	entry, exists := c.entries[key]
	c.mu.RUnlock()

	if !exists {
		atomic.AddInt64(&c.stats.Misses, 1)
		return nil, false
	}

	if entry.IsExpired() {
		c.Delete(key)
		atomic.AddInt64(&c.stats.Misses, 1)
		return nil, false
	}

	entry.UpdateAccess()
	atomic.AddInt64(&c.stats.Hits, 1)

	return entry.Value, true
}

func (c *BaseCache) Set(key string, value interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if ttl == 0 {
		ttl = c.defaultTTL
	}

	valueSize := estimateSize(value)

	if entry, exists := c.entries[key]; exists {
		c.currentSize -= entry.Size
		entry.Value = value
		entry.ExpiresAt = time.Now().Add(ttl)
		entry.Size = valueSize
		c.currentSize += valueSize
		entry.UpdateAccess()
		return
	}

	if c.currentSize >= c.maxSize {
		c.evict()
	}

	entry := &CacheEntry{
		Key:         key,
		Value:       value,
		ExpiresAt:   time.Now().Add(ttl),
		AccessedAt:  time.Now(),
		AccessCount: 1,
		Size:        valueSize,
	}

	c.entries[key] = entry
	c.currentSize += valueSize
	atomic.StoreInt64(&c.stats.CurrentSize, c.currentSize)
}

func (c *BaseCache) Delete(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.entries[key]
	if !exists {
		return false
	}

	c.currentSize -= entry.Size
	atomic.StoreInt64(&c.stats.CurrentSize, c.currentSize)
	delete(c.entries, key)
	atomic.AddInt64(&c.stats.Evictions, 1)

	return true
}

func (c *BaseCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*CacheEntry)
	c.currentSize = 0
	atomic.StoreInt64(&c.stats.CurrentSize, 0)
}

func (c *BaseCache) Size() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return int64(len(c.entries))
}

func (c *BaseCache) Stats() *CacheStats {
	return &CacheStats{
		Hits:        atomic.LoadInt64(&c.stats.Hits),
		Misses:      atomic.LoadInt64(&c.stats.Misses),
		Evictions:   atomic.LoadInt64(&c.stats.Evictions),
		CurrentSize: atomic.LoadInt64(&c.stats.CurrentSize),
		MaxSize:     c.stats.MaxSize,
		AvgLatency:  c.stats.AvgLatency,
	}
}

func (c *BaseCache) evict() {
	switch c.evictPolicy {
	case LRU:
		c.evictLRU()
	case LFU:
		c.evictLFU()
	case FIFO:
		c.evictFIFO()
	case TTL:
		c.evictTTL()
	default:
		c.evictLRU()
	}
}

func (c *BaseCache) evictLRU() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range c.entries {
		if oldestTime.IsZero() || entry.AccessedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.AccessedAt
		}
	}

	if oldestKey != "" {
		delete(c.entries, oldestKey)
		atomic.AddInt64(&c.stats.Evictions, 1)
	}
}

func (c *BaseCache) evictLFU() {
	var leastFreqKey string
	var leastFreq int64 = -1

	for key, entry := range c.entries {
		if leastFreq == -1 || entry.AccessCount < leastFreq {
			leastFreqKey = key
			leastFreq = entry.AccessCount
		}
	}

	if leastFreqKey != "" {
		delete(c.entries, leastFreqKey)
		atomic.AddInt64(&c.stats.Evictions, 1)
	}
}

func (c *BaseCache) evictFIFO() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range c.entries {
		if oldestTime.IsZero() || entry.AccessedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.AccessedAt
		}
	}

	if oldestKey != "" {
		delete(c.entries, oldestKey)
		atomic.AddInt64(&c.stats.Evictions, 1)
	}
}

func (c *BaseCache) evictTTL() {
	now := time.Now()
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range c.entries {
		if entry.ExpiresAt.Before(now) {
			delete(c.entries, key)
			atomic.AddInt64(&c.stats.Evictions, 1)
			continue
		}

		if oldestTime.IsZero() || entry.ExpiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.ExpiresAt
		}
	}

	if oldestKey != "" && c.currentSize >= c.maxSize {
		delete(c.entries, oldestKey)
		atomic.AddInt64(&c.stats.Evictions, 1)
	}
}

func (c *BaseCache) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer close(c.cleanupDone)

	for {
		select {
		case <-ticker.C:
			c.cleanup()
		}
	}
}

func (c *BaseCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			c.currentSize -= entry.Size
			delete(c.entries, key)
			atomic.AddInt64(&c.stats.Evictions, 1)
		}
	}

	atomic.StoreInt64(&c.stats.CurrentSize, c.currentSize)
}

func (c *BaseCache) Close() {
	close(c.cleanupDone)
}

func estimateSize(value interface{}) int64 {
	switch v := value.(type) {
	case string:
		return int64(len(v))
	case []byte:
		return int64(len(v))
	case int:
		return 8
	case int64:
		return 8
	case float64:
		return 8
	case bool:
		return 1
	case json.Marshaler:
		data, _ := json.Marshal(v)
		return int64(len(data))
	default:
		data, _ := json.Marshal(v)
		return int64(len(data))
	}
}

type IPReputationCache struct {
	*BaseCache
	reputationScores map[string]*IPReputation
	mu               sync.RWMutex
}

type IPReputation struct {
	IP            string
	Score         float64
	Category      string
	FirstSeen     time.Time
	LastSeen      time.Time
	ThreatCount   int64
	AllowCount    int64
	BlockCount    int64
	TotalRequests int64
	Tags          []string
	Country       string
	ASN           string
	ISP           string
	IsWhitelisted bool
	IsBlacklisted bool
	mu            sync.RWMutex
}

func NewIPReputationCache(maxSize int) *IPReputationCache {
	return &IPReputationCache{
		BaseCache:        NewBaseCache(maxSize, LRU, 30*time.Minute),
		reputationScores: make(map[string]*IPReputation),
	}
}

func (c *IPReputationCache) GetReputation(ip string) (*IPReputation, bool) {
	c.mu.RLock()
	rep, exists := c.reputationScores[ip]
	c.mu.RUnlock()

	if exists {
		return rep, true
	}

	value, found := c.Get(ip)
	if found {
		if rep, ok := value.(*IPReputation); ok {
			return rep, true
		}
	}

	return nil, false
}

func (c *IPReputationCache) SetReputation(ip string, rep *IPReputation, ttl time.Duration) {
	c.mu.Lock()
	c.reputationScores[ip] = rep
	c.mu.Unlock()

	c.Set(ip, rep, ttl)
}

func (c *IPReputationCache) UpdateReputation(ip string, update func(*IPReputation)) {
	rep, exists := c.GetReputation(ip)
	if !exists {
		rep = &IPReputation{
			IP:        ip,
			Score:     0.5,
			FirstSeen: time.Now(),
		}
	}

	rep.mu.Lock()
	update(rep)
	rep.LastSeen = time.Now()
	rep.mu.Unlock()

	c.SetReputation(ip, rep, 30*time.Minute)
}

func (c *IPReputationCache) RecordRequest(ip string, blocked bool) {
	c.UpdateReputation(ip, func(rep *IPReputation) {
		rep.TotalRequests++
		if blocked {
			rep.BlockCount++
			rep.ThreatCount++
		}
		rep.Score = calculateReputationScore(rep)
	})
}

func (c *IPReputationCache) RecordThreat(ip string, threatType string) {
	c.UpdateReputation(ip, func(rep *IPReputation) {
		rep.ThreatCount++
		rep.Score = calculateReputationScore(rep)
	})
}

func (c *IPReputationCache) SetWhitelisted(ip string, whitelisted bool) {
	c.UpdateReputation(ip, func(rep *IPReputation) {
		rep.IsWhitelisted = whitelisted
	})
}

func (c *IPReputationCache) SetBlacklisted(ip string, blacklisted bool) {
	c.UpdateReputation(ip, func(rep *IPReputation) {
		rep.IsBlacklisted = blacklisted
	})
}

func (c *IPReputationCache) IsWhitelisted(ip string) bool {
	rep, exists := c.GetReputation(ip)
	if !exists {
		return false
	}
	rep.mu.RLock()
	defer rep.mu.RUnlock()
	return rep.IsWhitelisted
}

func (c *IPReputationCache) IsBlacklisted(ip string) bool {
	rep, exists := c.GetReputation(ip)
	if !exists {
		return false
	}
	rep.mu.RLock()
	defer rep.mu.RUnlock()
	return rep.IsBlacklisted
}

func (c *IPReputationCache) GetThreatLevel(ip string) ThreatLevel {
	rep, exists := c.GetReputation(ip)
	if !exists {
		return ThreatLevelSafe
	}

	rep.mu.RLock()
	defer rep.mu.RUnlock()

	switch {
	case rep.Score >= 0.8:
		return ThreatLevelCritical
	case rep.Score >= 0.6:
		return ThreatLevelHigh
	case rep.Score >= 0.4:
		return ThreatLevelMedium
	case rep.Score >= 0.2:
		return ThreatLevelLow
	default:
		return ThreatLevelSafe
	}
}

func calculateReputationScore(rep *IPReputation) float64 {
	if rep.TotalRequests == 0 {
		return 0.5
	}

	threatRatio := float64(rep.ThreatCount) / float64(rep.TotalRequests)
	blockRatio := float64(rep.BlockCount) / float64(rep.TotalRequests)

	score := 0.5 + (threatRatio * 0.3) + (blockRatio * 0.2)

	if score > 1.0 {
		score = 1.0
	}
	if score < 0.0 {
		score = 0.0
	}

	return score
}

type SessionCache struct {
	*BaseCache
	sessions    map[string]*Session
	mu          sync.RWMutex
	maxIdleTime time.Duration
}

type Session struct {
	ID             string
	Data           map[string]interface{}
	CreatedAt      time.Time
	LastAccessedAt time.Time
	ExpiresAt      time.Time
	IP             string
	UserAgent      string
	RequestCount   int64
	ThreatCount    int64
	Metadata       map[string]string
	mu             sync.RWMutex
}

func NewSessionCache(maxSize int, maxIdleTime time.Duration) *SessionCache {
	if maxIdleTime == 0 {
		maxIdleTime = 30 * time.Minute
	}

	return &SessionCache{
		BaseCache:   NewBaseCache(maxSize, LRU, maxIdleTime),
		sessions:    make(map[string]*Session),
		maxIdleTime: maxIdleTime,
	}
}

func (c *SessionCache) CreateSession(sessionID string, ip string, userAgent string, ttl time.Duration) *Session {
	session := &Session{
		ID:             sessionID,
		Data:           make(map[string]interface{}),
		CreatedAt:      time.Now(),
		LastAccessedAt: time.Now(),
		ExpiresAt:      time.Now().Add(ttl),
		IP:             ip,
		UserAgent:      userAgent,
		RequestCount:   0,
		ThreatCount:    0,
		Metadata:       make(map[string]string),
	}

	c.mu.Lock()
	c.sessions[sessionID] = session
	c.mu.Unlock()

	c.Set(sessionID, session, ttl)

	return session
}

func (c *SessionCache) GetSession(sessionID string) (*Session, bool) {
	session, exists := c.Get(sessionID)
	if !exists {
		c.mu.RLock()
		s, found := c.sessions[sessionID]
		c.mu.RUnlock()
		if found {
			return s, true
		}
		return nil, false
	}

	if s, ok := session.(*Session); ok {
		return s, true
	}

	return nil, false
}

func (c *SessionCache) UpdateSession(sessionID string, update func(*Session)) {
	session, exists := c.GetSession(sessionID)
	if !exists {
		return
	}

	session.mu.Lock()
	update(session)
	session.LastAccessedAt = time.Now()
	session.mu.Unlock()

	c.Set(sessionID, session, c.maxIdleTime)
}

func (c *SessionCache) DeleteSession(sessionID string) bool {
	c.mu.Lock()
	delete(c.sessions, sessionID)
	c.mu.Unlock()

	return c.Delete(sessionID)
}

func (c *SessionCache) RecordRequest(sessionID string) {
	c.UpdateSession(sessionID, func(s *Session) {
		s.RequestCount++
	})
}

func (c *SessionCache) RecordThreat(sessionID string) {
	c.UpdateSession(sessionID, func(s *Session) {
		s.ThreatCount++
	})
}

func (c *SessionCache) SetData(sessionID string, key string, value interface{}) {
	c.UpdateSession(sessionID, func(s *Session) {
		s.Data[key] = value
	})
}

func (c *SessionCache) GetData(sessionID string, key string) (interface{}, bool) {
	session, exists := c.GetSession(sessionID)
	if !exists {
		return nil, false
	}

	session.mu.RLock()
	defer session.mu.RUnlock()

	value, exists := session.Data[key]
	return value, exists
}

func (c *SessionCache) IsExpired(sessionID string) bool {
	session, exists := c.GetSession(sessionID)
	if !exists {
		return true
	}

	session.mu.RLock()
	defer session.mu.RUnlock()

	return time.Now().After(session.ExpiresAt)
}

func (c *SessionCache) GetActiveSessionCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.sessions)
}

type ParameterBaselineCache struct {
	*BaseCache
	baselines map[string]*ParameterBaseline
	mu        sync.RWMutex
}

type ParameterBaseline struct {
	ParameterName string
	Values        map[string]int
	TotalCount    int64
	FirstSeen     time.Time
	LastSeen      time.Time
	AverageLength float64
	MaxLength     int
	MinLength     int
	DataTypes     []string
	Patterns      []string
	mu            sync.RWMutex
}

func NewParameterBaselineCache(maxSize int) *ParameterBaselineCache {
	return &ParameterBaselineCache{
		BaseCache: NewBaseCache(maxSize, LFU, 24*time.Hour),
		baselines: make(map[string]*ParameterBaseline),
	}
}

func (c *ParameterBaselineCache) RecordParameter(paramName string, value string, dataType string) {
	key := c.generateKey(paramName)

	c.mu.RLock()
	baseline, exists := c.baselines[key]
	c.mu.RUnlock()

	if !exists {
		baseline = &ParameterBaseline{
			ParameterName: paramName,
			Values:        make(map[string]int),
			FirstSeen:     time.Now(),
			DataTypes:     make([]string, 0),
			Patterns:      make([]string, 0),
		}

		c.mu.Lock()
		c.baselines[key] = baseline
		c.mu.Unlock()
	}

	baseline.mu.Lock()
	baseline.Values[value]++
	baseline.TotalCount++
	baseline.LastSeen = time.Now()

	valueLen := len(value)
	if baseline.MinLength == 0 || valueLen < baseline.MinLength {
		baseline.MinLength = valueLen
	}
	if valueLen > baseline.MaxLength {
		baseline.MaxLength = valueLen
	}

	baseline.AverageLength = (baseline.AverageLength*float64(baseline.TotalCount-1) + float64(valueLen)) / float64(baseline.TotalCount)

	dataTypeExists := false
	for _, dt := range baseline.DataTypes {
		if dt == dataType {
			dataTypeExists = true
			break
		}
	}
	if !dataTypeExists {
		baseline.DataTypes = append(baseline.DataTypes, dataType)
	}

	baseline.mu.Unlock()

	c.Set(key, baseline, 24*time.Hour)
}

func (c *ParameterBaselineCache) GetBaseline(paramName string) (*ParameterBaseline, bool) {
	key := c.generateKey(paramName)

	value, found := c.Get(key)
	if found {
		if baseline, ok := value.(*ParameterBaseline); ok {
			return baseline, true
		}
	}

	c.mu.RLock()
	baseline, exists := c.baselines[key]
	c.mu.RUnlock()

	return baseline, exists
}

func (c *ParameterBaselineCache) IsAnomalous(paramName string, value string) bool {
	baseline, exists := c.GetBaseline(paramName)
	if !exists {
		return false
	}

	baseline.mu.RLock()
	defer baseline.mu.RUnlock()

	if baseline.TotalCount < 10 {
		return false
	}

	valueFreq := 0
	for val, count := range baseline.Values {
		if val == value {
			valueFreq = count
			break
		}
	}

	freq := float64(valueFreq) / float64(baseline.TotalCount)
	if freq < 0.001 {
		return true
	}

	valueLen := len(value)
	if valueLen > baseline.MaxLength*3 {
		return true
	}

	if baseline.MinLength > 0 && valueLen < baseline.MinLength/2 {
		return true
	}

	return false
}

func (c *ParameterBaselineCache) GetValueFrequency(paramName string, value string) float64 {
	baseline, exists := c.GetBaseline(paramName)
	if !exists {
		return 0.0
	}

	baseline.mu.RLock()
	defer baseline.mu.RUnlock()

	count := 0
	for val, c := range baseline.Values {
		if val == value {
			count = c
			break
		}
	}

	if baseline.TotalCount == 0 {
		return 0.0
	}

	return float64(count) / float64(baseline.TotalCount)
}

func (c *ParameterBaselineCache) generateKey(paramName string) string {
	hash := sha256.Sum256([]byte(paramName))
	return "param:" + hex.EncodeToString(hash[:8])
}

type ParsingResultCache struct {
	*BaseCache
}

type ParsedRequest struct {
	Scheme      string
	Host        string
	Port        int
	Path        string
	QueryParams map[string][]string
	Fragment    string
	RawQuery    string
	Opaque      string
}

type ParsingMetadata struct {
	ParsedAt      time.Time
	ParseTime     time.Duration
	Format        string
	IsValid       bool
	Error         string
	ContentLength int
	HeaderCount   int
}

func NewParsingResultCache(maxSize int) *ParsingResultCache {
	return &ParsingResultCache{
		BaseCache: NewBaseCache(maxSize, LRU, 10*time.Minute),
	}
}

func (c *ParsingResultCache) GetParsedURL(rawURL string) (*ParsedRequest, *ParsingMetadata, bool) {
	key := c.generateURLKey(rawURL)

	value, found := c.Get(key)
	if !found {
		return nil, nil, false
	}

	if result, ok := value.(*ParsingCacheEntry); ok {
		return result.Parsed, result.Metadata, true
	}

	return nil, nil, false
}

func (c *ParsingResultCache) SetParsedURL(rawURL string, parsed *ParsedRequest, metadata *ParsingMetadata, ttl time.Duration) {
	key := c.generateURLKey(rawURL)

	entry := &ParsingCacheEntry{
		RawURL:   rawURL,
		Parsed:   parsed,
		Metadata: metadata,
		CachedAt: time.Now(),
	}

	c.Set(key, entry, ttl)
}

type ParsingCacheEntry struct {
	RawURL   string
	Parsed   *ParsedRequest
	Metadata *ParsingMetadata
	CachedAt time.Time
}

func (c *ParsingResultCache) GetHeaderParse(headers map[string]string) (map[string]string, bool) {
	key := c.generateHeadersKey(headers)

	value, found := c.Get(key)
	if !found {
		return nil, false
	}

	if normalized, ok := value.(map[string]string); ok {
		return normalized, true
	}

	return nil, false
}

func (c *ParsingResultCache) SetHeaderParse(headers map[string]string, normalized map[string]string, ttl time.Duration) {
	key := c.generateHeadersKey(headers)
	c.Set(key, normalized, ttl)
}

func (c *ParsingResultCache) GetBodyParse(body string, contentType string) ([]byte, bool) {
	key := c.generateBodyKey(body, contentType)

	value, found := c.Get(key)
	if !found {
		return nil, false
	}

	if parsed, ok := value.([]byte); ok {
		return parsed, true
	}

	return nil, false
}

func (c *ParsingResultCache) SetBodyParse(body string, contentType string, parsed []byte, ttl time.Duration) {
	key := c.generateBodyKey(body, contentType)
	c.Set(key, parsed, ttl)
}

func (c *ParsingResultCache) generateURLKey(rawURL string) string {
	hash := sha256.Sum256([]byte(rawURL))
	return "url:" + hex.EncodeToString(hash[:16])
}

func (c *ParsingResultCache) generateHeadersKey(headers map[string]string) string {
	data, _ := json.Marshal(headers)
	hash := sha256.Sum256(data)
	return "hdr:" + hex.EncodeToString(hash[:16])
}

func (c *ParsingResultCache) generateBodyKey(body string, contentType string) string {
	key := body + ":" + contentType
	hash := sha256.Sum256([]byte(key))
	return "body:" + hex.EncodeToString(hash[:16])
}

type MultiLevelCache struct {
	l1 *BaseCache
	l2 *IPReputationCache
	l3 *SessionCache
}

func NewMultiLevelCache(l1Size, l2Size, l3Size int) *MultiLevelCache {
	return &MultiLevelCache{
		l1: NewBaseCache(l1Size, LRU, 5*time.Minute),
		l2: NewIPReputationCache(l2Size),
		l3: NewSessionCache(l3Size, 30*time.Minute),
	}
}

func (m *MultiLevelCache) GetL1(key string) (interface{}, bool) {
	return m.l1.Get(key)
}

func (m *MultiLevelCache) SetL1(key string, value interface{}, ttl time.Duration) {
	m.l1.Set(key, value, ttl)
}

func (m *MultiLevelCache) GetIPReputation(ip string) (*IPReputation, bool) {
	return m.l2.GetReputation(ip)
}

func (m *MultiLevelCache) SetIPReputation(ip string, rep *IPReputation, ttl time.Duration) {
	m.l2.SetReputation(ip, rep, ttl)
}

func (m *MultiLevelCache) GetSession(sessionID string) (*Session, bool) {
	return m.l3.GetSession(sessionID)
}

func (m *MultiLevelCache) CreateSession(sessionID string, ip string, userAgent string, ttl time.Duration) *Session {
	return m.l3.CreateSession(sessionID, ip, userAgent, ttl)
}

func (m *MultiLevelCache) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"l1_cache": m.l1.Stats(),
		"l2_cache": map[string]interface{}{
			"hits":         m.l2.Stats().Hits,
			"misses":       m.l2.Stats().Misses,
			"evictions":    m.l2.Stats().Evictions,
			"current_size": m.l2.Stats().CurrentSize,
			"max_size":     m.l2.Stats().MaxSize,
		},
		"l3_cache": map[string]interface{}{
			"hits":            m.l3.Stats().Hits,
			"misses":          m.l3.Stats().Misses,
			"evictions":       m.l3.Stats().Evictions,
			"current_size":    m.l3.Stats().CurrentSize,
			"max_size":        m.l3.Stats().MaxSize,
			"active_sessions": m.l3.GetActiveSessionCount(),
		},
	}
}

func (m *MultiLevelCache) ClearAll() {
	m.l1.Clear()
	m.l2.Clear()
	m.l3.Clear()
}

type CacheFactory struct {
	defaultMaxSize int
	defaultTTL     time.Duration
}

func NewCacheFactory(defaultMaxSize int, defaultTTL time.Duration) *CacheFactory {
	return &CacheFactory{
		defaultMaxSize: defaultMaxSize,
		defaultTTL:     defaultTTL,
	}
}

func (f *CacheFactory) CreateIPReputationCache() *IPReputationCache {
	return NewIPReputationCache(f.defaultMaxSize)
}

func (f *CacheFactory) CreateSessionCache() *SessionCache {
	return NewSessionCache(f.defaultMaxSize, f.defaultTTL)
}

func (f *CacheFactory) CreateParameterBaselineCache() *ParameterBaselineCache {
	return NewParameterBaselineCache(f.defaultMaxSize)
}

func (f *CacheFactory) CreateParsingResultCache() *ParsingResultCache {
	return NewParsingResultCache(f.defaultMaxSize)
}

func (f *CacheFactory) CreateMultiLevelCache() *MultiLevelCache {
	return NewMultiLevelCache(f.defaultMaxSize, f.defaultMaxSize, f.defaultMaxSize)
}
