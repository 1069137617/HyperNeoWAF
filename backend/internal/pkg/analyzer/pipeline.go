package analyzer

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type PipelineStage int

const (
	StageWhitelist PipelineStage = iota
	StageRuleMatch
	StageSemantic
	StageBehavioral
	StageLog
)

func (s PipelineStage) String() string {
	switch s {
	case StageWhitelist:
		return "whitelist"
	case StageRuleMatch:
		return "rule_match"
	case StageSemantic:
		return "semantic"
	case StageBehavioral:
		return "behavioral"
	case StageLog:
		return "log"
	default:
		return "unknown"
	}
}

type PipelineResult struct {
	Stage       PipelineStage
	ThreatLevel ThreatLevel
	RiskScore   float64
	Matches     []Match
	ShouldBlock bool
	ShouldAllow bool
	ShouldLog   bool
	StageTime   time.Duration
	EarlyExit   bool
	ExitStage   PipelineStage
	Details     map[string]interface{}
}

type WhitelistEntry struct {
	Pattern     string
	PatternType string
	ExpiresAt   time.Time
}

type Pipeline struct {
	name               string
	enabled            bool
	whitelistCache     *WhitelistCache
	ruleMatchCache     *RuleMatchCache
	semanticCache      *SemanticResultCache
	behavioralAnalyzer BehavioralAnalyzer
	logChannel         chan *PipelineResult
	behaviorChannel    chan *PipelineResult
	analyzerRegistry   AnalyzerRegistry
	stageHandlers      map[PipelineStage]StageHandler
	mu                 sync.RWMutex
	stats              *PipelineStats
	ctx                context.Context
	cancel             context.CancelFunc
}

type StageHandler func(input *AnalysisInput, prevResult *PipelineResult) *PipelineResult

type BehavioralAnalyzer interface {
	AnalyzeBehavior(input *AnalysisInput) (*BehavioralResult, error)
}

type BehavioralResult struct {
	Score       float64
	ThreatLevel ThreatLevel
	Patterns    []string
	AnomalyType string
	Description string
}

type PipelineStats struct {
	TotalRequests   int64
	WhitelistedReqs int64
	BlockedReqs     int64
	AllowedReqs     int64
	AvgLatency      time.Duration
	MaxLatency      time.Duration
	MinLatency      time.Duration
	StageLatencies  map[PipelineStage]*StageLatencyStats
	mu              sync.RWMutex
}

type StageLatencyStats struct {
	Total time.Duration
	Count int64
	Avg   time.Duration
}

type WhitelistCache struct {
	entries        map[string]*WhitelistEntry
	ipEntries      map[string]*WhitelistEntry
	sessionEntries map[string]*WhitelistEntry
	mu             sync.RWMutex
	defaultTTL     time.Duration
}

type RuleMatchCache struct {
	patternCache map[string]*RuleMatchResult
	mu           sync.RWMutex
	maxSize      int
	hits         int64
	misses       int64
}

type RuleMatchResult struct {
	ThreatLevel ThreatLevel
	Matches     []Match
	ExpiresAt   time.Time
}

type SemanticResultCache struct {
	results map[string]*SemanticCacheEntry
	mu      sync.RWMutex
	maxSize int
	hits    int64
	misses  int64
}

type SemanticCacheEntry struct {
	Result    *AnalysisResult
	InputHash string
	ExpiresAt time.Time
}

func NewPipeline(name string, registry AnalyzerRegistry) *Pipeline {
	ctx, cancel := context.WithCancel(context.Background())
	p := &Pipeline{
		name:             name,
		enabled:          true,
		whitelistCache:   NewWhitelistCache(),
		ruleMatchCache:   NewRuleMatchCache(),
		semanticCache:    NewSemanticResultCache(),
		logChannel:       make(chan *PipelineResult, 1000),
		behaviorChannel:  make(chan *PipelineResult, 500),
		analyzerRegistry: registry,
		stageHandlers:    make(map[PipelineStage]StageHandler),
		stats:            NewPipelineStats(),
		ctx:              ctx,
		cancel:           cancel,
	}

	p.initStageHandlers()
	go p.processLogChannel()
	go p.processBehaviorChannel()

	return p
}

func NewPipelineStats() *PipelineStats {
	stats := &PipelineStats{
		StageLatencies: make(map[PipelineStage]*StageLatencyStats),
	}
	for stage := StageWhitelist; stage <= StageLog; stage++ {
		stats.StageLatencies[stage] = &StageLatencyStats{}
	}
	return stats
}

func (s *PipelineStats) RecordRequest() {
	atomic.AddInt64(&s.TotalRequests, 1)
}

func (s *PipelineStats) RecordWhitelisted() {
	atomic.AddInt64(&s.WhitelistedReqs, 1)
}

func (s *PipelineStats) RecordBlocked() {
	atomic.AddInt64(&s.BlockedReqs, 1)
}

func (s *PipelineStats) RecordAllowed() {
	atomic.AddInt64(&s.AllowedReqs, 1)
}

func (s *PipelineStats) RecordLatency(stage PipelineStage, latency time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stats := s.StageLatencies[stage]
	stats.Total += latency
	stats.Count++
	stats.Avg = stats.Total / time.Duration(stats.Count)

	if s.MinLatency == 0 || latency < s.MinLatency {
		s.MinLatency = latency
	}
	if latency > s.MaxLatency {
		s.MaxLatency = latency
	}

	totalLatency := s.TotalLatency()
	totalCount := atomic.LoadInt64(&s.TotalRequests)
	if totalCount > 0 {
		s.AvgLatency = totalLatency / time.Duration(totalCount)
	}
}

func (s *PipelineStats) TotalLatency() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var total time.Duration
	for _, stageStats := range s.StageLatencies {
		total += stageStats.Total
	}
	return total
}

func (s *PipelineStats) GetStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stageLatencies := make(map[string]interface{})
	for stage, stats := range s.StageLatencies {
		stageLatencies[stage.String()] = map[string]interface{}{
			"total": stats.Total.String(),
			"count": stats.Count,
			"avg":   stats.Avg.String(),
		}
	}

	return map[string]interface{}{
		"total_requests":  atomic.LoadInt64(&s.TotalRequests),
		"whitelisted_req": atomic.LoadInt64(&s.WhitelistedReqs),
		"blocked_req":     atomic.LoadInt64(&s.BlockedReqs),
		"allowed_req":     atomic.LoadInt64(&s.AllowedReqs),
		"avg_latency":     s.AvgLatency.String(),
		"max_latency":     s.MaxLatency.String(),
		"min_latency":     s.MinLatency.String(),
		"stage_latencies": stageLatencies,
	}
}

func NewWhitelistCache() *WhitelistCache {
	return &WhitelistCache{
		entries:        make(map[string]*WhitelistEntry),
		ipEntries:      make(map[string]*WhitelistEntry),
		sessionEntries: make(map[string]*WhitelistEntry),
		defaultTTL:     5 * time.Minute,
	}
}

func (c *WhitelistCache) Add(pattern string, patternType string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry := &WhitelistEntry{
		Pattern:     pattern,
		PatternType: patternType,
		ExpiresAt:   time.Now().Add(ttl),
	}

	switch patternType {
	case "ip":
		c.ipEntries[pattern] = entry
	case "session":
		c.sessionEntries[pattern] = entry
	default:
		c.entries[pattern] = entry
	}
}

func (c *WhitelistCache) AddIP(ip string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.ipEntries[ip] = &WhitelistEntry{
		Pattern:     ip,
		PatternType: "ip",
		ExpiresAt:   time.Now().Add(ttl),
	}
}

func (c *WhitelistCache) AddSession(sessionID string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.sessionEntries[sessionID] = &WhitelistEntry{
		Pattern:     sessionID,
		PatternType: "session",
		ExpiresAt:   time.Now().Add(ttl),
	}
}

func (c *WhitelistCache) Check(input *AnalysisInput) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now()

	if entry, ok := c.ipEntries[input.ClientIP]; ok {
		if now.Before(entry.ExpiresAt) {
			return true
		}
	}

	for _, entry := range c.ipEntries {
		if now.Before(entry.ExpiresAt) && strings.HasPrefix(input.ClientIP, entry.Pattern) {
			return true
		}
	}

	sessionID, ok := input.Metadata["session_id"].(string)
	if ok {
		if entry, ok := c.sessionEntries[sessionID]; ok {
			if now.Before(entry.ExpiresAt) {
				return true
			}
		}
	}

	pathWhitelist := []string{"/health", "/metrics", "/status", "/favicon.ico"}
	for _, path := range pathWhitelist {
		if entry, ok := c.entries[path]; ok {
			if now.Before(entry.ExpiresAt) && strings.HasPrefix(input.Path, path) {
				return true
			}
		}
	}

	return false
}

func (c *WhitelistCache) Remove(pattern string, patternType string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch patternType {
	case "ip":
		delete(c.ipEntries, pattern)
	case "session":
		delete(c.sessionEntries, pattern)
	default:
		delete(c.entries, pattern)
	}
}

func (c *WhitelistCache) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	for pattern, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			delete(c.entries, pattern)
		}
	}

	for pattern, entry := range c.ipEntries {
		if now.After(entry.ExpiresAt) {
			delete(c.ipEntries, pattern)
		}
	}

	for pattern, entry := range c.sessionEntries {
		if now.After(entry.ExpiresAt) {
			delete(c.sessionEntries, pattern)
		}
	}
}

func NewRuleMatchCache() *RuleMatchCache {
	return &RuleMatchCache{
		patternCache: make(map[string]*RuleMatchResult),
		maxSize:      10000,
	}
}

func (c *RuleMatchCache) Get(key string) (*RuleMatchResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result, exists := c.patternCache[key]
	if exists && time.Now().Before(result.ExpiresAt) {
		atomic.AddInt64(&c.hits, 1)
		return result, true
	}

	atomic.AddInt64(&c.misses, 1)
	return nil, false
}

func (c *RuleMatchCache) Set(key string, result *RuleMatchResult, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.patternCache) >= c.maxSize {
		c.evictOldest()
	}

	c.patternCache[key] = &RuleMatchResult{
		ThreatLevel: result.ThreatLevel,
		Matches:     result.Matches,
		ExpiresAt:   time.Now().Add(ttl),
	}
}

func (c *RuleMatchCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, result := range c.patternCache {
		if oldestTime.IsZero() || result.ExpiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = result.ExpiresAt
		}
	}

	if oldestKey != "" {
		delete(c.patternCache, oldestKey)
	}
}

func (c *RuleMatchCache) GetStats() (hits, misses int64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return atomic.LoadInt64(&c.hits), atomic.LoadInt64(&c.misses)
}

func NewSemanticResultCache() *SemanticResultCache {
	return &SemanticResultCache{
		results: make(map[string]*SemanticCacheEntry),
		maxSize: 5000,
	}
}

func (c *SemanticResultCache) Get(inputHash string) (*AnalysisResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.results[inputHash]
	if exists && time.Now().Before(entry.ExpiresAt) {
		atomic.AddInt64(&c.hits, 1)
		return entry.Result, true
	}

	atomic.AddInt64(&c.misses, 1)
	return nil, false
}

func (c *SemanticResultCache) Set(inputHash string, result *AnalysisResult, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.results) >= c.maxSize {
		c.evictOldest()
	}

	c.results[inputHash] = &SemanticCacheEntry{
		Result:    result,
		InputHash: inputHash,
		ExpiresAt: time.Now().Add(ttl),
	}
}

func (c *SemanticResultCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range c.results {
		if oldestTime.IsZero() || entry.ExpiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.ExpiresAt
		}
	}

	if oldestKey != "" {
		delete(c.results, oldestKey)
	}
}

func (c *SemanticResultCache) GetStats() (hits, misses int64, size int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return atomic.LoadInt64(&c.hits), atomic.LoadInt64(&c.misses), len(c.results)
}

func (p *Pipeline) initStageHandlers() {
	p.stageHandlers[StageWhitelist] = p.whitelistStage
	p.stageHandlers[StageRuleMatch] = p.ruleMatchStage
	p.stageHandlers[StageSemantic] = p.semanticStage
	p.stageHandlers[StageBehavioral] = p.behavioralStage
	p.stageHandlers[StageLog] = p.logStage
}

func (p *Pipeline) Execute(input *AnalysisInput) *PipelineResult {
	if !p.enabled {
		return &PipelineResult{
			Stage:       StageLog,
			ThreatLevel: ThreatLevelSafe,
			ShouldAllow: true,
			ShouldLog:   false,
		}
	}

	p.stats.RecordRequest()

	result := &PipelineResult{
		Stage:       StageWhitelist,
		ThreatLevel: ThreatLevelSafe,
		ShouldAllow: true,
		ShouldLog:   true,
		Details:     make(map[string]interface{}),
	}

	for stage := StageWhitelist; stage <= StageLog; stage++ {
		if handler, ok := p.stageHandlers[stage]; ok {
			start := time.Now()
			result = handler(input, result)
			latency := time.Since(start)
			result.StageTime = latency
			p.stats.RecordLatency(stage, latency)

			if result.EarlyExit {
				break
			}
		}
	}

	if result.ShouldBlock {
		p.stats.RecordBlocked()
	} else {
		p.stats.RecordAllowed()
	}

	return result
}

func (p *Pipeline) ExecuteAsync(input *AnalysisInput, callback func(*PipelineResult)) {
	go func() {
		result := p.Execute(input)
		if callback != nil {
			callback(result)
		}
	}()
}

func (p *Pipeline) whitelistStage(input *AnalysisInput, prevResult *PipelineResult) *PipelineResult {
	result := &PipelineResult{
		Stage:       StageWhitelist,
		ThreatLevel: ThreatLevelSafe,
		ShouldAllow: true,
		ShouldLog:   true,
		Details:     make(map[string]interface{}),
	}

	if p.whitelistCache.Check(input) {
		result.ThreatLevel = ThreatLevelSafe
		result.ShouldBlock = false
		result.ShouldAllow = true
		result.EarlyExit = true
		result.ExitStage = StageWhitelist
		result.Details["reason"] = "whitelist_match"
		p.stats.RecordWhitelisted()
		return result
	}

	result.Details["reason"] = "not_whitelisted"
	return result
}

func (p *Pipeline) ruleMatchStage(input *AnalysisInput, prevResult *PipelineResult) *PipelineResult {
	result := &PipelineResult{
		Stage:       StageRuleMatch,
		ThreatLevel: prevResult.ThreatLevel,
		ShouldAllow: prevResult.ShouldAllow,
		ShouldLog:   prevResult.ShouldLog,
		Matches:     make([]Match, 0),
		Details:     make(map[string]interface{}),
	}

	cacheKey := p.generateCacheKey(input)
	if cached, found := p.ruleMatchCache.Get(cacheKey); found {
		result.ThreatLevel = cached.ThreatLevel
		result.Matches = cached.Matches
		result.Details["cache_hit"] = true
		return result
	}

	normalized := NormalizeInput(input.Raw)
	sqlKeywords := ExtractSQLKeywords(normalized)
	xssKeywords := ExtractJSKeywords(normalized)
	cmdKeywords := ExtractCommandKeywords(normalized)

	var maxThreat ThreatLevel
	matches := make([]Match, 0)

	if len(sqlKeywords) > 0 {
		match := Match{
			Type:         MatchTypePattern,
			ThreatLevel:  ThreatLevelHigh,
			Pattern:      strings.Join(sqlKeywords, ","),
			Description:  "SQL注入特征关键词",
			Evidence:     normalized,
			AnalyzerName: "RuleMatchPipeline",
		}
		matches = append(matches, match)
		maxThreat = maxThreatLevel(maxThreat, ThreatLevelHigh)
	}

	if len(xssKeywords) > 0 {
		match := Match{
			Type:         MatchTypePattern,
			ThreatLevel:  ThreatLevelHigh,
			Pattern:      strings.Join(xssKeywords, ","),
			Description:  "XSS特征关键词",
			Evidence:     normalized,
			AnalyzerName: "RuleMatchPipeline",
		}
		matches = append(matches, match)
		maxThreat = maxThreatLevel(maxThreat, ThreatLevelHigh)
	}

	if len(cmdKeywords) > 0 {
		match := Match{
			Type:         MatchTypePattern,
			ThreatLevel:  ThreatLevelCritical,
			Pattern:      strings.Join(cmdKeywords, ","),
			Description:  "命令注入特征关键词",
			Evidence:     normalized,
			AnalyzerName: "RuleMatchPipeline",
		}
		matches = append(matches, match)
		maxThreat = maxThreatLevel(maxThreat, ThreatLevelCritical)
	}

	result.ThreatLevel = maxThreat
	result.Matches = matches
	result.ShouldBlock = maxThreat >= ThreatLevelHigh
	result.ShouldAllow = !result.ShouldBlock

	p.ruleMatchCache.Set(cacheKey, &RuleMatchResult{
		ThreatLevel: maxThreat,
		Matches:     matches,
	}, 5*time.Minute)

	result.Details["cache_hit"] = false
	result.Details["match_count"] = len(matches)

	return result
}

func (p *Pipeline) semanticStage(input *AnalysisInput, prevResult *PipelineResult) *PipelineResult {
	result := &PipelineResult{
		Stage:       StageSemantic,
		ThreatLevel: prevResult.ThreatLevel,
		ShouldAllow: prevResult.ShouldAllow,
		ShouldLog:   prevResult.ShouldLog,
		Matches:     prevResult.Matches,
		Details:     make(map[string]interface{}),
	}

	if prevResult.ShouldBlock {
		result.Details["skipped"] = "blocked_by_previous_stage"
		return result
	}

	cacheKey := p.generateCacheKey(input)
	if cached, found := p.semanticCache.Get(cacheKey); found {
		result.ThreatLevel = cached.ThreatLevel
		result.ShouldBlock = cached.ShouldBlock
		result.ShouldAllow = cached.ShouldAllow
		result.Matches = append(result.Matches, cached.Matches...)
		result.Details["cache_hit"] = true
		return result
	}

	results := p.analyzerRegistry.AnalyzeAll(input)

	var maxThreat ThreatLevel
	allMatches := make([]Match, 0)
	allMatches = append(allMatches, result.Matches...)

	for _, res := range results {
		if res.ThreatLevel > maxThreat {
			maxThreat = res.ThreatLevel
		}
		allMatches = append(allMatches, res.Matches...)
	}

	result.ThreatLevel = maxThreatLevel(result.ThreatLevel, maxThreat)
	result.Matches = allMatches
	result.ShouldBlock = result.ShouldBlock || maxThreat >= ThreatLevelHigh
	result.ShouldAllow = !result.ShouldBlock

	semanticResult := &AnalysisResult{
		ThreatLevel: maxThreat,
		Matches:     allMatches,
		ShouldBlock: result.ShouldBlock,
		ShouldAllow: result.ShouldAllow,
	}
	p.semanticCache.Set(cacheKey, semanticResult, 2*time.Minute)

	result.Details["cache_hit"] = false
	result.Details["analyzer_count"] = len(results)
	result.Details["total_matches"] = len(allMatches)

	return result
}

func (p *Pipeline) behavioralStage(input *AnalysisInput, prevResult *PipelineResult) *PipelineResult {
	result := &PipelineResult{
		Stage:       StageBehavioral,
		ThreatLevel: prevResult.ThreatLevel,
		ShouldAllow: prevResult.ShouldAllow,
		ShouldLog:   prevResult.ShouldLog,
		Matches:     prevResult.Matches,
		Details:     make(map[string]interface{}),
	}

	p.behaviorChannel <- prevResult

	result.Details["async_processing"] = true
	return result
}

func (p *Pipeline) logStage(input *AnalysisInput, prevResult *PipelineResult) *PipelineResult {
	result := &PipelineResult{
		Stage:       StageLog,
		ThreatLevel: prevResult.ThreatLevel,
		ShouldBlock: prevResult.ShouldBlock,
		ShouldAllow: prevResult.ShouldAllow,
		ShouldLog:   prevResult.ShouldLog,
		Matches:     prevResult.Matches,
		Details:     make(map[string]interface{}),
	}

	p.logChannel <- prevResult

	result.Details["logged"] = true
	return result
}

func (p *Pipeline) processLogChannel() {
	for {
		select {
		case <-p.ctx.Done():
			return
		case result := <-p.logChannel:
			if result != nil {
				p.processLogResult(result)
			}
		}
	}
}

func (p *Pipeline) processBehaviorChannel() {
	for {
		select {
		case <-p.ctx.Done():
			return
		case result := <-p.behaviorChannel:
			if result != nil && p.behavioralAnalyzer != nil {
				go p.processBehavioralResult(result)
			}
		}
	}
}

func (p *Pipeline) processLogResult(result *PipelineResult) {
}

func (p *Pipeline) processBehavioralResult(result *PipelineResult) {
}

func (p *Pipeline) generateCacheKey(input *AnalysisInput) string {
	return input.Raw + ":" + input.ClientIP + ":" + input.Path
}

func (p *Pipeline) SetEnabled(enabled bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.enabled = enabled
}

func (p *Pipeline) IsEnabled() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.enabled
}

func (p *Pipeline) GetStats() *PipelineStats {
	return p.stats
}

func (p *Pipeline) SetBehavioralAnalyzer(analyzer BehavioralAnalyzer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.behavioralAnalyzer = analyzer
}

func (p *Pipeline) Close() {
	p.cancel()
	close(p.logChannel)
	close(p.behaviorChannel)
}

func (p *Pipeline) AddWhitelist(pattern string, patternType string, ttl time.Duration) {
	p.whitelistCache.Add(pattern, patternType, ttl)
}

func (p *Pipeline) RemoveWhitelist(pattern string, patternType string) {
	p.whitelistCache.Remove(pattern, patternType)
}

type PipelineScheduler struct {
	pipelines   map[string]*Pipeline
	defaultPipe *Pipeline
	mu          sync.RWMutex
	rules       []PipelineRule
	stats       *SchedulerStats
}

type PipelineRule struct {
	Name         string
	Priority     int
	Matcher      func(*AnalysisInput) bool
	PipelineName string
}

type SchedulerStats struct {
	TotalScheduled int64
	PipelineUsage  map[string]int64
	mu             sync.RWMutex
}

func NewPipelineScheduler() *PipelineScheduler {
	return &PipelineScheduler{
		pipelines: make(map[string]*Pipeline),
		rules:     make([]PipelineRule, 0),
		stats:     &SchedulerStats{PipelineUsage: make(map[string]int64)},
	}
}

func (s *PipelineScheduler) RegisterPipeline(name string, pipe *Pipeline) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pipelines[name] = pipe
	if s.defaultPipe == nil {
		s.defaultPipe = pipe
	}
}

func (s *PipelineScheduler) SetDefaultPipeline(pipe *Pipeline) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.defaultPipe = pipe
}

func (s *PipelineScheduler) AddRule(rule PipelineRule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = append(s.rules, rule)
}

func (s *PipelineScheduler) Schedule(input *AnalysisInput) *PipelineResult {
	pipe := s.selectPipeline(input)

	atomic.AddInt64(&s.stats.TotalScheduled, 1)
	if pipe != nil {
		s.mu.Lock()
		s.stats.PipelineUsage[pipe.name]++
		s.mu.Unlock()
		return pipe.Execute(input)
	}

	return &PipelineResult{
		ThreatLevel: ThreatLevelSafe,
		ShouldAllow: true,
		ShouldLog:   false,
	}
}

func (s *PipelineScheduler) selectPipeline(input *AnalysisInput) *Pipeline {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, rule := range s.rules {
		if rule.Matcher(input) {
			if pipe, ok := s.pipelines[rule.PipelineName]; ok {
				return pipe
			}
		}
	}

	return s.defaultPipe
}

func (s *PipelineScheduler) GetStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	s.stats.mu.Lock()
	defer s.stats.mu.Unlock()

	pipelineUsage := make(map[string]int64)
	for name, count := range s.stats.PipelineUsage {
		pipelineUsage[name] = count
	}

	return map[string]interface{}{
		"total_scheduled": atomic.LoadInt64(&s.stats.TotalScheduled),
		"pipeline_usage":  pipelineUsage,
		"rule_count":      len(s.rules),
		"pipeline_count":  len(s.pipelines),
	}
}
