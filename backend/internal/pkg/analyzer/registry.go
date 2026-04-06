package analyzer

import (
	"errors"
	"sort"
	"sync"
	"time"
)

var (
	ErrNilAnalyzer           = errors.New("analyzer cannot be nil")
	ErrInvalidAnalyzerName   = errors.New("analyzer name cannot be empty")
	ErrAnalyzerAlreadyExists = errors.New("analyzer with this name already exists")
	ErrAnalyzerNotFound      = errors.New("analyzer not found")
)

type DefaultRegistry struct {
	analyzers map[string]SemanticAnalyzer
	mu        sync.RWMutex
	stats     map[string]*AnalyzerStats
	statsMu   sync.RWMutex
}

type AnalyzerStats struct {
	Name                string
	TotalAnalyzed       int64
	ThreatLevelCounts   map[ThreatLevel]int64
	AvgProcessingTime   time.Duration
	TotalProcessingTime time.Duration
	mu                  sync.RWMutex
}

func NewDefaultRegistry() *DefaultRegistry {
	return &DefaultRegistry{
		analyzers: make(map[string]SemanticAnalyzer),
		stats:     make(map[string]*AnalyzerStats),
	}
}

func (r *DefaultRegistry) Register(analyzer SemanticAnalyzer) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if analyzer == nil {
		return ErrNilAnalyzer
	}

	name := analyzer.Name()
	if name == "" {
		return ErrInvalidAnalyzerName
	}

	if _, exists := r.analyzers[name]; exists {
		return ErrAnalyzerAlreadyExists
	}

	r.analyzers[name] = analyzer
	r.initStats(analyzer)
	return nil
}

func (r *DefaultRegistry) initStats(analyzer SemanticAnalyzer) {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()

	r.stats[analyzer.Name()] = &AnalyzerStats{
		Name:              analyzer.Name(),
		ThreatLevelCounts: make(map[ThreatLevel]int64),
	}
}

func (r *DefaultRegistry) Unregister(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.analyzers[name]; !exists {
		return false
	}

	delete(r.analyzers, name)

	r.statsMu.Lock()
	delete(r.stats, name)
	r.statsMu.Unlock()

	return true
}

func (r *DefaultRegistry) Get(name string) SemanticAnalyzer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.analyzers[name]
}

func (r *DefaultRegistry) List() []SemanticAnalyzer {
	r.mu.RLock()
	defer r.mu.RUnlock()

	analyzers := make([]SemanticAnalyzer, 0, len(r.analyzers))
	for _, a := range r.analyzers {
		analyzers = append(analyzers, a)
	}

	sort.Slice(analyzers, func(i, j int) bool {
		return analyzers[i].Name() < analyzers[j].Name()
	})

	return analyzers
}

func (r *DefaultRegistry) ListByType(analyzerType string) []SemanticAnalyzer {
	r.mu.RLock()
	defer r.mu.RUnlock()

	analyzers := make([]SemanticAnalyzer, 0)
	for _, a := range r.analyzers {
		if a.Type() == analyzerType {
			analyzers = append(analyzers, a)
		}
	}

	return analyzers
}

func (r *DefaultRegistry) ListInfo() []AnalyzerInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	infos := make([]AnalyzerInfo, 0, len(r.analyzers))
	for _, a := range r.analyzers {
		info := AnalyzerInfo{
			Name:      a.Name(),
			Type:      a.Type(),
			Version:   a.Version(),
			IsEnabled: a.IsEnabled(),
		}

		if stats := r.getStats(a.Name()); stats != nil {
			info.MatchCount = stats.TotalAnalyzed
		}

		infos = append(infos, info)
	}

	return infos
}

func (r *DefaultRegistry) getStats(name string) *AnalyzerStats {
	r.statsMu.RLock()
	defer r.statsMu.RUnlock()
	return r.stats[name]
}

func (r *DefaultRegistry) AnalyzeAll(input *AnalysisInput) []*AnalysisResult {
	return r.AnalyzeWithFilter(input, func(a SemanticAnalyzer) bool {
		return a.IsEnabled()
	})
}

func (r *DefaultRegistry) AnalyzeWithFilter(input *AnalysisInput, filter func(SemanticAnalyzer) bool) []*AnalysisResult {
	r.mu.RLock()
	analyzerList := r.List()
	r.mu.RUnlock()

	var wg sync.WaitGroup
	results := make([]*AnalysisResult, 0)
	resultsMu := sync.Mutex{}

	for _, analyzer := range analyzerList {
		if !filter(analyzer) {
			continue
		}

		if !analyzer.IsEnabled() {
			continue
		}

		wg.Add(1)
		go func(a SemanticAnalyzer) {
			defer wg.Done()
			result := a.Analyze(input)

			resultsMu.Lock()
			results = append(results, result)
			resultsMu.Unlock()

			r.updateStats(a.Name(), result)
		}(analyzer)
	}

	wg.Wait()
	return results
}

func (r *DefaultRegistry) updateStats(name string, result *AnalysisResult) {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()

	stats, exists := r.stats[name]
	if !exists {
		stats = &AnalyzerStats{
			Name:              name,
			ThreatLevelCounts: make(map[ThreatLevel]int64),
		}
		r.stats[name] = stats
	}

	stats.mu.Lock()
	stats.TotalAnalyzed++
	stats.TotalProcessingTime += result.ProcessingTime
	stats.AvgProcessingTime = stats.TotalProcessingTime / time.Duration(stats.TotalAnalyzed)
	stats.ThreatLevelCounts[result.ThreatLevel]++
	stats.mu.Unlock()
}

func (r *DefaultRegistry) GetStats(name string) *AnalyzerStats {
	r.statsMu.RLock()
	defer r.statsMu.RUnlock()
	return r.stats[name]
}

func (r *DefaultRegistry) GetAllStats() map[string]*AnalyzerStats {
	r.statsMu.RLock()
	defer r.statsMu.RUnlock()

	result := make(map[string]*AnalyzerStats)
	for k, v := range r.stats {
		result[k] = v
	}
	return result
}

func (r *DefaultRegistry) Enable(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	analyzer, exists := r.analyzers[name]
	if !exists {
		return false
	}

	analyzer.SetEnabled(true)
	return true
}

func (r *DefaultRegistry) Disable(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	analyzer, exists := r.analyzers[name]
	if !exists {
		return false
	}

	analyzer.SetEnabled(false)
	return true
}

func (r *DefaultRegistry) Configure(name string, config map[string]interface{}) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	analyzer, exists := r.analyzers[name]
	if !exists {
		return ErrAnalyzerNotFound
	}

	return analyzer.Configure(config)
}

type CompositeAnalyzerImpl struct {
	name         string
	version      string
	analyzerType string
	enabled      bool
	analyzers    []SemanticAnalyzer
	config       map[string]interface{}
	mu           sync.RWMutex
}

func NewCompositeAnalyzer(name, analyzerType string) *CompositeAnalyzerImpl {
	return &CompositeAnalyzerImpl{
		name:         name,
		version:      "1.0.0",
		analyzerType: analyzerType,
		enabled:      true,
		analyzers:    make([]SemanticAnalyzer, 0),
	}
}

func (c *CompositeAnalyzerImpl) Name() string {
	return c.name
}

func (c *CompositeAnalyzerImpl) Type() string {
	return c.analyzerType
}

func (c *CompositeAnalyzerImpl) Version() string {
	return c.version
}

func (c *CompositeAnalyzerImpl) IsEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.enabled
}

func (c *CompositeAnalyzerImpl) SetEnabled(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enabled = enabled
}

func (c *CompositeAnalyzerImpl) Configure(config map[string]interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config = config
	return nil
}

func (c *CompositeAnalyzerImpl) Analyzers() []SemanticAnalyzer {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]SemanticAnalyzer, len(c.analyzers))
	copy(result, c.analyzers)
	return result
}

func (c *CompositeAnalyzerImpl) AddAnalyzer(analyzer SemanticAnalyzer) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if analyzer == nil {
		return ErrNilAnalyzer
	}

	c.analyzers = append(c.analyzers, analyzer)
	return nil
}

func (c *CompositeAnalyzerImpl) RemoveAnalyzer(name string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i, a := range c.analyzers {
		if a.Name() == name {
			c.analyzers = append(c.analyzers[:i], c.analyzers[i+1:]...)
			return true
		}
	}

	return false
}

func (c *CompositeAnalyzerImpl) Analyze(input *AnalysisInput) *AnalysisResult {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := NewAnalysisResult(c)
	result.AnalyzerName = c.name

	for _, analyzer := range c.analyzers {
		if !analyzer.IsEnabled() {
			continue
		}

		analyzerResult := analyzer.Analyze(input)
		result.ThreatLevel = maxThreatLevel(result.ThreatLevel, analyzerResult.ThreatLevel)
		result.RiskScore += analyzerResult.RiskScore

		for _, match := range analyzerResult.Matches {
			match.AnalyzerName = analyzer.Name()
			result.AddMatch(match)
		}

		result.ShouldBlock = result.ShouldBlock || analyzerResult.ShouldBlock
		result.ShouldLog = result.ShouldLog || analyzerResult.ShouldLog

		result.Details[analyzer.Name()] = map[string]interface{}{
			"threat_level": analyzerResult.ThreatLevel.String(),
			"risk_score":   analyzerResult.RiskScore,
			"match_count":  len(analyzerResult.Matches),
		}
	}

	result.ShouldAllow = !result.ShouldBlock

	return result
}

func maxThreatLevel(a, b ThreatLevel) ThreatLevel {
	if a > b {
		return a
	}
	return b
}

type Dispatcher struct {
	registry     AnalyzerRegistry
	threshold    float64
	parallel     bool
	maxWorkers   int
	resultMerger ResultMerger
	settings     *AnalyzerSettings
}

type ResultMerger interface {
	Merge(results []*AnalysisResult) *AnalysisResult
}

type DefaultResultMerger struct{}

func (m *DefaultResultMerger) Merge(results []*AnalysisResult) *AnalysisResult {
	if len(results) == 0 {
		return &AnalysisResult{
			ThreatLevel:    ThreatLevelSafe,
			ShouldBlock:    false,
			ShouldLog:      false,
			ShouldAllow:    true,
			ProcessingTime: 0,
		}
	}

	if len(results) == 1 {
		return results[0]
	}

	merged := &AnalysisResult{
		ThreatLevel:     ThreatLevelSafe,
		Matches:         make([]Match, 0),
		Details:         make(map[string]interface{}),
		Recommendations: make([]string, 0),
		ProcessingTime:  0,
	}

	seenPatterns := make(map[string]bool)

	for _, result := range results {
		if result.ThreatLevel > merged.ThreatLevel {
			merged.ThreatLevel = result.ThreatLevel
		}

		merged.RiskScore += result.RiskScore
		merged.ShouldBlock = merged.ShouldBlock || result.ShouldBlock
		merged.ShouldLog = merged.ShouldLog || result.ShouldLog

		for _, match := range result.Matches {
			key := match.Pattern + ":" + match.Type.String()
			if !seenPatterns[key] {
				seenPatterns[key] = true
				merged.AddMatch(match)
			}
		}

		merged.ProcessingTime += result.ProcessingTime

		merged.Details[result.AnalyzerName] = map[string]interface{}{
			"threat_level": result.ThreatLevel.String(),
			"risk_score":   result.RiskScore,
			"match_count":  len(result.Matches),
		}

		merged.Recommendations = append(merged.Recommendations, result.Recommendations...)
	}

	merged.ShouldAllow = !merged.ShouldBlock

	if len(merged.Recommendations) > 0 {
		seen := make(map[string]bool)
		unique := make([]string, 0)
		for _, rec := range merged.Recommendations {
			if !seen[rec] {
				seen[rec] = true
				unique = append(unique, rec)
			}
		}
		merged.Recommendations = unique
	}

	return merged
}

type DispatcherConfig struct {
	Threshold  float64
	Parallel   bool
	MaxWorkers int
}

func NewDispatcher(config *DispatcherConfig) *Dispatcher {
	if config == nil {
		config = &DispatcherConfig{
			Threshold:  0.7,
			Parallel:   true,
			MaxWorkers: 4,
		}
	}

	return &Dispatcher{
		registry:     NewDefaultRegistry(),
		threshold:    config.Threshold,
		parallel:     config.Parallel,
		maxWorkers:   config.MaxWorkers,
		resultMerger: &DefaultResultMerger{},
	}
}

func (d *Dispatcher) SetRegistry(registry AnalyzerRegistry) {
	d.registry = registry
}

func (d *Dispatcher) SetThreshold(threshold float64) {
	d.threshold = threshold
}

func (d *Dispatcher) SetParallel(parallel bool) {
	d.parallel = parallel
}

func (d *Dispatcher) SetSettings(settings *AnalyzerSettings) {
	d.settings = settings
	if settings != nil {
		for _, setting := range settings.GetAllAnalyzerSettings() {
			d.registry.Get(setting.Name).SetEnabled(setting.Enabled)
		}
	}
}

func (d *Dispatcher) GetSettings() *AnalyzerSettings {
	return d.settings
}

func (d *Dispatcher) SetAnalyzerEnabled(name string, enabled bool) error {
	if d.settings != nil {
		if err := d.settings.SetAnalyzerEnabled(name, enabled); err != nil {
			return err
		}
	}
	analyzer := d.registry.Get(name)
	if analyzer != nil {
		analyzer.SetEnabled(enabled)
	}
	return nil
}

func (d *Dispatcher) GetAnalyzerEnabled(name string) (bool, error) {
	if d.settings != nil {
		return d.settings.GetAnalyzerEnabled(name)
	}
	return d.registry.Get(name).IsEnabled(), nil
}

func (d *Dispatcher) SetAnalyzerThreshold(name string, threshold float64) error {
	if d.settings != nil {
		return d.settings.SetAnalyzerThreshold(name, threshold)
	}
	return nil
}

func (d *Dispatcher) GetRateLimitConfig() *RateLimitConfig {
	if d.settings != nil {
		return d.settings.GetRateLimitConfig()
	}
	return &RateLimitConfig{Enabled: true, IPLimit: 60, URLLimit: 120, UALimit: 200}
}

func (d *Dispatcher) SetRateLimitConfig(config *RateLimitConfig) error {
	if d.settings != nil {
		return d.settings.SetRateLimitConfig(config)
	}
	return nil
}

func (d *Dispatcher) Analyze(input *AnalysisInput) *AnalysisResult {
	if input == nil {
		return &AnalysisResult{
			ThreatLevel: ThreatLevelSafe,
			ShouldBlock: false,
			ShouldLog:   false,
			ShouldAllow: true,
		}
	}

	results := d.registry.AnalyzeAll(input)
	merged := d.resultMerger.Merge(results)
	merged.ShouldBlock = merged.ShouldBlockRequest(d.threshold)

	return merged
}

func (d *Dispatcher) AnalyzeWithContext(input *AnalysisInput, context *AnalysisContext) *AnalysisResult {
	if context == nil {
		return d.Analyze(input)
	}

	if context.Bypass {
		return &AnalysisResult{
			ThreatLevel: ThreatLevelSafe,
			ShouldBlock: false,
			ShouldLog:   true,
			ShouldAllow: true,
		}
	}

	filter := func(a SemanticAnalyzer) bool {
		for _, disabled := range context.DisabledAnalyzers {
			if a.Name() == disabled {
				return false
			}
		}

		if len(context.EnabledTypes) > 0 {
			for _, t := range context.EnabledTypes {
				if a.Type() == t {
					return true
				}
			}
			return false
		}

		return true
	}

	results := d.registry.AnalyzeWithFilter(input, filter)
	merged := d.resultMerger.Merge(results)
	merged.ShouldBlock = merged.ShouldBlockRequest(d.threshold)

	return merged
}

type AnalysisContext struct {
	Bypass             bool
	DisabledAnalyzers  []string
	EnabledTypes       []string
	CustomThreshold    float64
	AdditionalMetadata map[string]interface{}
}

func NewAnalysisContext() *AnalysisContext {
	return &AnalysisContext{
		DisabledAnalyzers:  make([]string, 0),
		EnabledTypes:       make([]string, 0),
		AdditionalMetadata: make(map[string]interface{}),
	}
}

func (c *AnalysisContext) DisableAnalyzer(name string) {
	c.DisabledAnalyzers = append(c.DisabledAnalyzers, name)
}

func (c *AnalysisContext) EnableType(analyzerType string) {
	c.EnabledTypes = append(c.EnabledTypes, analyzerType)
}

func (c *AnalysisContext) SetBypass(bypass bool) {
	c.Bypass = bypass
}

func CreateDefaultDispatcher() *Dispatcher {
	registry := NewDefaultRegistry()

	sqlAnalyzer := NewSQLInjectionAnalyzer()
	xssAnalyzer := NewXSSAnalyzer()
	commandAnalyzer := NewCommandInjectionAnalyzer()
	phpAnalyzer := NewPHPAnalyzer()
	jsAnalyzer := NewJSAnalyzer()
	zeroDayAnalyzer := NewZeroDayAnalyzer()

	registry.Register(sqlAnalyzer)
	registry.Register(xssAnalyzer)
	registry.Register(commandAnalyzer)
	registry.Register(phpAnalyzer)
	registry.Register(jsAnalyzer)
	registry.Register(zeroDayAnalyzer)

	dispatcher := NewDispatcher(nil)
	dispatcher.SetRegistry(registry)

	settings := NewAnalyzerSettings(
		WithAutoSave(true, 5*time.Second),
	)

	dispatcher.SetSettings(settings)

	return dispatcher
}
