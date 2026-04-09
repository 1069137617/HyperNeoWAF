package analyzer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"
)

type ReloadEventType int

const (
	EventRuleReload ReloadEventType = iota
	EventConfigReload
	EventVirtualPatchApply
	EventVirtualPatchRemove
	EventRuleEnable
	EventRuleDisable
)

func (t ReloadEventType) String() string {
	switch t {
	case EventRuleReload:
		return "rule_reload"
	case EventConfigReload:
		return "config_reload"
	case EventVirtualPatchApply:
		return "virtual_patch_apply"
	case EventVirtualPatchRemove:
		return "virtual_patch_remove"
	case EventRuleEnable:
		return "rule_enable"
	case EventRuleDisable:
		return "rule_disable"
	default:
		return "unknown"
	}
}

type ReloadEvent struct {
	Type        ReloadEventType
	Timestamp   time.Time
	Source      string
	Description string
	Changes     []Change
	Error       error
}

type Change struct {
	Path       string
	RuleID     string
	OldValue   interface{}
	NewValue   interface{}
	ChangeType string
}

type RuleVersion struct {
	Version   string
	RuleCount int
	Checksum  string
	AppliedAt time.Time
	AppliedBy string
}

type ConfigWatcher struct {
	path        string
	interval    time.Duration
	onChange    func([]byte) error
	checksum    string
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
	enabled     bool
	lastModTime time.Time
}

type HotReloader struct {
	rulesPath        string
	configPath       string
	registry         AnalyzerRegistry
	version          *RuleVersion
	watchers         map[string]*ConfigWatcher
	virtualPatches   map[string]*VirtualPatch
	eventListeners   map[string][]EventListener
	reloadStrategies map[ReloadEventType]ReloadStrategy
	mu               sync.RWMutex
	ctx              context.Context
	cancel           context.CancelFunc
	stats            *ReloaderStats
	patchExecutor    *PatchExecutor
}

type EventListener func(*ReloadEvent)

type ReloadStrategy interface {
	ShouldReload(event *ReloadEvent) bool
	ApplyReload(event *ReloadEvent) error
	Priority() int
}

type DefaultReloadStrategy struct {
	priority int
}

func (s *DefaultReloadStrategy) ShouldReload(event *ReloadEvent) bool {
	return event.Error == nil
}

func (s *DefaultReloadStrategy) ApplyReload(event *ReloadEvent) error {
	return nil
}

func (s *DefaultReloadStrategy) Priority() int {
	return s.priority
}

type VirtualPatch struct {
	ID              string
	Name            string
	Description     string
	Enabled         bool
	Priority        int
	TargetAnalyzers []string
	Pattern         string
	ThreatLevel     ThreatLevel
	MatchType       MatchType
	ExpiresAt       time.Time
	CreatedAt       time.Time
	CreatedBy       string
	Metadata        map[string]interface{}
	mu              sync.RWMutex
}

type PatchExecutor struct {
	patches          map[string]*VirtualPatch
	appliedPatches   map[string][]string
	analyzerRegistry AnalyzerRegistry
	mu               sync.RWMutex
	stats            *PatchExecutorStats
}

type PatchExecutorStats struct {
	TotalApplied int64
	TotalBlocked int64
	TotalAllowed int64
	AvgExecTime  time.Duration
	mu           sync.RWMutex
}

type ReloaderStats struct {
	TotalReloads     int64
	FailedReloads    int64
	LastReloadTime   time.Time
	LastReloadResult string
	LastError        error
	WatchedPaths     []string
	ActiveWatchers   int
	mu               sync.RWMutex
}

var (
	ErrPatchNotFound      = errors.New("virtual patch not found")
	ErrPatchAlreadyExists = errors.New("virtual patch already exists")
	ErrInvalidPatch       = errors.New("invalid virtual patch")
	ErrPatchExpired       = errors.New("virtual patch has expired")
	ErrRuleNotFound       = errors.New("rule not found")
	ErrRuleAlreadyExists  = errors.New("rule already exists")
	ErrInvalidConfig      = errors.New("invalid configuration")
)

func NewHotReloader(rulesPath, configPath string, registry AnalyzerRegistry) *HotReloader {
	ctx, cancel := context.WithCancel(context.Background())

	h := &HotReloader{
		rulesPath:        rulesPath,
		configPath:       configPath,
		registry:         registry,
		version:          &RuleVersion{},
		watchers:         make(map[string]*ConfigWatcher),
		virtualPatches:   make(map[string]*VirtualPatch),
		eventListeners:   make(map[string][]EventListener),
		reloadStrategies: make(map[ReloadEventType]ReloadStrategy),
		ctx:              ctx,
		cancel:           cancel,
		stats:            &ReloaderStats{},
		patchExecutor:    NewPatchExecutor(registry),
	}

	h.initDefaultStrategies()

	return h
}

func (h *HotReloader) initDefaultStrategies() {
	h.reloadStrategies[EventRuleReload] = &DefaultReloadStrategy{priority: 1}
	h.reloadStrategies[EventConfigReload] = &DefaultReloadStrategy{priority: 2}
	h.reloadStrategies[EventVirtualPatchApply] = &DefaultReloadStrategy{priority: 0}
	h.reloadStrategies[EventVirtualPatchRemove] = &DefaultReloadStrategy{priority: 0}
}

func NewPatchExecutor(registry AnalyzerRegistry) *PatchExecutor {
	return &PatchExecutor{
		patches:          make(map[string]*VirtualPatch),
		appliedPatches:   make(map[string][]string),
		analyzerRegistry: registry,
		stats:            &PatchExecutorStats{},
	}
}

func (e *PatchExecutor) RegisterPatch(patch *VirtualPatch) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if patch == nil || patch.ID == "" {
		return ErrInvalidPatch
	}

	if _, exists := e.patches[patch.ID]; exists {
		return ErrPatchAlreadyExists
	}

	e.patches[patch.ID] = patch
	return nil
}

func (e *PatchExecutor) UnregisterPatch(patchID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.patches[patchID]; !exists {
		return ErrPatchNotFound
	}

	delete(e.patches, patchID)

	for analyzerName := range e.appliedPatches {
		patches := e.appliedPatches[analyzerName]
		for i, id := range patches {
			if id == patchID {
				e.appliedPatches[analyzerName] = append(patches[:i], patches[i+1:]...)
				break
			}
		}
	}

	return nil
}

func (e *PatchExecutor) ApplyPatch(patchID string, input *AnalysisInput) *AnalysisResult {
	e.mu.RLock()
	patch, exists := e.patches[patchID]
	e.mu.RUnlock()

	if !exists {
		return nil
	}

	patch.mu.RLock()
	defer patch.mu.RUnlock()

	if !patch.Enabled {
		return nil
	}

	if !patch.ExpiresAt.IsZero() && time.Now().After(patch.ExpiresAt) {
		return nil
	}

	normalized := NormalizeInput(input.Raw)

	if containsPattern(normalized, patch.Pattern) {
		return &AnalysisResult{
			ThreatLevel:  patch.ThreatLevel,
			AnalyzerName: "VirtualPatch:" + patch.Name,
			AnalyzerType: "virtual_patch",
			Matches: []Match{
				{
					Type:         patch.MatchType,
					ThreatLevel:  patch.ThreatLevel,
					Pattern:      patch.Pattern,
					Description:  patch.Description,
					Evidence:     input.Raw,
					AnalyzerName: "VirtualPatch:" + patch.Name,
				},
			},
			IsSuspicious: true,
			RiskScore:    1.0,
			ShouldBlock:  true,
			ShouldLog:    true,
			ShouldAllow:  false,
			ProcessedAt:  time.Now(),
		}
	}

	return nil
}

func (e *PatchExecutor) ApplyAllPatches(input *AnalysisInput) []*AnalysisResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	results := make([]*AnalysisResult, 0)

	for _, patch := range e.patches {
		if !patch.Enabled {
			continue
		}

		if !patch.ExpiresAt.IsZero() && time.Now().After(patch.ExpiresAt) {
			continue
		}

		patch.mu.RLock()
		normalized := NormalizeInput(input.Raw)
		if containsPattern(normalized, patch.Pattern) {
			result := &AnalysisResult{
				ThreatLevel:  patch.ThreatLevel,
				AnalyzerName: "VirtualPatch:" + patch.Name,
				AnalyzerType: "virtual_patch",
				Matches: []Match{
					{
						Type:         patch.MatchType,
						ThreatLevel:  patch.ThreatLevel,
						Pattern:      patch.Pattern,
						Description:  patch.Description,
						Evidence:     input.Raw,
						AnalyzerName: "VirtualPatch:" + patch.Name,
					},
				},
				IsSuspicious: true,
				RiskScore:    1.0,
				ShouldBlock:  true,
				ShouldLog:    true,
				ShouldAllow:  false,
				ProcessedAt:  time.Now(),
			}
			results = append(results, result)
		}
		patch.mu.RUnlock()
	}

	return results
}

func (e *PatchExecutor) EnablePatch(patchID string) error {
	e.mu.RLock()
	patch, exists := e.patches[patchID]
	e.mu.RUnlock()

	if !exists {
		return ErrPatchNotFound
	}

	patch.mu.Lock()
	patch.Enabled = true
	patch.mu.Unlock()

	return nil
}

func (e *PatchExecutor) DisablePatch(patchID string) error {
	e.mu.RLock()
	patch, exists := e.patches[patchID]
	e.mu.RUnlock()

	if !exists {
		return ErrPatchNotFound
	}

	patch.mu.Lock()
	patch.Enabled = false
	patch.mu.Unlock()

	return nil
}

func (e *PatchExecutor) GetPatch(patchID string) (*VirtualPatch, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	patch, exists := e.patches[patchID]
	return patch, exists
}

func (e *PatchExecutor) ListPatches() []*VirtualPatch {
	e.mu.RLock()
	defer e.mu.RUnlock()

	patches := make([]*VirtualPatch, 0, len(e.patches))
	for _, patch := range e.patches {
		patches = append(patches, patch)
	}
	return patches
}

func containsPattern(text, pattern string) bool {
	return len(pattern) > 0 && len(text) > 0 &&
		(len(pattern) <= len(text) &&
			(pattern == text ||
				len(pattern) <= len(text) && matchSubstring(text, pattern)))
}

func matchSubstring(text, pattern string) bool {
	for i := 0; i <= len(text)-len(pattern); i++ {
		if text[i:i+len(pattern)] == pattern {
			return true
		}
	}
	return false
}

func NewConfigWatcher(path string, interval time.Duration, onChange func([]byte) error) *ConfigWatcher {
	ctx, cancel := context.WithCancel(context.Background())

	return &ConfigWatcher{
		path:     path,
		interval: interval,
		onChange: onChange,
		enabled:  true,
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (w *ConfigWatcher) Start() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.enabled {
		return nil
	}

	info, err := os.Stat(w.path)
	if err != nil {
		return err
	}
	w.lastModTime = info.ModTime()

	go w.watch()

	return nil
}

func (w *ConfigWatcher) watch() {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			w.check()
		}
	}
}

func (w *ConfigWatcher) check() {
	w.mu.RLock()
	if !w.enabled {
		w.mu.RUnlock()
		return
	}
	path := w.path
	onChange := w.onChange
	w.mu.RUnlock()

	info, err := os.Stat(path)
	if err != nil {
		return
	}

	if info.ModTime().After(w.lastModTime) {
		content, err := os.ReadFile(path)
		if err != nil {
			return
		}

		newChecksum := computeChecksum(content)
		w.mu.Lock()
		if newChecksum != w.checksum {
			w.checksum = newChecksum
			w.lastModTime = info.ModTime()
			w.mu.Unlock()

			if onChange != nil {
				onChange(content)
			}
		} else {
			w.mu.Unlock()
		}
	}
}

func (w *ConfigWatcher) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.enabled = false
	w.cancel()
}

func (w *ConfigWatcher) SetInterval(interval time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.interval = interval
}

func computeChecksum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func (h *HotReloader) StartWatching() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.rulesPath != "" {
		watcher := NewConfigWatcher(h.rulesPath, 5*time.Second, h.handleRulesChange)
		h.watchers[h.rulesPath] = watcher
		if err := watcher.Start(); err != nil {
			return err
		}
	}

	if h.configPath != "" {
		watcher := NewConfigWatcher(h.configPath, 5*time.Second, h.handleConfigChange)
		h.watchers[h.configPath] = watcher
		if err := watcher.Start(); err != nil {
			return err
		}
	}

	h.stats.ActiveWatchers = len(h.watchers)
	return nil
}

func (h *HotReloader) StopWatching() {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, watcher := range h.watchers {
		watcher.Stop()
	}

	h.watchers = make(map[string]*ConfigWatcher)
	h.stats.ActiveWatchers = 0
}

func (h *HotReloader) handleRulesChange(content []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	event := &ReloadEvent{
		Type:        EventRuleReload,
		Timestamp:   time.Now(),
		Source:      h.rulesPath,
		Description: "规则文件变更",
		Changes:     h.computeChanges(content),
	}

	if err := h.reloadRules(content); err != nil {
		event.Error = err
		h.stats.FailedReloads++
		h.stats.LastError = err
		h.stats.LastReloadResult = "failed: " + err.Error()
	} else {
		h.stats.TotalReloads++
		h.stats.LastReloadTime = time.Now()
		h.stats.LastReloadResult = "success"
	}

	h.notifyListeners(event)
	return nil
}

func (h *HotReloader) handleConfigChange(content []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	event := &ReloadEvent{
		Type:        EventConfigReload,
		Timestamp:   time.Now(),
		Source:      h.configPath,
		Description: "配置文件变更",
	}

	if err := h.reloadConfig(content); err != nil {
		event.Error = err
		h.stats.FailedReloads++
		h.stats.LastError = err
		h.stats.LastReloadResult = "failed: " + err.Error()
	} else {
		h.stats.TotalReloads++
		h.stats.LastReloadTime = time.Now()
		h.stats.LastReloadResult = "success"
	}

	h.notifyListeners(event)
	return nil
}

func (h *HotReloader) computeChanges(content []byte) []Change {
	return make([]Change, 0)
}

func (h *HotReloader) reloadRules(content []byte) error {
	type RuleFile struct {
		Version string                   `json:"version"`
		Rules   []map[string]interface{} `json:"rules"`
	}

	var file RuleFile
	if err := json.Unmarshal(content, &file); err != nil {
		return err
	}

	h.version = &RuleVersion{
		Version:   file.Version,
		RuleCount: len(file.Rules),
		Checksum:  computeChecksum(content),
		AppliedAt: time.Now(),
	}

	return nil
}

func (h *HotReloader) reloadConfig(content []byte) error {
	return nil
}

func (h *HotReloader) RegisterListener(name string, listener EventListener) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.eventListeners[name] = append(h.eventListeners[name], listener)
}

func (h *HotReloader) UnregisterListener(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	delete(h.eventListeners, name)
}

func (h *HotReloader) notifyListeners(event *ReloadEvent) {
	for _, listeners := range h.eventListeners {
		for _, listener := range listeners {
			go listener(event)
		}
	}
}

func (h *HotReloader) ApplyVirtualPatch(patch *VirtualPatch) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, exists := h.virtualPatches[patch.ID]; exists {
		return ErrPatchAlreadyExists
	}

	if patch.ID == "" || patch.Pattern == "" {
		return ErrInvalidPatch
	}

	patch.CreatedAt = time.Now()
	h.virtualPatches[patch.ID] = patch

	event := &ReloadEvent{
		Type:        EventVirtualPatchApply,
		Timestamp:   time.Now(),
		Source:      "HotReloader",
		Description: "应用虚拟补丁: " + patch.Name,
		Changes: []Change{
			{
				Path:       "",
				RuleID:     patch.ID,
				NewValue:   patch,
				ChangeType: "virtual_patch_apply",
			},
		},
	}

	h.notifyListeners(event)

	return h.patchExecutor.RegisterPatch(patch)
}

func (h *HotReloader) RemoveVirtualPatch(patchID string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	patch, exists := h.virtualPatches[patchID]
	if !exists {
		return ErrPatchNotFound
	}

	delete(h.virtualPatches, patchID)

	event := &ReloadEvent{
		Type:        EventVirtualPatchRemove,
		Timestamp:   time.Now(),
		Source:      "HotReloader",
		Description: "移除虚拟补丁: " + patch.Name,
		Changes: []Change{
			{
				Path:       "",
				RuleID:     patchID,
				OldValue:   patch,
				ChangeType: "virtual_patch_remove",
			},
		},
	}

	h.notifyListeners(event)

	return h.patchExecutor.UnregisterPatch(patchID)
}

func (h *HotReloader) GetVirtualPatch(patchID string) (*VirtualPatch, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	patch, exists := h.virtualPatches[patchID]
	return patch, exists
}

func (h *HotReloader) ListVirtualPatches() []*VirtualPatch {
	h.mu.RLock()
	defer h.mu.RUnlock()

	patches := make([]*VirtualPatch, 0, len(h.virtualPatches))
	for _, patch := range h.virtualPatches {
		patches = append(patches, patch)
	}
	return patches
}

func (h *HotReloader) EnableVirtualPatch(patchID string) error {
	h.mu.RLock()
	patch, exists := h.virtualPatches[patchID]
	h.mu.RUnlock()

	if !exists {
		return ErrPatchNotFound
	}

	h.mu.Lock()
	patch.Enabled = true
	h.mu.Unlock()

	event := &ReloadEvent{
		Type:        EventRuleEnable,
		Timestamp:   time.Now(),
		Source:      "HotReloader",
		Description: "启用虚拟补丁: " + patch.Name,
	}

	h.notifyListeners(event)

	return h.patchExecutor.EnablePatch(patchID)
}

func (h *HotReloader) DisableVirtualPatch(patchID string) error {
	h.mu.RLock()
	patch, exists := h.virtualPatches[patchID]
	h.mu.RUnlock()

	if !exists {
		return ErrPatchNotFound
	}

	h.mu.Lock()
	patch.Enabled = false
	h.mu.Unlock()

	event := &ReloadEvent{
		Type:        EventRuleDisable,
		Timestamp:   time.Now(),
		Source:      "HotReloader",
		Description: "禁用虚拟补丁: " + patch.Name,
	}

	h.notifyListeners(event)

	return h.patchExecutor.DisablePatch(patchID)
}

func (h *HotReloader) GetVersion() *RuleVersion {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.version
}

func (h *HotReloader) GetStats() *ReloaderStats {
	h.mu.RLock()
	defer h.mu.RUnlock()

	stats := &ReloaderStats{
		TotalReloads:     h.stats.TotalReloads,
		FailedReloads:    h.stats.FailedReloads,
		LastReloadTime:   h.stats.LastReloadTime,
		LastReloadResult: h.stats.LastReloadResult,
		LastError:        h.stats.LastError,
		ActiveWatchers:   h.stats.ActiveWatchers,
		WatchedPaths:     make([]string, 0, len(h.watchers)),
	}

	for path := range h.watchers {
		stats.WatchedPaths = append(stats.WatchedPaths, path)
	}

	return stats
}

func (h *HotReloader) TriggerReload() error {
	h.mu.RLock()
	rulesPath := h.rulesPath
	configPath := h.configPath
	h.mu.RUnlock()

	if rulesPath != "" {
		content, err := os.ReadFile(rulesPath)
		if err != nil {
			return err
		}
		h.handleRulesChange(content)
	}

	if configPath != "" {
		content, err := os.ReadFile(configPath)
		if err != nil {
			return err
		}
		h.handleConfigChange(content)
	}

	return nil
}

func (h *HotReloader) Close() {
	h.StopWatching()
	h.cancel()
}

type RuleManagerConfig struct {
	RulesPath    string
	AutoSave     bool
	SaveInterval time.Duration
}

type RuleManager struct {
	rules            map[string]*Rule
	ruleGroups       map[string]*RuleGroup
	version          *RuleVersion
	config           *RuleManagerConfig
	hotReloader      *HotReloader
	mu               sync.RWMutex
	analyzerRegistry AnalyzerRegistry
}

type Rule struct {
	ID             string
	Name           string
	Pattern        string
	ThreatLevel    ThreatLevel
	MatchType      MatchType
	Enabled        bool
	Analyzers      []string
	Description    string
	Recommendation string
	Tags           []string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	Version        string
	Metadata       map[string]interface{}
	mu             sync.RWMutex
}

type RuleGroup struct {
	ID          string
	Name        string
	Description string
	RuleIDs     []string
	Priority    int
	Enabled     bool
	mu          sync.RWMutex
}

func NewRuleManager(registry AnalyzerRegistry, config *RuleManagerConfig) *RuleManager {
	return &RuleManager{
		rules:            make(map[string]*Rule),
		ruleGroups:       make(map[string]*RuleGroup),
		version:          &RuleVersion{},
		config:           config,
		analyzerRegistry: registry,
	}
}

func (m *RuleManager) AddRule(rule *Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.rules[rule.ID]; exists {
		return ErrRuleAlreadyExists
	}

	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()
	m.rules[rule.ID] = rule

	return nil
}

func (m *RuleManager) UpdateRule(ruleID string, updates map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rule, exists := m.rules[ruleID]
	if !exists {
		return ErrRuleNotFound
	}

	if name, ok := updates["name"].(string); ok {
		rule.Name = name
	}
	if pattern, ok := updates["pattern"].(string); ok {
		rule.Pattern = pattern
	}
	if threatLevel, ok := updates["threat_level"]; ok {
		if tl, ok := threatLevel.(ThreatLevel); ok {
			rule.ThreatLevel = tl
		}
	}
	if enabled, ok := updates["enabled"].(bool); ok {
		rule.Enabled = enabled
	}

	rule.UpdatedAt = time.Now()

	return nil
}

func (m *RuleManager) RemoveRule(ruleID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.rules[ruleID]; !exists {
		return ErrRuleNotFound
	}

	delete(m.rules, ruleID)
	return nil
}

func (m *RuleManager) GetRule(ruleID string) (*Rule, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rule, exists := m.rules[ruleID]
	return rule, exists
}

func (m *RuleManager) ListRules() []*Rule {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rules := make([]*Rule, 0, len(m.rules))
	for _, rule := range m.rules {
		rules = append(rules, rule)
	}
	return rules
}

func (m *RuleManager) EnableRule(ruleID string) error {
	m.mu.RLock()
	rule, exists := m.rules[ruleID]
	m.mu.RUnlock()

	if !exists {
		return ErrRuleNotFound
	}

	m.mu.Lock()
	rule.Enabled = true
	rule.UpdatedAt = time.Now()
	m.mu.Unlock()

	return nil
}

func (m *RuleManager) DisableRule(ruleID string) error {
	m.mu.RLock()
	rule, exists := m.rules[ruleID]
	m.mu.RUnlock()

	if !exists {
		return ErrRuleNotFound
	}

	m.mu.Lock()
	rule.Enabled = false
	rule.UpdatedAt = time.Now()
	m.mu.Unlock()

	return nil
}

func (m *RuleManager) AddRuleGroup(group *RuleGroup) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.ruleGroups[group.ID]; exists {
		return errors.New("rule group already exists")
	}

	m.ruleGroups[group.ID] = group
	return nil
}

func (m *RuleManager) GetRuleGroup(groupID string) (*RuleGroup, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	group, exists := m.ruleGroups[groupID]
	return group, exists
}

func (m *RuleManager) ListRuleGroups() []*RuleGroup {
	m.mu.RLock()
	defer m.mu.RUnlock()

	groups := make([]*RuleGroup, 0, len(m.ruleGroups))
	for _, group := range m.ruleGroups {
		groups = append(groups, group)
	}
	return groups
}

func (m *RuleManager) GetRulesByGroup(groupID string) []*Rule {
	m.mu.RLock()
	defer m.mu.RUnlock()

	group, exists := m.ruleGroups[groupID]
	if !exists {
		return nil
	}

	rules := make([]*Rule, 0)
	for _, ruleID := range group.RuleIDs {
		if rule, ok := m.rules[ruleID]; ok {
			rules = append(rules, rule)
		}
	}

	return rules
}

func (m *RuleManager) SaveRules(path string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	data := struct {
		Version string  `json:"version"`
		Rules   []*Rule `json:"rules"`
	}{
		Version: m.version.Version,
		Rules:   make([]*Rule, 0, len(m.rules)),
	}

	for _, rule := range m.rules {
		data.Rules = append(data.Rules, rule)
	}

	content, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, content, 0644)
}

func (m *RuleManager) LoadRules(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	type RuleFile struct {
		Version string  `json:"version"`
		Rules   []*Rule `json:"rules"`
	}

	var file RuleFile
	if err := json.Unmarshal(content, &file); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.rules = make(map[string]*Rule)
	for _, rule := range file.Rules {
		m.rules[rule.ID] = rule
	}

	m.version.Version = file.Version
	m.version.RuleCount = len(file.Rules)
	m.version.Checksum = computeChecksum(content)
	m.version.AppliedAt = time.Now()

	return nil
}

func (m *RuleManager) SetHotReloader(reloader *HotReloader) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hotReloader = reloader
}

func (m *RuleManager) GetHotReloader() *HotReloader {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.hotReloader
}
