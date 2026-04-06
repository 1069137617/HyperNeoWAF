package analyzer

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

// ==================== 威胁等级枚举 ====================
// ThreatLevel - 威胁等级枚举
// 用于表示检测到的威胁的严重程度，从低到高分为 5 个等级
type ThreatLevel int

const (
	ThreatLevelSafe     ThreatLevel = iota // 安全 - 无威胁
	ThreatLevelLow                         // 低风险 - 可疑但无害
	ThreatLevelMedium                      // 中风险 - 需要关注
	ThreatLevelHigh                        // 高风险 - 强烈建议拦截
	ThreatLevelCritical                    // 严重风险 - 必须拦截
)

// String - 返回威胁等级对应的字符串表示
func (t ThreatLevel) String() string {
	switch t {
	case ThreatLevelSafe:
		return "safe"
	case ThreatLevelLow:
		return "low"
	case ThreatLevelMedium:
		return "medium"
	case ThreatLevelHigh:
		return "high"
	case ThreatLevelCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// ==================== 匹配类型枚举 ====================
// MatchType - 匹配类型枚举
// 表示检测到威胁的匹配方式，用于分析威胁特征
type MatchType int

const (
	MatchTypeNone       MatchType = iota // 无匹配
	MatchTypeExact                       // 精确匹配 - 完全相同的恶意特征
	MatchTypePattern                     // 模式匹配 - 正则表达式匹配
	MatchTypeSemantic                    // 语义匹配 - 基于语义的检测
	MatchTypeBehavioral                  // 行为匹配 - 基于行为的检测
)

// String - 返回匹配类型对应的字符串表示
func (m MatchType) String() string {
	switch m {
	case MatchTypeNone:
		return "none"
	case MatchTypeExact:
		return "exact"
	case MatchTypePattern:
		return "pattern"
	case MatchTypeSemantic:
		return "semantic"
	case MatchTypeBehavioral:
		return "behavioral"
	default:
		return "unknown"
	}
}

// ==================== 匹配结果结构 ====================
// Match - 单个匹配结果结构
// 描述一次检测到的威胁匹配，包括位置、类型、威胁等级等信息
type Match struct {
	Type           MatchType   // 匹配类型
	ThreatLevel    ThreatLevel // 威胁等级
	Pattern        string      // 匹配的正则表达式或模式
	Position       int         // 匹配在输入中的起始位置
	Length         int         // 匹配的长度
	Description    string      // 威胁描述
	Evidence       string      // 匹配的证据（原始片段）
	Recommendation string      // 建议的应对措施
	AnalyzerName   string      // 分析器名称
}

// ==================== 分析输入结构 ====================
// AnalysisInput - 语义分析的输入数据结构
// 包含待检测的原始数据和各种上下文信息
type AnalysisInput struct {
	Raw         string                 // 原始输入字符串
	Normalized  string                 // 规范化后的输入
	Scheme      string                 // URL 协议 (http/https)
	Host        string                 // URL 主机名
	Path        string                 // URL 路径
	QueryString string                 // URL 查询字符串
	Headers     map[string]string      // HTTP 请求头
	Method      string                 // HTTP 方法 (GET/POST 等)
	ContentType string                 // Content-Type
	Body        string                 // 请求体
	Source      string                 // 来源标识
	ClientIP    string                 // 客户端 IP
	UserAgent   string                 // User-Agent
	Timestamp   time.Time              // 时间戳
	Metadata    map[string]interface{} // 额外元数据
}

// ==================== 分析结果结构 ====================
// AnalysisResult - 语义分析的结果数据结构
// 包含分析结论、匹配列表、风险评分和处理建议
type AnalysisResult struct {
	ThreatLevel     ThreatLevel            // 综合威胁等级
	AnalyzerName    string                 // 分析器名称
	AnalyzerType    string                 // 分析器类型
	Matches         []Match                // 匹配列表
	IsSuspicious    bool                   // 是否可疑
	RiskScore       float64                // 风险评分 (0.0-1.0)
	ShouldBlock     bool                   // 是否应该拦截
	ShouldLog       bool                   // 是否应该记录日志
	ShouldAllow     bool                   // 是否应该允许
	ProcessedAt     time.Time              // 处理时间
	ProcessingTime  time.Duration          // 处理耗时
	Details         map[string]interface{} // 额外详情
	Recommendations []string               // 建议列表
}

// ==================== 分析器接口定义 ====================
// SemanticAnalyzer - 语义分析器接口
// 所有具体的分析器（如 SQL 注入、XSS 等）都需要实现此接口
type SemanticAnalyzer interface {
	Name() string                                  // 返回分析器名称
	Type() string                                  // 返回分析器类型
	Version() string                               // 返回分析器版本
	Analyze(input *AnalysisInput) *AnalysisResult  // 执行分析
	Configure(config map[string]interface{}) error // 配置分析器
	IsEnabled() bool                               // 是否启用
	SetEnabled(enabled bool)                       // 设置启用状态
}

// CompositeAnalyzer - 组合分析器接口
// 用于将多个分析器组合成一个进行分析
type CompositeAnalyzer interface {
	SemanticAnalyzer
	Analyzers() []SemanticAnalyzer         // 获取子分析器列表
	AddAnalyzer(analyzer SemanticAnalyzer) // 添加子分析器
	RemoveAnalyzer(name string) bool       // 移除子分析器
}

// AnalyzerRegistry - 分析器注册表接口
// 负责管理所有已注册的分析器，提供查询和批量分析功能
type AnalyzerRegistry interface {
	Register(analyzer SemanticAnalyzer) error                                                     // 注册分析器
	Unregister(name string) bool                                                                  // 注销分析器
	Get(name string) SemanticAnalyzer                                                             // 获取分析器
	List() []SemanticAnalyzer                                                                     // 列出所有分析器
	ListByType(analyzerType string) []SemanticAnalyzer                                            // 按类型筛选
	AnalyzeAll(input *AnalysisInput) []*AnalysisResult                                            // 所有分析器分析
	AnalyzeWithFilter(input *AnalysisInput, filter func(SemanticAnalyzer) bool) []*AnalysisResult // 筛选后分析
}

// ConfigValidator - 配置验证器接口
// 用于验证分析器配置的有效性
type ConfigValidator interface {
	Validate(config map[string]interface{}) (bool, error) // 验证配置
	DefaultConfig() map[string]interface{}                // 获取默认配置
}

// AnalyzerInfo - 分析器信息结构
// 用于返回分析器的元信息
type AnalyzerInfo struct {
	Name         string      // 分析器名称
	Type         string      // 分析器类型
	Version      string      // 分析器版本
	IsEnabled    bool        // 是否启用
	ThreatLevel  ThreatLevel // 威胁等级
	MatchCount   int64       // 匹配次数
	LastAnalyzed time.Time   // 最后分析时间
}

// PatternCache - 正则表达式缓存结构
// 用于缓存已编译的正则表达式，避免重复编译开销
type PatternCache struct {
	patterns map[string]*regexp.Regexp
	mu       sync.RWMutex
}

// NewPatternCache - 创建新的模式缓存
func NewPatternCache() *PatternCache {
	return &PatternCache{
		patterns: make(map[string]*regexp.Regexp),
	}
}

// Get - 获取或编译正则表达式
// 如果缓存中已存在直接返回，否则编译后缓存并返回
func (c *PatternCache) Get(pattern string) (*regexp.Regexp, error) {
	c.mu.RLock()
	compiled, exists := c.patterns[pattern]
	c.mu.RUnlock()

	if exists {
		return compiled, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// 双重检查
	if compiled, exists := c.patterns[pattern]; exists {
		return compiled, nil
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	c.patterns[pattern] = re
	return re, nil
}

// GetMust - 获取正则表达式，编译失败时panic
func (c *PatternCache) GetMust(pattern string) *regexp.Regexp {
	re, err := c.Get(pattern)
	if err != nil {
		panic("invalid regex pattern: " + pattern)
	}
	return re
}

// Precompile - 预编译多个正则表达式
// 批量编译模式并缓存，适用于初始化时
func (c *PatternCache) Precompile(patterns []struct {
	Pattern     string
	Description string
	ThreatLevel ThreatLevel
}) map[string]*regexp.Regexp {
	result := make(map[string]*regexp.Regexp)

	for _, p := range patterns {
		re, err := c.Get(p.Pattern)
		if err != nil {
			continue
		}
		result[p.Pattern] = re
	}

	return result
}

// 全局正则缓存实例
var globalPatternCache = NewPatternCache()

// GetGlobalPatternCache - 获取全局正则缓存
func GetGlobalPatternCache() *PatternCache {
	return globalPatternCache
}

// ==================== 分析结果辅助函数 ====================
// NewAnalysisResult - 创建新的分析结果
// 为指定分析器初始化一个默认结果
func NewAnalysisResult(analyzer SemanticAnalyzer) *AnalysisResult {
	return &AnalysisResult{
		ThreatLevel:     ThreatLevelSafe,
		AnalyzerName:    analyzer.Name(),
		AnalyzerType:    analyzer.Type(),
		Matches:         make([]Match, 0),
		IsSuspicious:    false,
		RiskScore:       0.0,
		ShouldBlock:     false,
		ShouldLog:       true,
		ShouldAllow:     true,
		ProcessedAt:     time.Now(),
		ProcessingTime:  0,
		Details:         make(map[string]interface{}),
		Recommendations: make([]string, 0),
	}
}

// AddMatch - 添加匹配结果
// 将一个新的匹配添加到结果中，同时更新相关统计
func (r *AnalysisResult) AddMatch(match Match) {
	r.Matches = append(r.Matches, match)
	r.IsSuspicious = true
	r.ShouldLog = true
	if match.ThreatLevel > r.ThreatLevel {
		r.ThreatLevel = match.ThreatLevel
	}
	r.RiskScore += calculateRiskScore(match)
}

// ShouldBlockRequest - 判断是否应拦截请求
// 基于风险评分阈值和威胁等级综合判断
func (r *AnalysisResult) ShouldBlockRequest(threshold float64) bool {
	return r.RiskScore >= threshold || r.ThreatLevel >= ThreatLevelHigh
}

// calculateRiskScore - 计算单个匹配的风险评分
// 基于匹配类型和威胁等级计算风险分值
func calculateRiskScore(match Match) float64 {
	baseScore := 0.0
	switch match.Type {
	case MatchTypeExact:
		baseScore = 1.0 // 精确匹配风险最高
	case MatchTypePattern:
		baseScore = 0.8 // 模式匹配次之
	case MatchTypeSemantic:
		baseScore = 0.6 // 语义匹配
	case MatchTypeBehavioral:
		baseScore = 0.4 // 行为匹配风险最低
	}

	// 威胁等级乘数
	threatMultiplier := 1.0
	switch match.ThreatLevel {
	case ThreatLevelCritical:
		threatMultiplier = 2.0 // 严重威胁加倍
	case ThreatLevelHigh:
		threatMultiplier = 1.5 // 高威胁 1.5 倍
	case ThreatLevelMedium:
		threatMultiplier = 1.0 // 中威胁标准
	case ThreatLevelLow:
		threatMultiplier = 0.5 // 低威胁减半
	}

	return baseScore * threatMultiplier
}

// ==================== 输入处理工具函数 ====================
// NormalizeInput - 规范化输入字符串
// 对输入进行小写转换和常见编码规范化，便于检测
func NormalizeInput(input string) string {
	normalized := strings.ToLower(input)
	normalized = strings.ReplaceAll(normalized, "<>", "")
	normalized = strings.ReplaceAll(normalized, "'", "\"")
	normalized = strings.ReplaceAll(normalized, ";--", " ")
	normalized = strings.ReplaceAll(normalized, "/*", " ")
	normalized = strings.ReplaceAll(normalized, "*/", " ")
	normalized = strings.ReplaceAll(normalized, "char(", " chr(")
	normalized = strings.ReplaceAll(normalized, "union+select", "union select")
	normalized = strings.ReplaceAll(normalized, "union%20select", "union select")
	normalized = strings.TrimSpace(normalized)
	return normalized
}

// ==================== 关键词提取工具函数 ====================
// ExtractSQLKeywords - 从输入中提取 SQL 关键词
// 返回输入中包含的所有 SQL 关键词列表
func ExtractSQLKeywords(input string) []string {
	keywords := []string{
		"select", "insert", "update", "delete", "drop", "create",
		"alter", "exec", "execute", "union", "where", "from",
		"join", "left", "right", "inner", "outer", "having",
		"group", "order", "by", "into", "load_file", "outfile",
		"benchmark", "sleep", "waitfor", "delay", " pg_sleep",
		"set", "show", "declare", "cast", "convert", "openrowset",
		"opendatasource", "xp_cmdshell", "sp_executesql",
	}
	found := make([]string, 0)
	lowerInput := strings.ToLower(input)
	for _, kw := range keywords {
		if strings.Contains(lowerInput, kw) {
			found = append(found, kw)
		}
	}
	return found
}

// ExtractJSKeywords - 从输入中提取 JavaScript 关键词
// 返回输入中包含的所有 JS 相关关键词列表
func ExtractJSKeywords(input string) []string {
	keywords := []string{
		"javascript:", "onload", "onerror", "onclick", "onmouseover",
		"onfocus", "onblur", "onchange", "onsubmit", "onkeydown",
		"onkeyup", "onkeypress", "eval(", "Function(", "setTimeout",
		"setInterval", "document.cookie", "document.domain",
		"document.write", "innerHTML", "outerHTML", "appendChild",
		"createElement", "import", "require", "window.location",
		"XMLHttpRequest", "fetch", "async", "await", "Promise",
		"<script>", "</script>", "<iframe>", "alert(", "confirm(",
		"prompt(", "console.log", "atob", "btoa",
	}
	found := make([]string, 0)
	lowerInput := strings.ToLower(input)
	for _, kw := range keywords {
		if strings.Contains(lowerInput, kw) {
			found = append(found, kw)
		}
	}
	return found
}

// ExtractCommandKeywords - 从输入中提取命令注入关键词
// 返回输入中包含的所有系统命令关键词列表
func ExtractCommandKeywords(input string) []string {
	keywords := []string{
		";", "|", "&", "&&", "||", "`", "$()", "${}",
		"$(", ">", ">>", "<", "<<", "2>", "2>>",
		"cat", "ls", "dir", "type", "echo", "cd", "pwd",
		"mkdir", "rmdir", "rm", "cp", "mv", "chmod", "chown",
		"wget", "curl", "nc", "netcat", "telnet", "ssh",
		"ping", "ifconfig", "ip", "nslookup", "dig",
		"whoami", "id", "uname", "ps", "kill", "killall",
		"gcc", "g++", "make", "python", "perl", "ruby", "php",
		"bash", "sh", "cmd", "powershell", "reg", "sc",
		"systeminfo", "hostname", "net", "netsh", "route",
		"arp", "tracert", "pathping", "nbtstat",
	}
	found := make([]string, 0)
	lowerInput := strings.ToLower(input)
	for _, kw := range keywords {
		if strings.Contains(lowerInput, kw) {
			found = append(found, kw)
		}
	}
	return found
}
