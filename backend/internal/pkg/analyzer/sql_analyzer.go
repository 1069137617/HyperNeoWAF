package analyzer

import (
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type SQLInjectionAnalyzer struct {
	name         string
	version      string
	analyzerType string
	enabled      bool
	config       map[string]interface{}
	mu           sync.RWMutex
}

func NewSQLInjectionAnalyzer() *SQLInjectionAnalyzer {
	return &SQLInjectionAnalyzer{
		name:         "sql_injection_analyzer",
		version:      "2.0.0",
		analyzerType: "sql_injection",
		enabled:      true,
		config:       make(map[string]interface{}),
	}
}

func (a *SQLInjectionAnalyzer) Name() string {
	return a.name
}

func (a *SQLInjectionAnalyzer) Type() string {
	return a.analyzerType
}

func (a *SQLInjectionAnalyzer) Version() string {
	return a.version
}

func (a *SQLInjectionAnalyzer) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

func (a *SQLInjectionAnalyzer) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

func (a *SQLInjectionAnalyzer) Configure(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = config
	return nil
}

func (a *SQLInjectionAnalyzer) Analyze(input *AnalysisInput) *AnalysisResult {
	start := time.Now()
	result := NewAnalysisResult(a)

	if input == nil || input.Raw == "" {
		return result
	}

	rawData := input.Raw + " " + input.Path + " " + input.QueryString + " " + input.Body
	_ = a.normalizeInput(rawData) // 规范化输入以检测编码攻击

	// 使用全局缓存的正则表达式
	cache := GetGlobalPatternCache()

	// ==================== 第一优先级：Critical 威胁 ====================
	// 检测到立即返回，不继续匹配

	// 存储过程注入 - Critical
	spCriticalPatterns := []string{
		`(?i)\bXP_CMDSHELL\b`,
		`(?i)\bSP_PASSWORD\b`,
		`(?i)\bDECLARE\s+@\w+\s+VARCHAR`,
		`(?i)\bDECLARE\s+##\w+\s+`,
	}

	for _, pattern := range spCriticalPatterns {
		re := cache.GetMust(pattern)
		if re.MatchString(rawData) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelCritical,
				Pattern:        pattern,
				Description:    "存储过程注入 - Critical威胁",
				Recommendation: "立即阻止并通知安全团队",
			})
			result.ProcessingTime = time.Since(start)
			result.ShouldBlock = true
			result.ShouldLog = true
			result.ShouldAllow = false
			return result
		}
	}

	// 时间盲注 - Critical (活跃攻击指标)
	delayCriticalPatterns := []string{
		`(?i)\bSLEEP\s*\(\s*[5-9]\d*\s*\)`,
		`(?i)\bBENCHMARK\s*\(\s*[5-9]\d{2,}`,
		`(?i)\bWAITFOR\s+DELAY\s+'[^']*[5-9]\d+`,
		`(?i)\bPG_SLEEP\s*\(\s*[5-9]\d*\s*\)`,
		`(?i)\bREPEAT\s*\(\s*[^)]+\s*,\s*[5-9]\d{3,}\s*\)`,
	}

	for _, pattern := range delayCriticalPatterns {
		re := cache.GetMust(pattern)
		if re.MatchString(rawData) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelCritical,
				Pattern:        pattern,
				Description:    "高延迟时间盲注 - 活跃攻击",
				Recommendation: "立即阻止请求",
			})
			result.ProcessingTime = time.Since(start)
			result.ShouldBlock = true
			result.ShouldLog = true
			result.ShouldAllow = false
			return result
		}
	}

	// 永真式注入 - Critical
	tautologyCriticalPatterns := []string{
		`(?i)\bOR\s+1\s*=\s*1\b`,
		`(?i)\bOR\s+TRUE\b`,
		`(?i)\bOR\s+'?\s*=\s*'?`,
		`(?i)'+OR+'1'='1`,
		`(?i)"+OR+"1"="1"`,
		`(?i)admin'--`,
		`(?i)admin'#`,
		`(?i)'OR'1'='1'--`,
		`(?i)'OR'1'='1'#`,
		`(?i)'OR'1'='1'/*`,
		`(?i)\bAND\s+0\s*=\s*0\s*OR\s+1\s*=\s*1\b`,
	}

	for _, pattern := range tautologyCriticalPatterns {
		re := cache.GetMust(pattern)
		if re.MatchString(rawData) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelCritical,
				Pattern:        pattern,
				Description:    "SQL永真式攻击 - Critical威胁",
				Recommendation: "拒绝请求并记录安全事件",
			})
			result.ProcessingTime = time.Since(start)
			result.ShouldBlock = true
			result.ShouldLog = true
			result.ShouldAllow = false
			return result
		}
	}

	// 堆叠查询 - Critical
	stackedCriticalPatterns := []string{
		`(?i);\s*DROP\b`,
		`(?i);\s*DELETE\b`,
		`(?i);\s*TRUNCATE\b`,
		`(?i);\s*GRANT\b`,
		`(?i);\s*REVOKE\b`,
		`(?i);\s*DENY\b`,
		`(?i);\s*EXEC\s*xp_cmdshell\b`,
		`(?i);\s*ALTER\s+DATABASE\b`,
		`(?i);\s*CREATE\s+TABLE\b`,
		`(?i);\s*DROP\s+TABLE\b`,
	}

	for _, pattern := range stackedCriticalPatterns {
		re := cache.GetMust(pattern)
		if re.MatchString(rawData) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelCritical,
				Pattern:        pattern,
				Description:    "危险堆叠查询 - 立即阻断",
				Recommendation: "阻止危险SQL操作",
			})
			result.ProcessingTime = time.Since(start)
			result.ShouldBlock = true
			result.ShouldLog = true
			result.ShouldAllow = false
			return result
		}
	}

	// ==================== 第二优先级：High 威胁 ====================

	// UNION SELECT - High
	unionPatterns := []string{
		`(?i)\bUNION\s+(ALL\s+)?SELECT\b`,
		`(?i)\bUNION\s+(ALL\s+)?SELECT\s+\d+(\s*,\s*\d+)*`,
		`(?i)\bUNION\s+(ALL\s+)?SELECT\s+NULL(\s*,\s*NULL)*`,
		`(?i)\bUNION\s+(ALL\s+)?SELECT\s+'[^']*'(\s*,\s*'[^']*')*`,
		`(?i)\bUNION\s+(ALL\s+)?SELECT\s+NULL\s+FROM\b`,
		`(?i)\bUNION\s+(ALL\s+)?SELECT\s+\w+\s+FROM\b`,
		`(?i)\bUNION\s+(ALL\s+)?SELECT\s+\*\s+FROM\b`,
		`(?i)\bUNION\s+(ALL\s+)?SELECT\s+[^,\s]+(\s*,\s*[^,\s]+){1,10}\s+FROM\b`,
		`(?i)\bUNION\s+(ALL\s+)?SELECT\s+INTO\s+(OUT|DUMP)FILE\b`,
		`(?i)\bUNION\s+(ALL\s+)?SELECT\s+\(SELECT\b`,
	}

	for _, pattern := range unionPatterns {
		re := cache.GetMust(pattern)
		if re.MatchString(rawData) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelHigh,
				Pattern:        pattern,
				Description:    "UNION型SQL注入",
				Recommendation: "检查上下文并验证输入参数",
			})
			result.ShouldBlock = true
			result.ShouldLog = true
			result.ShouldAllow = false
		}
	}

	// 存储过程 - High
	spPatterns := []string{
		`(?i)\bXP_DIRTREE\b`,
		`(?i)\bXP_REGREAD\b`,
		`(?i)\bXP_REGWRITE\b`,
		`(?i)\bXP_STARGEGEMOVEDIRS\b`,
		`(?i)\bSP_EXECUTESQL\b`,
		`(?i)\bEXEC\s*\(\s*@`,
		`(?i)\bEXECUTE\s+\(?\s*@`,
		`(?i)\bSP_START_MAILER\b`,
		`(?i)\bXP_SENDMAIL\b`,
		`(?i)\bXP_FIXED_DRIVES\b`,
		`(?i)\bXP_SUB_DIRS\b`,
		`(?i)\bXP_FILEEXIST\b`,
		`(?i)\bDBMS_ASSERT\b`,
		`(?i)\bUTL_FILE\b`,
		`(?i)\bUTL_SMTP\b`,
		`(?i)\bUTL_URL\b`,
	}

	for _, pattern := range spPatterns {
		re := cache.GetMust(pattern)
		if re.MatchString(rawData) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelHigh,
				Pattern:        pattern,
				Description:    "存储过程注入",
				Recommendation: "阻止并通知安全团队",
			})
			result.ShouldBlock = true
			result.ShouldLog = true
			result.ShouldAllow = false
		}
	}

	// ==================== 第三优先级：Medium 威胁 ====================

	// 布尔盲注 - Medium
	booleanPatterns := []string{
		`(?i)\bAND\s+\d+\s*=\s*\d+`,
		`(?i)\bAND\s+'[^']*'\s*=\s*'[^']*'`,
		`(?i)\bAND\s+1\s*=\s*2\b`,
		`(?i)\bIF\s*\(\s*\w+\s*=\s*\w+`,
		`(?i)\bIFNULL\s*\(\s*\w+\s*,\s*\w+\s*\)`,
		`(?i)\bCASE\s+WHEN\s+\w+\s*=\s*\w+\s+THEN\b`,
		`(?i)\bEXISTS\s*\(\s*SELECT\b`,
		`(?i)\bNOT\s+EXISTS\s*\(\s*SELECT\b`,
		`(?i)\bASCII\s*\(\s*SUBSTRING\b`,
	}

	for _, pattern := range booleanPatterns {
		re := cache.GetMust(pattern)
		if re.MatchString(rawData) && (containsSQLKeyword(rawData, "select") || containsSQLKeyword(rawData, "where")) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelMedium,
				Pattern:        pattern,
				Description:    "布尔型盲注",
				Recommendation: "验证输入为数字或正确引用",
			})
			break
		}
	}

	// 注释注入 - Medium
	commentPatterns := []string{
		`(?i)--\s*$`,
		`(?i)#\s*$`,
		`(?i)/\*.*\*/`,
		`(?i)'--`,
		`(?i)'#`,
		`(?i)'/\*`,
		`(?i)"--`,
		`(?i)"#`,
		`(?i)';\s*--`,
		`(?i)';\s*#`,
		`(?i)/\*\s*!\s*\d+`,
		`(?i)/\*\s*-\s*\*/`,
		`(?i)\x00`,
	}

	for _, pattern := range commentPatterns {
		re := cache.GetMust(pattern)
		if re.MatchString(rawData) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelMedium,
				Pattern:        pattern,
				Description:    "SQL注释注入",
				Recommendation: "剥离注释字符并验证输入",
			})
			break
		}
	}

	result.ProcessingTime = time.Since(start)

	if len(result.Matches) > 0 {
		if result.ShouldBlock {
			return result
		}
		result.ShouldBlock = result.ShouldBlockRequest(0.7)
		result.ShouldLog = true
		result.ShouldAllow = !result.ShouldBlock
	}

	return result
}

func (a *SQLInjectionAnalyzer) normalizeInput(data string) string {
	data = strings.ToLower(data)
	data = decodeURLEncoding(data)
	data = decodeHexEncoding(data)
	data = decodeUnicodeEncoding(data)
	data = removeSQLComments(data)
	return data
}

func decodeURLEncoding(data string) string {
	result := data
	for {
		decoded, changed := decodeOnceURL(result)
		if !changed {
			break
		}
		result = decoded
	}
	return result
}

func decodeOnceURL(data string) (string, bool) {
	pattern := regexp.MustCompile(`%([0-9a-fA-F]{2})`)
	matches := pattern.FindAllStringSubmatchIndex(data, -1)
	if len(matches) == 0 {
		return data, false
	}

	var sb strings.Builder
	lastEnd := 0
	changed := false

	for _, match := range matches {
		if match[0] > lastEnd {
			sb.WriteString(data[lastEnd:match[0]])
		}
		hexStr := data[match[2]:match[3]]
		sb.WriteByte(byte(hexToInt(hexStr)))
		lastEnd = match[1]
		changed = true
	}
	sb.WriteString(data[lastEnd:])
	return sb.String(), changed
}

func hexToInt(s string) int {
	var result int
	for _, c := range s {
		result *= 16
		switch {
		case c >= '0' && c <= '9':
			result += int(c - '0')
		case c >= 'a' && c <= 'f':
			result += int(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			result += int(c - 'A' + 10)
		}
	}
	return result
}

func decodeHexEncoding(data string) string {
	pattern := regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	return pattern.ReplaceAllStringFunc(data, func(match string) string {
		hex := match[2:]
		r, _ := utf8.DecodeRune([]byte{byte(hexToInt(hex))})
		return string(r)
	})
}

func decodeUnicodeEncoding(data string) string {
	pattern := regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
	return pattern.ReplaceAllStringFunc(data, func(match string) string {
		hex := match[2:]
		r, _ := utf8.DecodeRune([]byte{
			byte(hexToInt(hex[:2])),
			byte(hexToInt(hex[2:])),
		})
		return string(r)
	})
}

func removeSQLComments(data string) string {
	data = regexp.MustCompile(`--.*$).*`).ReplaceAllString(data, "")
	data = regexp.MustCompile(`#.*$).*`).ReplaceAllString(data, "")
	data = regexp.MustCompile(`/\*.*?\*/`).ReplaceAllString(data, " ")
	return data
}

func containsSQLKeyword(data, keyword string) bool {
	pattern := regexp.MustCompile(`(?i)\b` + keyword + `\b`)
	return pattern.MatchString(data)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
