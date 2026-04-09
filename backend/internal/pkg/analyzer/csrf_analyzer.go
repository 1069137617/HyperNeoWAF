package analyzer

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

type CSRFAnalyzer struct {
	name         string
	version      string
	analyzerType string
	enabled      bool
	config       map[string]interface{}
	tokenNames   []string
	tokenSeen    bool
	mu           sync.RWMutex
}

func NewCSRFAnalyzer() *CSRFAnalyzer {
	return &CSRFAnalyzer{
		name:         "csrf_analyzer",
		version:      "1.0.0",
		analyzerType: "csrf",
		enabled:      true,
		config:       make(map[string]interface{}),
		tokenNames:   []string{"csrf_token", "csrf", "_token", "token", "xsrf_token", "xsrf", "_csrf", "anticsrf", "requesttoken"},
	}
}

func (a *CSRFAnalyzer) Name() string {
	return a.name
}

func (a *CSRFAnalyzer) Type() string {
	return a.analyzerType
}

func (a *CSRFAnalyzer) Version() string {
	return a.version
}

func (a *CSRFAnalyzer) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

func (a *CSRFAnalyzer) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

func (a *CSRFAnalyzer) Configure(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if names, ok := config["token_names"].([]string); ok {
		a.tokenNames = names
	}
	a.config = config
	return nil
}

func (a *CSRFAnalyzer) Analyze(input *AnalysisInput) *AnalysisResult {
	start := time.Now()
	result := NewAnalysisResult(a)

	if input == nil || input.Raw == "" {
		return result
	}

	if input.Method == "" {
		input.Method = "GET"
	}

	a.analyzeStateChangingRequest(input, result)
	a.analyzeMissingCSRFToken(input, result)
	a.analyzeSameSiteCookie(input, result)
	a.analyzeTokenValidation(input, result)
	a.analyzeOriginHeader(input, result)
	a.analyzeRefererHeader(input, result)
	a.analyzeCSRFExploitPatterns(input, result)

	result.ProcessingTime = time.Since(start)
	result.ShouldBlock = result.ShouldBlockRequest(0.5)
	if len(result.Matches) > 0 {
		result.ShouldLog = true
		result.ShouldAllow = !result.ShouldBlock
	}

	return result
}

func (a *CSRFAnalyzer) analyzeStateChangingRequest(input *AnalysisInput, result *AnalysisResult) {
	stateChangingMethods := map[string]bool{
		"POST":   true,
		"PUT":    true,
		"DELETE": true,
		"PATCH":  true,
	}

	method := strings.ToUpper(input.Method)
	if !stateChangingMethods[method] {
		return
	}

	dataToCheck := input.Raw + " " + input.Body + " " + input.QueryString

	csrfSafePatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)Content-Type:\s*application/json`, "JSON Content-Type (通常安全)", ThreatLevelLow},
		{`(?i)Content-Type:\s*application/xml`, "XML Content-Type", ThreatLevelMedium},
		{`(?i)Content-Type:\s*text/xml`, "Text XML Content-Type", ThreatLevelMedium},
		{`(?i)X-Requested-With:\s*XMLHttpRequest`, "AJAX请求 (通常有CSRF保护)", ThreatLevelLow},
		{`(?i)Accept:\s*application/json`, "JSON Accept头", ThreatLevelLow},
	}

	hasCSRFProtection := false
	for _, p := range csrfSafePatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(dataToCheck) {
			hasCSRFProtection = true
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "CSRF安全标记 - " + p.description,
				Recommendation: "继续保持CSRF防护机制",
			})
		}
	}

	if !hasCSRFProtection && input.ContentType != "" && !strings.Contains(input.ContentType, "application/json") {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelMedium,
			Pattern:        "state_changing_request",
			Description:    "状态改变请求缺少明显CSRF保护",
			Recommendation: "实现CSRF令牌机制",
		})
	}
}

func (a *CSRFAnalyzer) analyzeMissingCSRFToken(input *AnalysisInput, result *AnalysisResult) {
	stateChangingMethods := map[string]bool{
		"POST":   true,
		"PUT":    true,
		"DELETE": true,
		"PATCH":  true,
	}

	method := strings.ToUpper(input.Method)
	if !stateChangingMethods[method] {
		return
	}

	dataToCheck := input.Raw + " " + input.Body + " " + input.QueryString
	tokenFound := false

	for _, tokenName := range a.tokenNames {
		patterns := []string{
			`(?i)` + tokenName + `=[^&\s]+`,
			`(?i)` + tokenName + `\s*:\s*[^&\s]+`,
			`(?i)_token\s*=\s*[^&\s]+`,
			`(?i)csrfmiddlewaretoken\s*=\s*[^&\s]+`,
		}

		for _, pattern := range patterns {
			re := regexp.MustCompile(pattern)
			if re.MatchString(dataToCheck) {
				tokenFound = true
				break
			}
		}
		if tokenFound {
			break
		}
	}

	if !tokenFound {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelHigh,
			Pattern:        "missing_csrf_token",
			Description:    "状态改变请求缺少CSRF令牌",
			Recommendation: "在表单和请求中添加CSRF令牌",
		})
	}
}

func (a *CSRFAnalyzer) analyzeSameSiteCookie(input *AnalysisInput, result *AnalysisResult) {
	if input.Headers == nil {
		return
	}

	setCookieHeader := ""
	for k, v := range input.Headers {
		if strings.ToLower(k) == "set-cookie" || strings.ToLower(k) == "set-cookie:" {
			setCookieHeader = v
			break
		}
	}

	if setCookieHeader == "" {
		return
	}

	samesitePatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)SameSite\s*=\s*Strict`, "SameSite=Strict Cookie (最佳防护)", ThreatLevelLow},
		{`(?i)SameSite\s*=\s*Lax`, "SameSite=Lax Cookie (中等防护)", ThreatLevelMedium},
		{`(?i)SameSite\s*=\s*None`, "SameSite=None Cookie (无防护-需Secure)", ThreatLevelHigh},
		{`(?i)SameSite\s*=\s*`, "SameSite属性存在但值未知", ThreatLevelMedium},
		{`(?i)Secure`, "Secure属性存在", ThreatLevelLow},
		{`(?i)HttpOnly`, "HttpOnly属性存在", ThreatLevelLow},
	}

	hasSameSite := false
	for _, p := range samesitePatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(setCookieHeader) {
			hasSameSite = true
			if p.threatLevel >= ThreatLevelMedium {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    p.threatLevel,
					Pattern:        p.pattern,
					Description:    "Cookie安全属性 - " + p.description,
					Recommendation: p.description,
				})
			}
		}
	}

	if !hasSameSite {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelMedium,
			Pattern:        "missing_samesite",
			Description:    "Cookie缺少SameSite属性",
			Recommendation: "添加SameSite=Strict或SameSite=Lax属性",
		})
	}
}

func (a *CSRFAnalyzer) analyzeTokenValidation(input *AnalysisInput, result *AnalysisResult) {
	dataToCheck := input.Raw + " " + input.Body + " " + input.QueryString

	invalidTokenPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)csrf_token\s*=\s*test`, "测试CSRF令牌", ThreatLevelMedium},
		{`(?i)csrf_token\s*=\s*dummy`, "虚拟CSRF令牌", ThreatLevelMedium},
		{`(?i)csrf_token\s*=\s*fake`, "伪造CSRF令牌", ThreatLevelMedium},
		{`(?i)csrf_token\s*=\s*空白`, "空白CSRF令牌", ThreatLevelMedium},
		{`(?i)csrf_token\s*=\s*$^`, "无效CSRF令牌格式", ThreatLevelMedium},
		{`(?i)_token\s*=\s*0000`, "简单数字令牌", ThreatLevelMedium},
		{`(?i)_token\s*=\s*1234`, "简单数字令牌", ThreatLevelMedium},
		{`(?i)_token\s*=\s*aaaa`, "简单字母令牌", ThreatLevelMedium},
		{`(?i)_token\s*=\s*null`, "Null令牌", ThreatLevelHigh},
		{`(?i)_token\s*=\s*undefined`, "Undefined令牌", ThreatLevelMedium},
		{`(?i)_token\s*=\s*none`, "None令牌", ThreatLevelMedium},
		{`(?i)_token\s*=\s*0`, "零值令牌", ThreatLevelMedium},
	}

	for _, p := range invalidTokenPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(dataToCheck) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "无效CSRF令牌 - " + p.description,
				Recommendation: "使用有效的随机CSRF令牌",
			})
		}
	}

	tokenReusePatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)csrf_token\s*=\s*[a-f0-9]{32}\s*.*csrf_token\s*=\s*[a-f0-9]{32}`, "令牌重复使用", ThreatLevelMedium},
	}

	for _, p := range tokenReusePatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(dataToCheck) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "CSRF威胁 - " + p.description,
				Recommendation: "确保令牌一次性使用",
			})
		}
	}
}

func (a *CSRFAnalyzer) analyzeOriginHeader(input *AnalysisInput, result *AnalysisResult) {
	if input.Headers == nil {
		return
	}

	origin := ""
	for k, v := range input.Headers {
		if strings.ToLower(k) == "origin" {
			origin = v
			break
		}
	}

	if origin == "" {
		return
	}

	originPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`^https?://[^/]+\.evil\.com`, "恶意Origin - 子域名攻击", ThreatLevelCritical},
		{`^https?://evil\.com`, "恶意Origin - 域名攻击", ThreatLevelCritical},
		{`^https?://[^/]+\.attacker\.`, "攻击者域名", ThreatLevelCritical},
		{`^null$`, "Null Origin (可能的数据窃取)", ThreatLevelHigh},
		{`^https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+`, "IP地址Origin", ThreatLevelMedium},
	}

	for _, p := range originPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(origin) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "可疑Origin头 - " + p.description,
				Recommendation: "验证Origin与预期域名匹配",
			})
		}
	}

	host := strings.ToLower(input.Host)
	if origin != "" && !strings.Contains(strings.ToLower(origin), host) {
		parsedOrigin, err := regexp.MustCompile(`^https?://[^/]+`).FindString(strings.ToLower(origin))
		if err == nil && parsedOrigin != "" {
			expectedOrigin := "https://" + host
			if !strings.Contains(origin, host) && !strings.HasSuffix(host, strings.ReplaceAll(parsedOrigin, "https://", "")) {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    ThreatLevelHigh,
					Pattern:        "origin_mismatch",
					Description:    "Origin与Host不匹配",
					Evidence:       "Origin: " + origin + ", Host: " + host,
					Recommendation: "验证请求Origin与服务器域名匹配",
				})
			}
		}
	}
}

func (a *CSRFAnalyzer) analyzeRefererHeader(input *AnalysisInput, result *AnalysisResult) {
	if input.Headers == nil {
		return
	}

	referer := ""
	for k, v := range input.Headers {
		if strings.ToLower(k) == "referer" {
			referer = v
			break
		}
	}

	if referer == "" {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelLow,
			Pattern:        "missing_referer",
			Description:    "缺少Referer头 (可能是CSRF攻击)",
			Recommendation: "验证Referer头或使用CSRF令牌",
		})
		return
	}

	refererPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)evil\.com`, "恶意Referer域名", ThreatLevelCritical},
		{`(?i)attacker\.`, "攻击者域名", ThreatLevelCritical},
		{`(?i)hacker\.`, "黑客域名", ThreatLevelCritical},
		{`^https?://[^/]+\.evil\.com`, "恶意子域名Referer", ThreatLevelCritical},
		{`^https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+`, "IP Referer", ThreatLevelMedium},
		{`^data:`, "Data URL Referer", ThreatLevelHigh},
		{`^javascript:`, "JavaScript伪协议Referer", ThreatLevelHigh},
	}

	for _, p := range refererPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(referer) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "可疑Referer - " + p.description,
				Recommendation: "验证Referer与预期域名匹配",
			})
		}
	}
}

func (a *CSRFAnalyzer) analyzeCSRFExploitPatterns(input *AnalysisInput, result *AnalysisResult) {
	dataToCheck := input.Raw + " " + input.Body + " " + input.QueryString

	csrfExploitPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)<form[^>]*action\s*=\s*["']https?://`, "跨站表单提交", ThreatLevelHigh},
		{`(?i)<form[^>]*method\s*=\s*["']?post["']?[^>]*>`, "POST表单无令牌", ThreatLevelHigh},
		{`(?i)<img[^>]*src\s*=\s*["']https?://[^"']*(\?|&)`, "IMG标签CSRF (GET)", ThreatLevelMedium},
		{`(?i)<script[^>]*src\s*=\s*["']https?://`, "Script标签跨域", ThreatLevelMedium},
		{`(?i)<link[^>]*href\s*=\s*["']https?://`, "Link标签跨域", ThreatLevelLow},
		{`(?i)<iframe[^>]*src\s*=\s*["']https?://`, "Iframe跨域", ThreatLevelMedium},
		{`(?i)fetch\s*\(\s*["']https?://`, "Fetch API跨域", ThreatLevelMedium},
		{`(?i)XMLHttpRequest.*open.*POST`, "XHR POST跨域", ThreatLevelMedium},
		{`(?i)\.submit\s*\(\s*\)`, "JavaScript表单提交", ThreatLevelMedium},
		{`(?i)document\.forms\[`, "DOM表单操作", ThreatLevelLow},
		{`(?i)<svg[^>]*onload\s*=`, "SVG onload事件", ThreatLevelHigh},
		{`(?i)src\s*=\s*["']?https?://.*&.*=`, "URL参数构造", ThreatLevelMedium},
		{`(?i)method\s*=\s*["']?post["']?.*action\s*=\s*["']?https?://(?!`+ strings.ReplaceAll(input.Host, ".", `\.`) + `)`, "外部POST表单", ThreatLevelCritical},
	}

	for _, p := range csrfExploitPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(dataToCheck) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "CSRF利用模式 - " + p.description,
				Recommendation: "添加CSRF令牌和验证来源",
			})
		}
	}
}

func (a *CSRFAnalyzer) extractTokenFromCookie(cookies string, tokenName string) string {
	patterns := []string{
		tokenName + `=([^;]+)`,
		`(?i)` + tokenName + `\s*=\s*([^;]+)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(cookies)
		if len(matches) > 1 {
			return matches[1]
		}
	}
	return ""
}

func (a *CSRFAnalyzer) extractTokenFromHeader(headers map[string]string, tokenName string) string {
	for k, v := range headers {
		if strings.Contains(strings.ToLower(k), strings.ToLower(tokenName)) {
			return v
		}
	}
	return ""
}
