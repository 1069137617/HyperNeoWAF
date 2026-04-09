package analyzer

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

type JSONPAnalyzer struct {
	name         string
	version      string
	analyzerType string
	enabled      bool
	config       map[string]interface{}
	mu           sync.RWMutex
}

func NewJSONPAnalyzer() *JSONPAnalyzer {
	return &JSONPAnalyzer{
		name:         "jsonp_analyzer",
		version:      "1.0.0",
		analyzerType: "jsonp",
		enabled:      true,
		config:       make(map[string]interface{}),
	}
}

func (a *JSONPAnalyzer) Name() string {
	return a.name
}

func (a *JSONPAnalyzer) Type() string {
	return a.analyzerType
}

func (a *JSONPAnalyzer) Version() string {
	return a.version
}

func (a *JSONPAnalyzer) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

func (a *JSONPAnalyzer) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

func (a *JSONPAnalyzer) Configure(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = config
	return nil
}

func (a *JSONPAnalyzer) Analyze(input *AnalysisInput) *AnalysisResult {
	start := time.Now()
	result := NewAnalysisResult(a)

	if input == nil {
		return result
	}

	a.analyzeJSONPContext(input, result)
	a.analyzeJSONPCallback(input, result)
	a.analyzeAjaxContext(input, result)
	a.analyzeJSONPHijacking(input, result)

	result.ProcessingTime = time.Since(start)
	result.ShouldBlock = result.ShouldBlockRequest(0.6)
	if len(result.Matches) > 0 {
		result.ShouldLog = true
		result.ShouldAllow = !result.ShouldBlock
	}

	return result
}

func (a *JSONPAnalyzer) analyzeJSONPContext(input *AnalysisInput, result *AnalysisResult) {
	if input.ContentType != "" {
		contentType := strings.ToLower(input.ContentType)
		if strings.Contains(contentType, "application/javascript") ||
			strings.Contains(contentType, "text/javascript") ||
			strings.Contains(contentType, "application/json") {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelLow,
				Pattern:        "Content-Type",
				Description:    "JavaScript/JSON Content-Type",
				Recommendation: "检测JSONP上下文",
			})
		}
	}

	if input.QueryString != "" {
		a.analyzeJSONPInQueryString(input.QueryString, result)
	}

	if input.Path != "" {
		a.analyzeJSONPInPath(input.Path, result)
	}

	if input.Headers != nil {
		a.analyzeJSONPHeaders(input.Headers, result)
	}

	if input.Body != "" {
		a.analyzeJSONPInBody(input.Body, result)
	}
}

func (a *JSONPAnalyzer) analyzeJSONPInQueryString(query string, result *AnalysisResult) {
	jsonpParams := []string{
		"callback", "jsonp", "jsonpcallback", "jsoncallback",
		"cb", "jsoncb", "jsonpcb", "jcallback", "jcb",
		"func", "function", "json", "jsonp_response",
		"_callback", "_jsonp", "_cb", "_func",
	}

	queryLower := strings.ToLower(query)
	for _, param := range jsonpParams {
		pattern := `(?i)(?:` + param + `)=([^&\s]+)`
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(query, -1)

		for _, match := range matches {
			if len(match) > 1 {
				callbackValue := match[1]
				a.analyzeJSONPCallbackValue(param, callbackValue, result)
			}
		}
	}
}

func (a *JSONPAnalyzer) analyzeJSONPInPath(path string, result *AnalysisResult) {
	pathLower := strings.ToLower(path)

	jsonpPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`/callback\.`, "JSONP路径模式", ThreatLevelMedium},
		{`/jsonp\.`, "JSONP路径模式", ThreatLevelMedium},
		{`/api\.`, "API路径", ThreatLevelLow},
		{`/rest\.`, "REST路径", ThreatLevelLow},
		{`/graphql\.`, "GraphQL路径", ThreatLevelMedium},
		{`\.jsonp`, "JSONP文件扩展名", ThreatLevelMedium},
		{`\.json`, "JSON文件扩展名", ThreatLevelLow},
	}

	for _, p := range jsonpPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(pathLower) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "JSONP路径检测: " + p.description,
				Recommendation: "验证JSONP端点安全性",
			})
		}
	}
}

func (a *JSONPAnalyzer) analyzeJSONPHeaders(headers map[string]string, result *AnalysisResult) {
	acceptHeader := strings.ToLower(headers["Accept"])
	if strings.Contains(acceptHeader, "application/javascript") ||
		strings.Contains(acceptHeader, "text/javascript") {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelLow,
			Pattern:        "Accept",
			Description:    "AJAX Accept头请求JavaScript",
			Recommendation: "监控AJAX请求",
		})
	}

	xRequestedWith := headers["X-Requested-With"]
	if xRequestedWith != "" {
		xRequestedWithLower := strings.ToLower(xRequestedWith)
		if strings.Contains(xRequestedWithLower, "xmlhttprequest") ||
			strings.Contains(xRequestedWithLower, "fetch") {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelLow,
				Pattern:        "X-Requested-With",
				Description:    "AJAX XMLHttpRequest标识",
				Recommendation: "正常AJAX请求",
			})
		}
	}

	origin := headers["Origin"]
	if origin != "" {
		a.analyzeJSONPOrigin(origin, result)
	}

	referer := headers["Referer"]
	if referer != "" {
		a.analyzeJSONPReferer(referer, result)
	}
}

func (a *JSONPAnalyzer) analyzeJSONPOrigin(origin string, result *AnalysisResult) {
	originLower := strings.ToLower(origin)

	if originLower == "null" || originLower == "" {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelMedium,
			Pattern:        "Origin",
			Description:    "空或null Origin值",
			Recommendation: "验证Origin来源",
		})
	}

	suspiciousOrigins := []string{
		"file://", "data://", "javascript://",
	}

	for _, so := range suspiciousOrigins {
		if strings.HasPrefix(originLower, so) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelHigh,
				Pattern:        "Origin",
				Description:    "可疑Origin协议: " + so,
				Recommendation: "阻止异常Origin",
			})
		}
	}
}

func (a *JSONPAnalyzer) analyzeJSONPReferer(referer string, result *AnalysisResult) {
	refererLower := strings.ToLower(referer)

	suspiciousReferers := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`file://`, "本地文件引用", ThreatLevelHigh},
		{`data:text/html`, "Data URL HTML", ThreatLevelCritical},
		{`javascript:`, "JavaScript协议", ThreatLevelCritical},
	}

	for _, sr := range suspiciousReferers {
		if strings.Contains(refererLower, sr.pattern) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    sr.threatLevel,
				Pattern:        "Referer",
				Description:    "可疑Referer: " + sr.description,
				Recommendation: "验证Referer来源",
			})
		}
	}
}

func (a *JSONPAnalyzer) analyzeJSONPInBody(body string, result *AnalysisResult) {
	if strings.HasPrefix(body, "(") && strings.HasSuffix(body, ")") {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelMedium,
			Pattern:        "jsonp-wrapper",
			Description:    "JSONP包装函数模式",
			Recommendation: "验证JSONP响应安全性",
		})
	}

	jsonpBodyPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`^[a-zA-Z_]\w*\s*=`, "JSONP变量赋值模式", ThreatLevelMedium},
		{`typeof\s+`, "Typeof检测", ThreatLevelLow},
		{`\.call\s*\(`, "函数call调用", ThreatLevelMedium},
		{`\.apply\s*\(`, "函数apply调用", ThreatLevelMedium},
	}

	for _, p := range jsonpBodyPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(body) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "JSONP body模式: " + p.description,
				Recommendation: "验证JSONP响应内容",
			})
		}
	}
}

func (a *JSONPAnalyzer) analyzeJSONPCallback(input *AnalysisInput, result *AnalysisResult) {
	callbackPatterns := []string{
		`(?i)callback\s*=`,
		`(?i)jsonp\s*=`,
		`(?i)jsonpcallback\s*=`,
		`(?i)jsoncallback\s*=`,
		`(?i)cb\s*=`,
	}

	data := input.QueryString + " " + input.Body

	for _, pattern := range callbackPatterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelMedium,
				Pattern:        "callback-param",
				Description:    "JSONP回调参数检测",
				Recommendation: "验证回调函数名安全性",
			})
			break
		}
	}

	a.analyzeCallbackInjection(data, result)
	a.analyzeCallbackDOMXSS(data, result)
}

func (a *JSONPAnalyzer) analyzeJSONPCallbackValue(param string, value string, result *AnalysisResult) {
	result.AddMatch(Match{
		Type:           MatchTypeSemantic,
		ThreatLevel:    ThreatLevelLow,
		Pattern:        param + "=" + value,
		Description:    "JSONP回调检测: " + param + "=" + value,
		Recommendation: "验证JSONP回调函数",
	})

	a.analyzeCallbackValueSafety(value, result)
}

func (a *JSONPAnalyzer) analyzeCallbackValueSafety(value string, result *AnalysisResult) {
	if len(value) > 100 {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelMedium,
			Pattern:        "long-callback",
			Description:    "过长的回调函数名",
			Recommendation: "限制回调函数名长度",
		})
	}

	suspiciousChars := []string{
		"<", ">", "'", "\"", "(", ")", ";", "&", "|",
		"=", "[", "]", "{", "}", "`", "$", "\\",
	}

	for _, char := range suspiciousChars {
		if strings.Contains(value, char) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelHigh,
				Pattern:        "suspicious-char",
				Description:    "回调函数包含可疑字符: " + char,
				Recommendation: "使用白名单限制回调函数名",
			})
		}
	}

	callbackBlacklist := []string{
		"alert(", "eval(", "Function(", "setTimeout", "setInterval",
		"document.cookie", "document.write", "innerHTML", "onerror",
		"onload", "onclick", "javascript:", "data:", "vbscript:",
	}

	valueLower := strings.ToLower(value)
	for _, bl := range callbackBlacklist {
		if strings.Contains(valueLower, strings.ToLower(bl)) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelCritical,
				Pattern:        "callback-blacklist",
				Description:    "回调函数命中黑名单: " + bl,
				Recommendation: "立即阻止可疑回调",
			})
		}
	}
}

func (a *JSONPAnalyzer) analyzeCallbackInjection(data string, result *AnalysisResult) {
	injectionPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)callback\s*=\s*[^&\s]*[;<]`, "回调函数注入分号", ThreatLevelHigh},
		{`(?i)callback\s*=\s*[^&\s]*['\"]`, "回调函数注入引号", ThreatLevelHigh},
		{`(?i)callback\s*=\s*[^&\s]*\bor\b`, "回调函数OR注入", ThreatLevelHigh},
		{`(?i)callback\s*=\s*[^&\s]*\band\b`, "回调函数AND注入", ThreatLevelHigh},
		{`(?i)callback\s*=\s*[^&\s]*\bunion\b`, "回调函数UNION注入", ThreatLevelCritical},
		{`(?i)callback\s*=\s*[^&\s]*\bselect\b`, "回调函数SELECT注入", ThreatLevelHigh},
	}

	for _, p := range injectionPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "JSONP回调注入: " + p.description,
				Recommendation: "使用白名单验证回调函数",
			})
		}
	}
}

func (a *JSONPAnalyzer) analyzeCallbackDOMXSS(data string, result *AnalysisResult) {
	domxssPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)callback\s*=\s*[^&\s]*<script`, "回调函数Script注入", ThreatLevelCritical},
		{`(?i)callback\s*=\s*[^&\s]*javascript:`, "回调函数JavaScript协议", ThreatLevelCritical},
		{`(?i)callback\s*=\s*[^&\s]*on\w+\s*=`, "回调函数事件处理器", ThreatLevelCritical},
		{`(?i)callback\s*=\s*[^&\s]*<img`, "回调函数IMG标签", ThreatLevelHigh},
		{`(?i)callback\s*=\s*[^&\s]*<iframe`, "回调函数IFrame", ThreatLevelHigh},
		{`(?i)callback\s*=\s*[^&\s]*<svg`, "回调函数SVG", ThreatLevelHigh},
		{`(?i)callback\s*=\s*[^&\s]*\x3c`, "URL编码<", ThreatLevelHigh},
		{`(?i)callback\s*=\s*[^&\s]*\x3e`, "URL编码>", ThreatLevelHigh},
		{`(?i)callback\s*=\s*[^&\s]*&#\d+;`, "HTML实体编码", ThreatLevelHigh},
	}

	for _, p := range domxssPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "JSONP DOM XSS: " + p.description,
				Recommendation: "正确编码回调输出",
			})
		}
	}
}

func (a *JSONPAnalyzer) analyzeAjaxContext(input *AnalysisInput, result *AnalysisResult) {
	if input.Headers == nil {
		return
	}

	ajaxIndicators := 0

	xRequestedWith := strings.ToLower(input.Headers["X-Requested-With"])
	if xRequestedWith == "xmlhttprequest" || xRequestedWith == "fetch" {
		ajaxIndicators++
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelLow,
			Pattern:        "X-Requested-With",
			Description:    "XMLHttpRequest AJAX标识",
			Recommendation: "正常AJAX请求",
		})
	}

	acceptHeader := strings.ToLower(input.Headers["Accept"])
	if strings.Contains(acceptHeader, "application/json") ||
		strings.Contains(acceptHeader, "application/javascript") {
		ajaxIndicators++
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelLow,
			Pattern:        "Accept",
			Description:    "AJAX Accept头",
			Recommendation: "正常AJAX请求",
		})
	}

	origin := input.Headers["Origin"]
	if origin != "" {
		ajaxIndicators++
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelLow,
			Pattern:        "Origin",
			Description:    "AJAX Origin头",
			Recommendation: "跨域请求检查",
		})
	}

	if ajaxIndicators >= 2 {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelLow,
			Pattern:        "ajax-context",
			Description:    "检测到AJAX请求上下文",
			Recommendation: "监控AJAX请求安全",
		})
	}

	a.analyzeAjaxSensitiveData(input, result)
	a.analyzeAjaxCSRF(input, result)
}

func (a *JSONPAnalyzer) analyzeAjaxSensitiveData(input *AnalysisInput, result *AnalysisResult) {
	sensitiveParams := []string{
		"token", "session", "sessionid", "auth", "password",
		"secret", "key", "api_key", "apikey", "private",
		"credit_card", "cc", "ssn", "social_security",
	}

	queryLower := strings.ToLower(input.QueryString)
	bodyLower := strings.ToLower(input.Body)

	for _, param := range sensitiveParams {
		if strings.Contains(queryLower, param) || strings.Contains(bodyLower, param) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelHigh,
				Pattern:        param,
				Description:    "AJAX请求包含敏感参数: " + param,
				Recommendation: "确保AJAX传输敏感数据加密",
			})
		}
	}
}

func (a *JSONPAnalyzer) analyzeAjaxCSRF(input *AnalysisInput, result *AnalysisResult) {
	if input.QueryString == "" && input.Body == "" {
		return
	}

	data := input.QueryString + " " + input.Body

 csrfPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)csrf`, "CSRF令牌参数", ThreatLevelMedium},
		{`(?i)_token`, "Laravel CSRF", ThreatLevelMedium},
		{`(?i)xsrf`, "XSRF令牌", ThreatLevelMedium},
		{`(?i)__RequestVerificationToken`, "ASP.NET CSRF", ThreatLevelMedium},
	}

	for _, p := range csrfPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "CSRF保护参数: " + p.description,
				Recommendation: "验证CSRF令牌",
			})
		}
	}
}

func (a *JSONPAnalyzer) analyzeJSONPHijacking(input *AnalysisInput, result *AnalysisResult) {
	data := input.Raw + " " + input.QueryString + " " + input.Body

	hijackingPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)jsonp\s*=\s*[^&\s]*[^a-zA-Z]alert\(`, "JSONP劫持alert测试", ThreatLevelHigh},
		{`(?i)jsonp\s*=\s*[^&\s]*[^a-zA-Z]confirm\(`, "JSONP劫持confirm测试", ThreatLevelHigh},
		{`(?i)jsonp\s*=\s*[^&\s]*[^a-zA-Z]prompt\(`, "JSONP劫持prompt测试", ThreatLevelHigh},
		{`(?i)callback\s*=\s*[^&\s]*<script`, "JSONP script注入", ThreatLevelCritical},
		{`(?i)callback\s*=\s*[^&\s]*onerror`, "JSONP onerror事件", ThreatLevelHigh},
		{`(?i)callback\s*=\s*[^&\s]*onload`, "JSONP onload事件", ThreatLevelHigh},
		{`(?i)callback\s*=\s*[^&\s]*javascript:`, "JSONP javascript协议", ThreatLevelCritical},
		{`(?i)callback\s*=\s*[^&\s]*data:`, "JSONP data协议", ThreatLevelHigh},
		{`(?i)jsonp_callback\s*=\s*[^&\s]*eval`, "JSONP eval执行", ThreatLevelCritical},
	}

	for _, p := range hijackingPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "JSONP劫持攻击: " + p.description,
				Recommendation: "使用CSRF token保护JSONP",
			})
		}
	}

	a.analyzeJSONPHijackingVectors(input, result)
}

func (a *JSONPAnalyzer) analyzeJSONPHijackingVectors(input *AnalysisInput, result *AnalysisResult) {
	hijackingVectors := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)callback\s*=\s*[^&\s]*\bvoid\b`, "void注入", ThreatLevelHigh},
		{`(?i)callback\s*=\s*[^&\s]*\beval\b`, "eval注入", ThreatLevelCritical},
		{`(?i)callback\s*=\s*[^&\s]*\bFunction\b`, "Function构造", ThreatLevelCritical},
		{`(?i)callback\s*=\s*[^&\s]*\bsetTimeout\b`, "setTimeout注入", ThreatLevelHigh},
		{`(?i)callback\s*=\s*[^&\s]*\bsetInterval\b`, "setInterval注入", ThreatLevelHigh},
		{`(?i)callback\s*=\s*[^&\s]*\bsetAttribute\b`, "setAttribute注入", ThreatLevelHigh},
		{`(?i)callback\s*=\s*[^&\s]*\.src\s*=`, "Script src注入", ThreatLevelCritical},
		{`(?i)callback\s*=\s*[^&\s]*\.href\s*=`, "Href注入", ThreatLevelHigh},
		{`(?i)callback\s*=\s*[^&\s]*location\.href`, "location.href注入", ThreatLevelCritical},
		{`(?i)callback\s*=\s*[^&\s]*document\.location`, "document.location注入", ThreatLevelCritical},
	}

	for _, p := range hijackingVectors {
		pattern := `(?i)` + p.pattern
		re := regexp.MustCompile(pattern)

		queryMatch := re.FindStringSubmatch(input.QueryString)
		if len(queryMatch) > 0 {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "JSONP劫持向量: " + p.description,
				Recommendation: "严格验证回调函数名",
			})
		}
	}
}
