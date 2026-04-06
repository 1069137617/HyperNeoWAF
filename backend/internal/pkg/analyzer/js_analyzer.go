package analyzer

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

type JSAnalyzer struct {
	name         string
	version      string
	analyzerType string
	enabled      bool
	config       map[string]interface{}
	patterns     map[string]*regexp.Regexp
	mu           sync.RWMutex
}

func NewJSAnalyzer() *JSAnalyzer {
	return &JSAnalyzer{
		name:         "js_analyzer",
		version:      "2.0.0",
		analyzerType: "js_injection",
		enabled:      true,
		config:       make(map[string]interface{}),
		patterns:     make(map[string]*regexp.Regexp),
	}
}

func (a *JSAnalyzer) Name() string {
	return a.name
}

func (a *JSAnalyzer) Type() string {
	return a.analyzerType
}

func (a *JSAnalyzer) Version() string {
	return a.version
}

func (a *JSAnalyzer) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

func (a *JSAnalyzer) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

func (a *JSAnalyzer) Configure(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = config
	return nil
}

func (a *JSAnalyzer) Analyze(input *AnalysisInput) *AnalysisResult {
	start := time.Now()
	result := NewAnalysisResult(a)

	if input == nil || input.Raw == "" {
		return result
	}

	dataToAnalyze := a.prepareData(input)
	normalized := a.normalizeInput(dataToAnalyze)

	a.analyzeCodeExecution(dataToAnalyze, result)
	a.analyzePrototypePollution(dataToAnalyze, result)
	a.analyzeEvalPatterns(dataToAnalyze, result)
	a.analyzeSensitiveDataExposure(dataToAnalyze, result)
	a.analyzeServerSideRequest(dataToAnalyze, result)
	a.analyzePathTraversal(dataToAnalyze, result)
	a.analyzeReDoS(dataToAnalyze, result)
	a.analyzeMaliciousPatterns(normalized, result)
	a.analyzeNodejsSpecific(normalized, result)
	a.analyzeClientSideInjection(dataToAnalyze, result)

	result.ProcessingTime = time.Since(start)
	result.ShouldBlock = result.ShouldBlockRequest(0.65)
	if len(result.Matches) > 0 {
		result.ShouldLog = true
		result.ShouldAllow = !result.ShouldBlock
	}

	return result
}

func (a *JSAnalyzer) prepareData(input *AnalysisInput) string {
	var sb strings.Builder
	sb.WriteString(input.Raw)
	sb.WriteString(" ")
	sb.WriteString(input.Path)
	sb.WriteString(" ")
	sb.WriteString(input.QueryString)
	sb.WriteString(" ")
	sb.WriteString(input.Body)
	if input.Headers != nil {
		for k, v := range input.Headers {
			sb.WriteString(" ")
			sb.WriteString(k)
			sb.WriteString(": ")
			sb.WriteString(v)
		}
	}
	return sb.String()
}

func (a *JSAnalyzer) normalizeInput(data string) string {
	data = strings.ToLower(data)
	data = a.decodeURLEncoding(data)
	data = a.decodeHexEncoding(data)
	data = a.decodeUnicodeEncoding(data)
	return data
}

func (a *JSAnalyzer) decodeURLEncoding(data string) string {
	pattern := regexp.MustCompile(`%([0-9a-fA-F]{2})`)
	return pattern.ReplaceAllStringFunc(data, func(match string) string {
		hex := match[1:]
		b := a.hexToByte(hex)
		return string(rune(b))
	})
}

func (a *JSAnalyzer) decodeHexEncoding(data string) string {
	pattern := regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	return pattern.ReplaceAllStringFunc(data, func(match string) string {
		hex := match[2:]
		b := a.hexToByte(hex)
		return string(rune(b))
	})
}

func (a *JSAnalyzer) decodeUnicodeEncoding(data string) string {
	pattern := regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
	return pattern.ReplaceAllStringFunc(data, func(match string) string {
		hex := match[2:]
		b1 := a.hexToByte(hex[:2])
		b2 := a.hexToByte(hex[2:])
		return string(rune(int(b1)<<8 | int(b2)))
	})
}

func (a *JSAnalyzer) hexToByte(s string) byte {
	var result byte
	for _, c := range s {
		result *= 16
		switch {
		case c >= '0' && c <= '9':
			result += byte(c - '0')
		case c >= 'a' && c <= 'f':
			result += byte(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			result += byte(c - 'A' + 10)
		}
	}
	return result
}

func (a *JSAnalyzer) analyzeCodeExecution(data string, result *AnalysisResult) {
	codeExecPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{"(?i)\\beval\\s*\\(\\s*[\\'\\\"]", "eval() - 动态代码执行", ThreatLevelCritical},
		{"(?i)\\bFunction\\s*\\(\\s*[\\'\\\"]", "Function() - 动态函数创建", ThreatLevelCritical},
		{"(?i)\\bsetTimeout\\s*\\(\\s*[\\'\\\"]", "setTimeout() - 延迟执行", ThreatLevelHigh},
		{"(?i)\\bsetInterval\\s*\\(\\s*[\\'\\\"]", "setInterval() - 周期执行", ThreatLevelHigh},
		{"(?i)\\bsetImmediate\\s*\\(\\s*[\\'\\\"]", "setImmediate() - 即时执行", ThreatLevelHigh},
		{"(?i)\\bexecScript\\s*\\(\\s*[\\'\\\"]", "execScript() - IE脚本执行", ThreatLevelCritical},
		{`(?i)\bnew\s+Function\s*\(`, "new Function() - 动态函数", ThreatLevelHigh},
		{`(?i)\batob\s*\(`, "atob() - Base64解码", ThreatLevelHigh},
		{`(?i)\bbtoa\s*\(`, "btoa() - Base64编码", ThreatLevelMedium},
		{`(?i)\bJSON\.parse\s*\(`, "JSON.parse() - JSON解析", ThreatLevelLow},
		{`(?i)\bString\.fromCharCode\s*\(`, "fromCharCode() - 字符转换", ThreatLevelMedium},
		{`(?i)\beval\s*\(\s*atob\s*\(`, "eval(atob()) - 编码载荷执行", ThreatLevelCritical},
		{`(?i)\bprocess\.binding\s*\(`, "process.binding() - Node.js绑定", ThreatLevelCritical},
		{`(?i)\bprocess\.mainModule\.require\s*\(`, "process.mainModule.require() - 模块加载", ThreatLevelCritical},
		{`(?i)\bvm\.runInContext\s*\(`, "vm.runInContext() - 上下文执行", ThreatLevelCritical},
		{`(?i)\bvm\.runInNewContext\s*\(`, "vm.runInNewContext() - 新上下文执行", ThreatLevelCritical},
		{`(?i)\bvm\.runInThisContext\s*\(`, "vm.runInThisContext() - 当前上下文执行", ThreatLevelCritical},
		{`(?i)\bFunction\.prototype\.bind\.call`, "Function.bind.call - 绑定调用", ThreatLevelHigh},
		{`(?i)\bReflect\.get\s*\(`, "Reflect.get() - 反射获取", ThreatLevelHigh},
		{`(?i)\bReflect\.set\s*\(`, "Reflect.set() - 反射设置", ThreatLevelHigh},
		{`(?i)\beval\s*\(.*\$\{`, "eval() with template literal - 模板注入", ThreatLevelCritical},
	}

	for _, p := range codeExecPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "避免动态代码执行;使用安全替代方案",
			})
		}
	}
}

func (a *JSAnalyzer) analyzePrototypePollution(data string, result *AnalysisResult) {
	protoPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\b__proto__`, "__proto__ - 原型链污染向量", ThreatLevelCritical},
		{`(?i)constructor`, "constructor - 构造函数引用", ThreatLevelHigh},
		{`(?i)prototype`, "prototype - 原型引用", ThreatLevelHigh},
		{`(?i)\[\s*["\x27]__proto__["\x27]\s*\]`, " __proto__ 数组访问", ThreatLevelCritical},
		{`(?i)\[\s*["\x27]constructor["\x27]\s*\]`, "constructor 数组访问", ThreatLevelHigh},
		{`(?i)\.__proto__\s*=`, "__proto__ 属性赋值", ThreatLevelCritical},
		{`(?i)\.constructor\.`, "constructor 链式访问", ThreatLevelHigh},
		{`(?i)Object\.assign\s*\(\s*\$`, "Object.assign with variable", ThreatLevelHigh},
		{`(?i)Object\.merge\s*\(\s*\$`, "Object.merge with variable", ThreatLevelHigh},
		{`(?i)Object\.deepMerge\s*\(\s*\$`, "Object.deepMerge with variable", ThreatLevelHigh},
		{`(?i)lodash\.merge\s*\(\s*\$`, "lodash.merge with variable", ThreatLevelHigh},
		{`(?i)lodash\.cloneDeep\s*\(\s*\$`, "lodash.cloneDeep with variable", ThreatLevelHigh},
		{`(?i)\$\.extend\s*\(\s*\$`, "jQuery.extend with variable", ThreatLevelHigh},
		{`(?i)deep-assign\s*\(\s*\$`, "deep-assign with variable", ThreatLevelHigh},
		{`(?i)merge\s*\(\s*\$`, "merge function with variable", ThreatLevelHigh},
		{`(?i)Object\.keys\s*\(\s*\$\{`, "Object.keys with __proto__", ThreatLevelHigh},
		{`(?i)Object\.values\s*\(\s*\$\{`, "Object.values with __proto__", ThreatLevelHigh},
		{`(?i)Object\.entries\s*\(\s*\$\{`, "Object.entries with __proto__", ThreatLevelHigh},
	}

	for _, p := range protoPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "验证对象键;使用安全合并库",
			})
		}
	}
}

func (a *JSAnalyzer) analyzeEvalPatterns(data string, result *AnalysisResult) {
	evalPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{"(?i)\\beval\\s*\\(\\s*[\\'\\\"]", "eval() with dynamic string", ThreatLevelCritical},
		{"(?i)\\bFunction\\s*\\(\\s*[\\'\\\"]", "Function() with string", ThreatLevelCritical},
		{"(?i)\\bsetTimeout\\s*\\(\\s*[\\'\\\"]", "setTimeout(string, ...)", ThreatLevelHigh},
		{"(?i)\\bsetInterval\\s*\\(\\s*[\\'\\\"]", "setInterval(string, ...)", ThreatLevelHigh},
		{"(?i)\\bsetImmediate\\s*\\(\\s*[\\'\\\"]", "setImmediate(string)", ThreatLevelHigh},
		{"(?i)\\bexecScript\\s*\\(\\s*[\\'\\\"]", "execScript()", ThreatLevelCritical},
		{`(?i)\bnew\s+Function\s*\([^)]*\)`, "new Function()", ThreatLevelCritical},
		{"(?i)\\batob\\s*\\(\\s*[\\'\\\"\\'\\\\]", "atob() decode", ThreatLevelHigh},
		{`(?i)\bbtoa\s*\(`, "btoa() encode", ThreatLevelMedium},
		{"(?i)\\bJSON\\.parse\\s*\\(\\s*[\\'\\\"\\'\\\\]", "JSON.parse with string", ThreatLevelLow},
		{`(?i)\bString\.fromCharCode\s*\(\s*\d+`, "String.fromCharCode()", ThreatLevelMedium},
		{`(?i)\beval\s*\(\s*atob\s*\(`, "eval(atob()) - encoded payload", ThreatLevelCritical},
		{`(?i)\beval\s*\(\s*\$`, "eval() with variable", ThreatLevelCritical},
		{`(?i)\bFunction\s*\(\s*\$`, "Function() with variable", ThreatLevelCritical},
		{"(?i)\\bprocess\\.binding\\s*\\(\\s*[\\'\\\"\\'\\\\]", "process.binding()", ThreatLevelCritical},
		{`(?i)\bprocess\.mainModule\.require\s*\(`, "process.mainModule.require()", ThreatLevelCritical},
	}

	for _, p := range evalPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "Avoid dynamic evaluation; use safe alternatives",
			})
		}
	}
}

func (a *JSAnalyzer) analyzeSensitiveDataExposure(data string, result *AnalysisResult) {
	sensitivePatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\bdocument\.cookie\b`, "document.cookie access", ThreatLevelHigh},
		{`(?i)\bdocument\.domain\b`, "document.domain access", ThreatLevelMedium},
		{`(?i)\bdocument\.referrer\b`, "document.referrer access", ThreatLevelMedium},
		{`(?i)\blocalStorage\.`, "localStorage access", ThreatLevelHigh},
		{`(?i)\bsessionStorage\.`, "sessionStorage access", ThreatLevelHigh},
		{`(?i)\bindexedDB\.`, "indexedDB access", ThreatLevelMedium},
		{`(?i)\bcache\.store\s*\(`, "Cache API storage", ThreatLevelMedium},
		{`(?i)\bcaches\.open\s*\(`, "caches.open()", ThreatLevelMedium},
		{`(?i)\bconsole\.log\s*\([^)]*\btoken`, "Console log with token", ThreatLevelHigh},
		{`(?i)\bconsole\.log\s*\([^)]*\bkey`, "Console log with key", ThreatLevelHigh},
		{`(?i)\bconsole\.log\s*\([^)]*\bsecret`, "Console log with secret", ThreatLevelHigh},
		{`(?i)\bconsole\.log\s*\([^)]*\bpassword`, "Console log with password", ThreatLevelHigh},
		{`(?i)\bconsole\.log\s*\([^)]*\bauth`, "Console log with auth", ThreatLevelHigh},
		{`(?i)\bfetch\s*\(\s*[^)]*\bAuthorization`, "fetch with Authorization header", ThreatLevelMedium},
		{`(?i)\bXMLHttpRequest\.`, "XMLHttpRequest (data exfil)", ThreatLevelHigh},
		{`(?i)\bnavigator\.credentials\.`, "Navigator.credentials API", ThreatLevelHigh},
		{`(?i)\bperformance\.memory`, "performance.memory (Chrome)", ThreatLevelMedium},
		{`(?i)\bwindow\.name\b`, "window.name (persistent)", ThreatLevelMedium},
		{`(?i)\bpostMessage\s*\(`, "postMessage() call", ThreatLevelMedium},
		{`(?i)\bStorageEvent\b`, "StorageEvent listener", ThreatLevelMedium},
		{`(?i)\bcrypto\.getRandomValues\s*\(`, "crypto.getRandomValues()", ThreatLevelLow},
		{`(?i)\bcrypto\.subtle\.`, "crypto.subtle API", ThreatLevelMedium},
		{`(?i)\bNotification\.requestPermission\s*\(`, "Notification API", ThreatLevelLow},
		{`(?i)\bBroadcastChannel\b`, "BroadcastChannel API", ThreatLevelMedium},
	}

	for _, p := range sensitivePatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "Protect sensitive data; avoid logging secrets",
			})
		}
	}
}

func (a *JSAnalyzer) analyzeServerSideRequest(data string, result *AnalysisResult) {
	ssrPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\bfetch\s*\(\s*['\"']http`, "fetch() with URL", ThreatLevelHigh},
		{`(?i)\bXMLHttpRequest\s*\(\s*\)`, "XMLHttpRequest instantiation", ThreatLevelHigh},
		{`(?i)\baxios\.`, "axios HTTP client", ThreatLevelHigh},
		{`(?i)\brequest\s*\(\s*\{`, "request library", ThreatLevelHigh},
		{`(?i)\bnode-fetch\.`, "node-fetch library", ThreatLevelHigh},
		{`(?i)\bgot\.`, "got HTTP library", ThreatLevelHigh},
		{`(?i)\bsuperagent\.`, "superagent library", ThreatLevelHigh},
		{`(?i)\bhttp\.request\s*\(`, "http.request()", ThreatLevelHigh},
		{`(?i)\bhttps\.request\s*\(`, "https.request()", ThreatLevelHigh},
		{`(?i)\bnet\.socket\s*\(`, "net.socket()", ThreatLevelHigh},
		{`(?i)\btls\.connect\s*\(`, "tls.connect()", ThreatLevelHigh},
		{`(?i)\bws\.WebSocket\s*\(`, "WebSocket connection", ThreatLevelHigh},
		{`(?i)\blocation\.href\s*=`, "location.href redirect", ThreatLevelMedium},
		{`(?i)\bwindow\.location\s*=`, "window.location redirect", ThreatLevelMedium},
		{`(?i)\bdocument\.location\s*=`, "document.location redirect", ThreatLevelMedium},
		{`(?i)\bhistory\.pushState\s*\(`, "history.pushState()", ThreatLevelMedium},
		{`(?i)\bhistory\.replaceState\s*\(`, "history.replaceState()", ThreatLevelMedium},
	}

	for _, p := range ssrPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "Validate URLs; use allowlist for destinations",
			})
		}
	}
}

func (a *JSAnalyzer) analyzePathTraversal(data string, result *AnalysisResult) {
	pathPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\.\./`, "路径遍历: ../", ThreatLevelCritical},
		{`(?i)\.\.\\/`, "路径遍历: ../ (反斜杠)", ThreatLevelCritical},
		{`%2e%2e/`, "URL编码的 ../", ThreatLevelCritical},
		{`%2e%2e\\/`, "URL编码的 ../ (反斜杠)", ThreatLevelCritical},
		{`(?i)/etc/passwd`, "引用 /etc/passwd", ThreatLevelCritical},
		{`(?i)/etc/shadow`, "引用 /etc/shadow", ThreatLevelCritical},
		{`(?i)c:\\windows`, "Windows路径: c:\\windows", ThreatLevelHigh},
		{`(?i)file://`, "file:// 协议", ThreatLevelHigh},
		{`(?i)ftp://`, "ftp:// 协议", ThreatLevelHigh},
		{`(?i)sftp://`, "sftp:// 协议", ThreatLevelHigh},
		{`(?i)ssh://`, "ssh:// 协议", ThreatLevelHigh},
		{`(?i)smb://`, "smb:// 协议", ThreatLevelHigh},
		{`(?i)jar://`, "jar:// 协议", ThreatLevelCritical},
		{`(?i) Phasar://`, "Phar:// 协议", ThreatLevelCritical},
		{`(?i)\.\.\.%00`, "路径遍历 + NULL字节", ThreatLevelCritical},
	}

	for _, p := range pathPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "Validate and sanitize file paths",
			})
		}
	}
}

func (a *JSAnalyzer) analyzeReDoS(data string, result *AnalysisResult) {
	redosPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\(\.\+\)\*`, "Double quantifiers: (.+)*", ThreatLevelCritical},
		{`\(\.\?\)`, "Double quantifiers: (.?)*", ThreatLevelCritical},
		{`\(\.\{[^}]+\}\)\+`, "Nested repetition: (.{n,})+", ThreatLevelCritical},
		{`\(\.\{[^}]+\}\)\*`, "Double nested repetition: (.{n,})*", ThreatLevelCritical},
		{`\(\w\+\)\+`, "Nested word quantifiers: (\\w+)+", ThreatLevelCritical},
		{`\(\w\*\)\+`, "Nested word quantifiers: (\\w*)+", ThreatLevelCritical},
		{`\(\[\^[^]]+\]\+\)\+`, "Nested negated char class: ([^]+)+", ThreatLevelCritical},
		{`\(\[\^[^]]\*\]\+\)\+`, "Nested negated char class: ([^]*)+", ThreatLevelCritical},
		{`\(a\*\)\*b`, "ReDoS pattern: (a*)*b", ThreatLevelCritical},
		{`\(a\+\)\+b`, "ReDoS pattern: (a+)+b", ThreatLevelCritical},
		{`\(a\?a\)\*`, "ReDoS pattern: (a?a)*", ThreatLevelCritical},
		{`\(a\?a\?a\)\*`, "ReDoS pattern: (a?a?a)*", ThreatLevelCritical},
		{`\(\.\+\)\+\$`, "Greedy with end anchor: (.+)+$", ThreatLevelHigh},
		{`\(\.\*\)\+\$`, "Greedy star with end: (.*)+$", ThreatLevelHigh},
		{`\(a\{1,\d+\}\)\+`, "Large range repetition", ThreatLevelCritical},
	}

	for _, p := range redosPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "Review regex patterns; avoid nested quantifiers",
			})
		}
	}
}

func (a *JSAnalyzer) analyzeMaliciousPatterns(data string, result *AnalysisResult) {
	maliciousPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)<script`, "Script标签注入", ThreatLevelCritical},
		{`(?i)</script`, "Script标签闭合", ThreatLevelCritical},
		{`(?i)<img[^>]+onerror`, "Img onerror事件", ThreatLevelCritical},
		{`(?i)<svg[^>]+onload`, "SVG onload事件", ThreatLevelCritical},
		{`(?i)<iframe`, "Iframe注入", ThreatLevelHigh},
		{`(?i)<object`, "Object标签注入", ThreatLevelHigh},
		{`(?i)<embed`, "Embed标签注入", ThreatLevelHigh},
		{`(?i)<link[^>]+href`, "Link标签注入", ThreatLevelMedium},
		{`(?i)<form[^>]+action`, "Form标签注入", ThreatLevelMedium},
		{`(?i)javascript:`, "JavaScript协议", ThreatLevelHigh},
		{`(?i)data:text/html`, "Data URL协议", ThreatLevelHigh},
		{`(?i)vbscript:`, "VBScript协议", ThreatLevelHigh},
		{`(?i)onload\s*=`, "onload事件属性", ThreatLevelCritical},
		{`(?i)onerror\s*=`, "onerror事件属性", ThreatLevelCritical},
		{`(?i)onclick\s*=`, "onclick事件属性", ThreatLevelHigh},
		{`(?i)onmouseover\s*=`, "onmouseover事件属性", ThreatLevelMedium},
		{`(?i)onfocus\s*=`, "onfocus事件属性", ThreatLevelMedium},
		{`(?i)onblur\s*=`, "onblur事件属性", ThreatLevelMedium},
		{`(?i)onkeydown\s*=`, "onkeydown事件属性", ThreatLevelMedium},
		{`(?i)onkeyup\s*=`, "onkeyup事件属性", ThreatLevelMedium},
		{`(?i)onkeypress\s*=`, "onkeypress事件属性", ThreatLevelMedium},
		{`(?i)onsubmit\s*=`, "onsubmit事件属性", ThreatLevelMedium},
		{`(?i)onchange\s*=`, "onchange事件属性", ThreatLevelMedium},
		{`(?i)alert\s*\(\s*`, "alert()弹窗", ThreatLevelMedium},
		{`(?i)confirm\s*\(\s*`, "confirm()确认框", ThreatLevelMedium},
		{`(?i)prompt\s*\(\s*`, "prompt()提示框", ThreatLevelMedium},
		{`(?i)console\.error\s*\(\s*`, "console.error()错误日志", ThreatLevelMedium},
		{`(?i)console\.warn\s*\(\s*`, "console.warn()警告日志", ThreatLevelMedium},
		{`(?i)document\.write\s*\(\s*`, "document.write()动态写入", ThreatLevelHigh},
		{`(?i)document\.writeln\s*\(\s*`, "document.writeln()动态写入", ThreatLevelHigh},
		{`(?i)innerHTML\s*=`, "innerHTML赋值", ThreatLevelHigh},
		{`(?i)outerHTML\s*=`, "outerHTML赋值", ThreatLevelHigh},
		{`(?i)insertAdjacentHTML\s*\(`, "insertAdjacentHTML()插入", ThreatLevelHigh},
		{`(?i)createElement\s*\(\s*['\x27]script`, "createElement(script)", ThreatLevelCritical},
		{`(?i)setAttribute\s*\(\s*['\x27]onerror`, "setAttribute(onerror)", ThreatLevelCritical},
		{`(?i)setAttribute\s*\(\s*['\x27]onload`, "setAttribute(onload)", ThreatLevelCritical},
	}

	for _, p := range maliciousPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "Sanitize HTML output; use textContent instead of innerHTML",
			})
		}
	}
}

func (a *JSAnalyzer) analyzeNodejsSpecific(data string, result *AnalysisResult) {
	nodejsPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\bchild_process\.exec\s*\(`, "child_process.exec()", ThreatLevelCritical},
		{`(?i)\bchild_process\.execSync\s*\(`, "child_process.execSync()", ThreatLevelCritical},
		{`(?i)\bchild_process\.spawn\s*\(`, "child_process.spawn()", ThreatLevelHigh},
		{`(?i)\bchild_process\.fork\s*\(`, "child_process.fork()", ThreatLevelHigh},
		{`(?i)\beval\s*\(\s*process`, "eval(process)", ThreatLevelCritical},
		{`(?i)\bBuffer\.from\s*\(\s*process\.env`, "Buffer from process.env", ThreatLevelCritical},
		{`(?i)\bglobal\.process`, "global.process", ThreatLevelHigh},
		{`(?i)\bglobal\.GLOBAL`, "global.GLOBAL", ThreatLevelHigh},
		{`(?i)\bglobal\.root`, "global.root", ThreatLevelHigh},
		{`(?i)\bglobalThis\.process`, "globalThis.process", ThreatLevelHigh},
		{`(?i)\brequire\s*\(\s*['\"]child_process`, "require(child_process)", ThreatLevelCritical},
		{`(?i)\brequire\s*\(\s*['\"]fs`, "require(fs)", ThreatLevelHigh},
		{`(?i)\brequire\s*\(\s*['\"]net`, "require(net)", ThreatLevelHigh},
		{`(?i)\brequire\s*\(\s*['\"]tls`, "require(tls)", ThreatLevelHigh},
		{`(?i)\brequire\s*\(\s*['\"]http`, "require(http)", ThreatLevelMedium},
		{`(?i)\brequire\s*\(\s*['\"]https`, "require(https)", ThreatLevelMedium},
		{`(?i)\brequire\s*\(\s*['\"]dns`, "require(dns)", ThreatLevelMedium},
		{`(?i)\brequire\s*\(\s*['\"]os`, "require(os)", ThreatLevelMedium},
		{`(?i)\bmodule\.exports\s*=`, "module.exports assignment", ThreatLevelMedium},
		{`(?i)\bexports\.\w+\s*=`, "exports assignment", ThreatLevelMedium},
		{`(?i)\b__dirname`, "__dirname exposure", ThreatLevelMedium},
		{`(?i)\b__filename`, "__filename exposure", ThreatLevelMedium},
		{`(?i)\bprocess\.cwd\s*\(`, "process.cwd()", ThreatLevelMedium},
		{`(?i)\bprocess\.chdir\s*\(`, "process.chdir()", ThreatLevelHigh},
		{`(?i)\bprocess\.kill\s*\(`, "process.kill()", ThreatLevelHigh},
		{`(?i)\bprocess\.exit\s*\(`, "process.exit()", ThreatLevelMedium},
		{`(?i)\bprocess\.env\.NODE_ENV`, "process.env.NODE_ENV", ThreatLevelLow},
		{`(?i)\bprocess\.env\.SECRET`, "process.env.SECRET", ThreatLevelHigh},
		{`(?i)\bprocess\.env\.PASSWORD`, "process.env.PASSWORD", ThreatLevelHigh},
		{`(?i)\bprocess\.env\.API_KEY`, "process.env.API_KEY", ThreatLevelHigh},
		{`(?i)\bprocess\.env\.DATABASE_URL`, "process.env.DATABASE_URL", ThreatLevelHigh},
	}

	for _, p := range nodejsPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "Protect Node.js environment; avoid dynamic require",
			})
		}
	}
}

func (a *JSAnalyzer) analyzeClientSideInjection(data string, result *AnalysisResult) {
	domXssPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\bdocument\.URL\s*`, "document.URL in sink", ThreatLevelHigh},
		{`(?i)\bdocument\.documentURI\s*`, "document.documentURI in sink", ThreatLevelHigh},
		{`(?i)\bdocument\.referrer\s*`, "document.referrer in sink", ThreatLevelHigh},
		{`(?i)\blocation\.href\s*`, "location.href in sink", ThreatLevelHigh},
		{`(?i)\blocation\.search\s*`, "location.search in sink", ThreatLevelHigh},
		{`(?i)\blocation\.hash\s*`, "location.hash in sink", ThreatLevelHigh},
		{`(?i)\blocation\.pathname\s*`, "location.pathname in sink", ThreatLevelMedium},
		{`(?i)\bwindow\.name\s*`, "window.name in sink", ThreatLevelHigh},
		{`(?i)\bhistory\.pushState\s*\(\s*\$\{`, "history.pushState with template", ThreatLevelMedium},
		{`(?i)\bhistory\.replaceState\s*\(\s*\$\{`, "history.replaceState with template", ThreatLevelMedium},
		{`(?i)\bpostMessage\s*\(\s*\$\{`, "postMessage with template", ThreatLevelMedium},
		{`(?i)\bwebSocket\s*\(\s*\$\{`, "webSocket with template", ThreatLevelMedium},
		{`(?i)\bEventSource\s*\(\s*\$\{`, "EventSource with template", ThreatLevelMedium},
		{`(?i)\bXMLHttpRequest\.open\s*\(\s*['\"']\,\s*\$\{`, "XMLHttpRequest.open with template", ThreatLevelHigh},
		{`(?i)\bfetch\s*\(\s*\$\{`, "fetch with template", ThreatLevelHigh},
		{`(?i)\bnew\s+Worker\s*\(\s*\$\{`, "new Worker with template", ThreatLevelCritical},
		{`(?i)\bnew\s+SharedWorker\s*\(\s*\$\{`, "new SharedWorker with template", ThreatLevelCritical},
		{`(?i)\bimport\s*\(\s*\$\{`, "Dynamic import with template", ThreatLevelCritical},
		{`(?i)\bimportScripts\s*\(\s*\$\{`, "importScripts with template", ThreatLevelCritical},
		{`(?i)\beval\s*\(\s*atob\s*\(\s*\$\{`, "eval(atob(template))", ThreatLevelCritical},
	}

	for _, p := range domXssPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "Sanitize DOM inputs; use safe DOM manipulation methods",
			})
		}
	}
}
