package analyzer

import (
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

type XXEAnalyzer struct {
	name         string
	version      string
	analyzerType string
	enabled      bool
	config       map[string]interface{}
	mu           sync.RWMutex
}

func NewXXEAnalyzer() *XXEAnalyzer {
	return &XXEAnalyzer{
		name:         "xxe_analyzer",
		version:      "1.0.0",
		analyzerType: "xxe",
		enabled:      true,
		config:       make(map[string]interface{}),
	}
}

func (a *XXEAnalyzer) Name() string {
	return a.name
}

func (a *XXEAnalyzer) Type() string {
	return a.analyzerType
}

func (a *XXEAnalyzer) Version() string {
	return a.version
}

func (a *XXEAnalyzer) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

func (a *XXEAnalyzer) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

func (a *XXEAnalyzer) Configure(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = config
	return nil
}

func (a *XXEAnalyzer) Analyze(input *AnalysisInput) *AnalysisResult {
	start := time.Now()
	result := NewAnalysisResult(a)

	if input == nil || input.Raw == "" {
		return result
	}

	dataToAnalyze := a.prepareData(input)

	a.analyzeEntityDeclarations(dataToAnalyze, result)
	a.analyzeDOCTYPEDeclarations(dataToAnalyze, result)
	a.analyzeEntityExpansion(dataToAnalyze, result)
	a.analyzeXXEPayloads(dataToAnalyze, result)
	a.analyzeBlindXXE(dataToAnalyze, result)
	a.analyzeSSRFVectors(dataToAnalyze, result)
	a.analyzeFileReadVectors(dataToAnalyze, result)

	result.ProcessingTime = time.Since(start)
	result.ShouldBlock = result.ShouldBlockRequest(0.5)
	if len(result.Matches) > 0 {
		result.ShouldLog = true
		result.ShouldAllow = !result.ShouldBlock
	}

	return result
}

func (a *XXEAnalyzer) prepareData(input *AnalysisInput) string {
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

func (a *XXEAnalyzer) analyzeEntityDeclarations(data string, result *AnalysisResult) {
	entityPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)<!ENTITY\s+`, "ENTITY声明", ThreatLevelCritical},
		{`(?i)<!ATTLIST\s+`, "ATTLIST声明", ThreatLevelHigh},
		{`(?i)<!ELEMENT\s+`, "ELEMENT声明", ThreatLevelMedium},
		{`(?i)<!NOTATION\s+`, "NOTATION声明", ThreatLevelHigh},
		{`(?i)<!ENTITY\s+\w+\s+SYSTEM`, "SYSTEM实体声明", ThreatLevelCritical},
		{`(?i)<!ENTITY\s+\w+\s+PUBLIC`, "PUBLIC实体声明", ThreatLevelCritical},
		{`(?i)<!ENTITY\s+\w+\s+['"]`, "内部实体声明", ThreatLevelMedium},
		{`(?i)<!ENTITY\s+\w+\s+SYSTEM\s+['"]`, "SYSTEM内部实体", ThreatLevelCritical},
		{`(?i)<!ENTITY\s+\w+\s+PUBLIC\s+['"]`, "PUBLIC内部实体", ThreatLevelCritical},
		{`(?i)%\s+\w+;`, "参数实体引用", ThreatLevelHigh},
	}

	for _, p := range entityPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "XXE威胁 - " + p.description,
				Recommendation: "禁用DTD和外部实体解析",
			})
		}
	}
}

func (a *XXEAnalyzer) analyzeDOCTYPEDeclarations(data string, result *AnalysisResult) {
	doctypePatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)<!DOCTYPE\s+`, "DOCTYPE声明", ThreatLevelCritical},
		{`(?i)<!DOCTYPE\s+\w+\s+SYSTEM`, "DOCTYPE SYSTEM声明", ThreatLevelCritical},
		{`(?i)<!DOCTYPE\s+\w+\s+PUBLIC`, "DOCTYPE PUBLIC声明", ThreatLevelCritical},
		{`(?i)<!DOCTYPE\s+\w+\s+\[`, "DOCTYPE内部子集", ThreatLevelHigh},
		{`(?i)<!DOCTYPE\s+\w+\s+SYSTEM\s+['"]file:`, "本地文件引用", ThreatLevelCritical},
		{`(?i)<!DOCTYPE\s+\w+\s+SYSTEM\s+['"]http:`, "HTTP URL引用", ThreatLevelCritical},
		{`(?i)<!DOCTYPE\s+\w+\s+SYSTEM\s+['"]https:`, "HTTPS URL引用", ThreatLevelCritical},
		{`(?i)<!DOCTYPE\s+\w+\s+SYSTEM\s+['"]ftp:`, "FTP URL引用", ThreatLevelCritical},
		{`(?i)<!DOCTYPE\s+\w+\s+PUBLIC\s+['"][^'"]*['"]\s+['"]`, "PUBLIC外部ID", ThreatLevelCritical},
	}

	for _, p := range doctypePatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "DOCTYPE声明威胁 - " + p.description,
				Recommendation: "禁用外部DTD和实体解析",
			})
		}
	}
}

func (a *XXEAnalyzer) analyzeEntityExpansion(data string, result *AnalysisResult) {
	expansionPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`&\w+;`, "实体引用", ThreatLevelHigh},
		{`&#[0-9]+;`, "十进制字符引用", ThreatLevelHigh},
		{`&#x[0-9a-fA-F]+;`, "十六进制字符引用", ThreatLevelHigh},
		{`&#x[0-9a-fA-F]+`, "裸十六进制字符引用", ThreatLevelMedium},
		{`&[a-zA-Z]+;`, "命名实体引用", ThreatLevelMedium},
		{`%\d+;`, "参数实体引用", ThreatLevelHigh},
		{`%\w+;`, "参数实体引用变体", ThreatLevelHigh},
		{`&\d+;`, "数字字符引用", ThreatLevelHigh},
		{`&\#\d+;`, "HTML实体数字引用", ThreatLevelHigh},
		{`&\#x[0-9a-fA-F]+;`, "HTML实体十六进制引用", ThreatLevelHigh},
	}

	for _, p := range expansionPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "实体扩展威胁 - " + p.description,
				Recommendation: "禁用DTD并过滤实体引用",
			})
		}
	}
}

func (a *XXEAnalyzer) analyzeXXEPayloads(data string, result *AnalysisResult) {
	payloadPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)<!ENTITY\s+\w+\s+SYSTEM\s+["']file:///`, "XXE本地文件读取", ThreatLevelCritical},
		{`(?i)<!ENTITY\s+\w+\s+SYSTEM\s+["']file://`, "XXE本地文件读取", ThreatLevelCritical},
		{`(?i)<!ENTITY\s+\w+\s+SYSTEM\s+["']/etc/`, "XXE Unix文件读取", ThreatLevelCritical},
		{`(?i)<!ENTITY\s+\w+\s+SYSTEM\s+["']c:\\`, "XXE Windows文件读取", ThreatLevelCritical},
		{`(?i)<!ENTITY\s+\w+\s+SYSTEM\s+["']http://`, "XXE HTTP SSRF", ThreatLevelCritical},
		{`(?i)<!ENTITY\s+\w+\s+SYSTEM\s+["']https://`, "XXE HTTPS SSRF", ThreatLevelCritical},
		{`(?i)<!ENTITY\s+\w+\s+SYSTEM\s+["']ftp://`, "XXE FTP SSRF", ThreatLevelCritical},
		{`(?i)<!ENTITY\s+\w+\s+SYSTEM\s+["']dict://`, "XXE Dict协议", ThreatLevelCritical},
		{`(?i)<!ENTITY\s+\w+\s+SYSTEM\s+["']gopher://`, "XXE Gopher协议", ThreatLevelCritical},
		{`(?i)<!ENTITY\s+\w+\s+PUBLIC\s+["'][^"']+["']\s+["'][^"']*`, "XXE PUBLIC实体", ThreatLevelCritical},
		{`(?i)<!ENTITY\s+%?\s*\w+\s+SYSTEM\s+["']`, "参数实体XXE", ThreatLevelCritical},
		{`(?i)<!ENTITY\s+%?\s*\w+\s+PUBLIC\s+["']`, "参数实体PUBLIC", ThreatLevelCritical},
		{`(?i)<!DOCTYPE[^>]*\[\s*<!ENTITY`, "内部DTD XXE", ThreatLevelCritical},
		{`(?i)<!DOCTYPE[^>]*\[\s*<!ATTLIST`, "内部DTD ATTLIST", ThreatLevelHigh},
		{`(?i)<!DOCTYPE[^>]*\[\s*<!ELEMENT`, "内部DTD ELEMENT", ThreatLevelMedium},
		{`(?i)\[CDATA\[.*\]\]>`, "CDATA节注入", ThreatLevelHigh},
	}

	for _, p := range payloadPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "XXE攻击载荷 - " + p.description,
				Recommendation: "禁用外部实体和DTD解析",
			})
		}
	}
}

func (a *XXEAnalyzer) analyzeBlindXXE(data string, result *AnalysisResult) {
	blindXXEPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)<!ENTITY\s+\w+\s+SYSTEM\s+["']http://[^"']+["']`, "Blind XXE HTTP外带", ThreatLevelCritical},
		{`(?i)<!ENTITY\s+\w+\s+SYSTEM\s+["']https://[^"']+["']`, "Blind XXE HTTPS外带", ThreatLevelCritical},
		{`(?i)<!ENTITY\s+\w+\s+SYSTEM\s+["']ftp://[^"']+["']`, "Blind XXE FTP外带", ThreatLevelHigh},
		{`(?i)<!ENTITY\s+\w+\s+SYSTEM\s+["']dict://[^"']+["']`, "Blind XXE Dict外带", ThreatLevelCritical},
		{`(?i)<!ENTITY\s+\w+\s+SYSTEM\s+["']gopher://[^"']+["']`, "Blind XXE Gopher外带", ThreatLevelCritical},
		{`(?i)<!ENTITY\s+\w+\s+SYSTEM\s+["']file:///dev/`, "XXE /dev/zero", ThreatLevelHigh},
		{`(?i)<!ENTITY\s+\w+\s+SYSTEM\s+["']file:///tmp/`, "XXE /tmp文件", ThreatLevelHigh},
		{`(?i)<!ENTITY\s+\w+\s+SYSTEM\s+["']php://`, "XXE PHP协议", ThreatLevelCritical},
		{`(?i)<!ENTITY\s+\w+\s+SYSTEM\s+["']expect://`, "XXE Expect协议", ThreatLevelCritical},
		{`(?i)<!ENTITY\s+\w+\s+SYSTEM\s+["']jar://`, "XXE Jar协议", ThreatLevelCritical},
		{`(?i)<!ENTITY\s+\w+\s+SYSTEM\s+["']zip://`, "XXE Zip协议", ThreatLevelHigh},
		{`(?i)xmlns\s*=\s*["']http://`, "XML命名空间注入", ThreatLevelHigh},
		{`(?i)xmlns:xs\s*=\s*["']http://www\.w3\.org/`, "XSI命名空间注入", ThreatLevelMedium},
		{`(?i)xsi\s*:schemaLocation\s*=`, "XSI schemaLocation注入", ThreatLevelHigh},
		{`(?i)noNamespaceSchemaLocation\s*=`, "noNamespaceSchemaLocation注入", ThreatLevelHigh},
		{`(?i)<!DOCTYPE[^>]*SYSTEM\s+["']file://`, "外部DTD文件引用", ThreatLevelCritical},
		{`(?i)<!DOCTYPE[^>]*PUBLIC\s+["'][^"']+["']\s+["']file://`, "外部PUBLIC DTD", ThreatLevelCritical},
	}

	for _, p := range blindXXEPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Blind XXE威胁 - " + p.description,
				Recommendation: "禁用外部实体并使用完整安全配置",
			})
		}
	}
}

func (a *XXEAnalyzer) analyzeSSRFVectors(data string, result *AnalysisResult) {
	ssrfPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)system\s*=\s*["']http://`, "SSRF HTTP向量", ThreatLevelHigh},
		{`(?i)system\s*=\s*["']https://`, "SSRF HTTPS向量", ThreatLevelHigh},
		{`(?i)system\s*=\s*["']file://`, "SSRF File向量", ThreatLevelHigh},
		{`(?i)system\s*=\s*["']ftp://`, "SSRF FTP向量", ThreatLevelMedium},
		{`(?i)system\s*=\s*["']dict://`, "SSRF Dict向量", ThreatLevelHigh},
		{`(?i)system\s*=\s*["']gopher://`, "SSRF Gopher向量", ThreatLevelHigh},
		{`(?i)system\s*=\s*["']sftp://`, "SSRF SFTP向量", ThreatLevelHigh},
		{`(?i)system\s*=\s*["']ldap://`, "SSRF LDAP向量", ThreatLevelHigh},
		{`(?i)system\s*=\s*["']smtp://`, "SSRF SMTP向量", ThreatLevelMedium},
		{`(?i)system\s*=\s*["']imap://`, "SSRF IMAP向量", ThreatLevelMedium},
		{`(?i)system\s*=\s*["']pop3://`, "SSRF POP3向量", ThreatLevelMedium},
		{`(?i)public\s*=\s*["']-[^"']*["']\s*["'][^"']*["']`, "SSRF PUBLIC向量", ThreatLevelHigh},
	}

	for _, p := range ssrfPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "XXE SSRF向量 - " + p.description,
				Recommendation: "禁用外部实体解析和协议限制",
			})
		}
	}
}

func (a *XXEAnalyzer) analyzeFileReadVectors(data string, result *AnalysisResult) {
	fileReadPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)file:///etc/passwd`, "读取/etc/passwd", ThreatLevelCritical},
		{`(?i)file:///etc/shadow`, "读取/etc/shadow", ThreatLevelCritical},
		{`(?i)file:///etc/hosts`, "读取/etc/hosts", ThreatLevelHigh},
		{`(?i)file:///etc/group`, "读取/etc/group", ThreatLevelHigh},
		{`(?i)file:///etc/my\.cnf`, "读取MySQL配置", ThreatLevelCritical},
		{`(?i)file:///etc/httpd/conf`, "读取Apache配置", ThreatLevelCritical},
		{`(?i)file:///etc/nginx/`, "读取Nginx配置", ThreatLevelCritical},
		{`(?i)file:///c:/windows/`, "读取Windows目录", ThreatLevelCritical},
		{`(?i)file:///c:/boot\.ini`, "读取Windows启动配置", ThreatLevelHigh},
		{`(?i)file:///c:/Program Files/`, "读取Program Files", ThreatLevelHigh},
		{`(?i)file:///c:/Users/`, "读取Windows用户目录", ThreatLevelCritical},
		{`(?i)file:///var/log/`, "读取Linux日志", ThreatLevelHigh},
		{`(?i)file:///var/www/`, "读取Web目录", ThreatLevelHigh},
		{`(?i)file:///home/`, "读取用户主目录", ThreatLevelHigh},
		{`(?i)file:///tmp/`, "读取临时文件目录", ThreatLevelMedium},
		{`(?i)file:///proc/self/environ`, "读取进程环境变量", ThreatLevelCritical},
		{`(?i)file:///proc/self/cmdline`, "读取进程命令行", ThreatLevelHigh},
		{`(?i)file:///proc/version`, "读取内核版本", ThreatLevelMedium},
		{`(?i)file:///proc/cmdline`, "读取内核命令行", ThreatLevelMedium},
		{`(?i)php://filter/`, "PHP过滤器协议", ThreatLevelCritical},
		{`(?i)php://input`, "PHP输入流", ThreatLevelCritical},
		{`(?i)expect://`, "Expect协议", ThreatLevelCritical},
		{`(?i)ogg://`, "Ogg协议", ThreatLevelMedium},
		{`(?i)zlib://`, "Zlib协议", ThreatLevelMedium},
		{`(?i)zip://`, "Zip协议", ThreatLevelHigh},
		{`(?i)data://`, "Data协议", ThreatLevelHigh},
	}

	for _, p := range fileReadPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "XXE文件读取向量 - " + p.description,
				Recommendation: "禁止外部实体和文件协议",
			})
		}
	}
}

func (a *XXEAnalyzer) detectXXEInURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if strings.Contains(parsed.RawQuery, "<!ENTITY") || strings.Contains(parsed.RawQuery, "<!DOCTYPE") {
		return true
	}
	return false
}
