package analyzer

import (
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type PathTraversalAnalyzer struct {
	name           string
	version        string
	analyzerType   string
	enabled        bool
	config         map[string]interface{}
	sensitivePaths []string
	mu             sync.RWMutex
}

func NewPathTraversalAnalyzer() *PathTraversalAnalyzer {
	return &PathTraversalAnalyzer{
		name:         "path_traversal_analyzer",
		version:      "1.0.0",
		analyzerType: "path_traversal",
		enabled:      true,
		config:       make(map[string]interface{}),
		sensitivePaths: []string{
			"/etc/passwd",
			"/etc/shadow",
			"/etc/hosts",
			"/etc/group",
			"/etc/my.cnf",
			"/etc/nginx/nginx.conf",
			"/etc/apache2/apache2.conf",
			"/etc/httpd/conf/httpd.conf",
			"/var/log/",
			"/var/www/",
			"/home/",
			"/root/",
			"/.ssh/",
			"/.aws/",
			"/.git/",
			"/.env",
			"/proc/self/environ",
			"/proc/self/cmdline",
			"/proc/version",
			"/c:/windows/",
			"/c:/boot.ini",
			"/c:/Program Files/",
			"/c:/Users/",
			"/boot.ini",
			"/web.config",
			"/.htaccess",
			"/config.php",
			"/wp-config.php",
			"/settings.py",
			"/application.properties",
		},
	}
}

func (a *PathTraversalAnalyzer) Name() string {
	return a.name
}

func (a *PathTraversalAnalyzer) Type() string {
	return a.analyzerType
}

func (a *PathTraversalAnalyzer) Version() string {
	return a.version
}

func (a *PathTraversalAnalyzer) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

func (a *PathTraversalAnalyzer) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

func (a *PathTraversalAnalyzer) Configure(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if paths, ok := config["sensitive_paths"].([]string); ok {
		a.sensitivePaths = paths
	}
	a.config = config
	return nil
}

func (a *PathTraversalAnalyzer) Analyze(input *AnalysisInput) *AnalysisResult {
	start := time.Now()
	result := NewAnalysisResult(a)

	if input == nil || input.Raw == "" {
		return result
	}

	dataToAnalyze := a.prepareData(input)

	a.analyzeBasicTraversal(dataToAnalyze, result)
	a.analyzeURLEncodedTraversal(dataToAnalyze, result)
	a.analyzeDoubleEncodedTraversal(dataToAnalyze, result)
	a.analyzeUnicodeTraversal(dataToAnalyze, result)
	a.analyzeNullByteInjection(dataToAnalyze, result)
	a.analyzePathNormalization(dataToAnalyze, input, result)
	a.analyzeSensitivePathAccess(dataToAnalyze, result)
	a.analyzeSolarPathTraversal(dataToAnalyze, result)
	a.analyzeWindowsPathTraversal(dataToAnalyze, result)
	a.analyzeWrapperTraversal(dataToAnalyze, result)

	result.ProcessingTime = time.Since(start)
	result.ShouldBlock = result.ShouldBlockRequest(0.5)
	if len(result.Matches) > 0 {
		result.ShouldLog = true
		result.ShouldAllow = !result.ShouldBlock
	}

	return result
}

func (a *PathTraversalAnalyzer) prepareData(input *AnalysisInput) string {
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

func (a *PathTraversalAnalyzer) analyzeBasicTraversal(data string, result *AnalysisResult) {
	traversalPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\.\./`, "双点目录遍历", ThreatLevelCritical},
		{`(?i)\.\./\.\./`, "双重双点目录遍历", ThreatLevelCritical},
		{`(?i)\.\./\.\./\.\./`, "三重双点目录遍历", ThreatLevelCritical},
		{`(?i)\.\.%2f`, "URL编码双点", ThreatLevelHigh},
		{`(?i)%2e%2e/`, "双编码双点斜线", ThreatLevelCritical},
		{`(?i)%2e%2e%2f`, "双编码双点斜线变体", ThreatLevelCritical},
		{`(?i)\.\.%c0%af`, "UTF-8编码双点", ThreatLevelCritical},
		{`(?i)\.\.%c1%9c`, "Windows UNC路径", ThreatLevelHigh},
		{`(?i)\.\.%e0%80%af`, "超长UTF-8双点", ThreatLevelCritical},
		{`(?i)/\.\./`, "斜线双点斜线", ThreatLevelHigh},
		{`(?i)/\.\.%`, "斜线双点", ThreatLevelHigh},
		{`(?i)\.\./\.\./\.\./\.\./`, "四次双点遍历", ThreatLevelCritical},
		{`(?i)\.\./\.\./\.\./\.\./\.\./`, "五次双点遍历", ThreatLevelCritical},
		{`(?i)\.\.\/`, "反斜线双点", ThreatLevelHigh},
		{`(?i)\.\.\.\./`, "多重双点", ThreatLevelHigh},
		{`(?i)\.\.\./`, "单双点遍历", ThreatLevelHigh},
		{`\.\.\\`, "Windows双点反斜线", ThreatLevelHigh},
		{`\.\.\\\.\\`, "Windows多重双点", ThreatLevelHigh},
	}

	for _, p := range traversalPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "路径遍历威胁 - " + p.description,
				Recommendation: "过滤和验证所有路径输入",
			})
		}
	}
}

func (a *PathTraversalAnalyzer) analyzeURLEncodedTraversal(data string, result *AnalysisResult) {
	urlEncodedPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`%2e%2e/`, "双点URL编码 (../)", ThreatLevelCritical},
		{`%2e%2e%2f`, "双点URL编码变体 (..%2f)", ThreatLevelCritical},
		{`%2e%2e\\`, "双点URL编码反斜线", ThreatLevelHigh},
		{`%2e%2e%5c`, "双点URL编码反斜线变体", ThreatLevelHigh},
		{`%252e%252e/`, "双重URL编码双点", ThreatLevelCritical},
		{`%252e%252e%252f`, "双重URL编码变体", ThreatLevelCritical},
		{`%252e%252e\\`, "双重URL编码反斜线", ThreatLevelCritical},
		{`%252e%252e%255c`, "双重URL编码反斜线变体", ThreatLevelCritical},
		{`%c0%ae%c0%ae/`, "Java曲棍球编码双点", ThreatLevelCritical},
		{`%c0%af/`, "UTF-8双点斜线", ThreatLevelCritical},
		{`%c0%5c`, "UTF-8反斜线", ThreatLevelCritical},
		{`%c1%9c`, "Windows UNC编码", ThreatLevelHigh},
		{`%c1%8f`, "UTF-8编码", ThreatLevelHigh},
		{`%c0%9v`, "UTF-8编码变体", ThreatLevelHigh},
		{`%c0%qf`, "UTF-8编码变体", ThreatLevelHigh},
		{`%e0%80%af`, "超长UTF-8序列", ThreatLevelCritical},
		{`%f0%80%80%af`, "超长UTF-8序列2", ThreatLevelCritical},
		{`%f8%80%80%80%af`, "超长UTF-8序列3", ThreatLevelCritical},
		{`%fc%80%80%80%80%af`, "超长UTF-8序列4", ThreatLevelCritical},
		{`%u002e%u002e/`, "Unicode双点", ThreatLevelCritical},
		{`%u2215`, "Unicode斜线", ThreatLevelHigh},
		{`%u2216`, "Unicode反斜线", ThreatLevelHigh},
		{`%uE8C0`, "Unicode编码", ThreatLevelHigh},
		{`%uE8C0`, "Unicode编码变体", ThreatLevelHigh},
		{`\.\.%255c`, "混合编码", ThreatLevelHigh},
		{`\.\.%5c`, "混合编码变体", ThreatLevelHigh},
	}

	for _, p := range urlEncodedPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "URL编码路径遍历 - " + p.description,
				Recommendation: "规范化URL编码路径",
			})
		}
	}
}

func (a *PathTraversalAnalyzer) analyzeDoubleEncodedTraversal(data string, result *AnalysisResult) {
	doubleEncodedPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`%252e%252e/`, "双重编码双点斜线", ThreatLevelCritical},
		{`%252e%252e%252f`, "双重编码双点", ThreatLevelCritical},
		{`%252e%252e%255c`, "双重编码双点反斜线", ThreatLevelCritical},
		{`%25%2e%25%2e/`, "百分号双编码双点", ThreatLevelCritical},
		{`%252e%252e/`, "双重编码遍历", ThreatLevelCritical},
		{`%252e%252e\\`, "双重编码反斜线", ThreatLevelCritical},
		{`%252e%252e%252e%252e/`, "三次双重编码", ThreatLevelCritical},
		{`%252e%252e%252e%252e%252f`, "多重双重编码", ThreatLevelCritical},
		{`\.\.%2500`, "空字节双重编码", ThreatLevelHigh},
		{`\.\.%2500/`, "空字节双重编码遍历", ThreatLevelHigh},
		{`%252e%252e%2500/`, "组合双重编码", ThreatLevelCritical},
		{`%252e%252e%2500%5c`, "组合双重编码反斜线", ThreatLevelCritical},
	}

	for _, p := range doubleEncodedPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "双重编码路径遍历 - " + p.description,
				Recommendation: "多次解码并验证路径",
			})
		}
	}
}

func (a *PathTraversalAnalyzer) analyzeUnicodeTraversal(data string, result *AnalysisResult) {
	unicodePatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\u002e\u002e/`, "Unicode双点斜线", ThreatLevelCritical},
		{`\u002e\u002e\\`, "Unicode双点反斜线", ThreatLevelCritical},
		{`\u002e\u002e\u2215`, "Unicode双点正斜线", ThreatLevelHigh},
		{`\u002e\u002e\u2216`, "Unicode双点反斜线变体", ThreatLevelHigh},
		{`\u00c0\u0080`, "Unicode替代", ThreatLevelCritical},
		{`\u00c1\u009c`, "Unicode替代变体", ThreatLevelHigh},
		{`\u00c0\u00ae`, "Unicode曲棍球点", ThreatLevelCritical},
		{`\uff0e\uff0e/`, "全角双点", ThreatLevelHigh},
		{`\uff0e\uff0e\\`, "全角双点反斜线", ThreatLevelHigh},
		{`\u002e/`, "单Unicode点斜线", ThreatLevelMedium},
		{`\u002e\\`, "单Unicode点反斜线", ThreatLevelMedium},
		{`\u3009/`, "Unicode右角括号斜线", ThreatLevelMedium},
		{`\u3008/`, "Unicode左角括号斜线", ThreatLevelMedium},
		{`\u2215/`, "Unicode斜线变体", ThreatLevelMedium},
		{`\uFE64/`, "Unicode小型斜线", ThreatLevelMedium},
		{`\u2216\`, "Unicode反斜线变体", ThreatLevelMedium},
	}

	for _, p := range unicodePatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Unicode路径遍历 - " + p.description,
				Recommendation: "规范化Unicode字符",
			})
		}
	}
}

func (a *PathTraversalAnalyzer) analyzeNullByteInjection(data string, result *AnalysisResult) {
	nullBytePatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\.\./%00`, "空字节注入遍历", ThreatLevelCritical},
		{`\.\./\x00`, "十六进制空字节注入", ThreatLevelCritical},
		{`\.\./\0`, "八进制空字节注入", ThreatLevelCritical},
		{`%00\.\./`, "前缀空字节遍历", ThreatLevelHigh},
		{`\.\.%00/`, "后缀空字节遍历", ThreatLevelHigh},
		{`%2500`, "URL编码空字节", ThreatLevelCritical},
		{`%00/`, "URL编码空字节斜线", ThreatLevelHigh},
		{`%00\\`, "URL编码空字节反斜线", ThreatLevelHigh},
		{`\.\./%2500`, "混合空字节遍历", ThreatLevelCritical},
		{`\.\./\u0000`, "Unicode空字节", ThreatLevelCritical},
		{`[^\x00]*\x00`, "内嵌空字节", ThreatLevelMedium},
		{`/\x00/`, "空字节路径分隔", ThreatLevelHigh},
		{`\\\x00/`, "空字节反斜线", ThreatLevelHigh},
		{`/%00/`, "URL空字节路径", ThreatLevelHigh},
		{`%00%2e%00`, "多点空字节", ThreatLevelCritical},
	}

	for _, p := range nullBytePatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "空字节注入 - " + p.description,
				Recommendation: "过滤空字节并验证路径",
			})
		}
	}
}

func (a *PathTraversalAnalyzer) analyzePathNormalization(data string, input *AnalysisInput, result *AnalysisResult) {
	paths := a.extractPaths(data)

	for _, path := range paths {
		if path == "" {
			continue
		}

		decoded := a.decodePath(path)
		normalized := filepath.Clean(decoded)
		real, _ := filepath.Abs(normalized)

		if real != normalized {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelHigh,
				Pattern:        "path_normalization_difference",
				Description:    "路径规范化差异检测",
				Evidence:       "原始: " + path + ", 规范化: " + normalized,
				Recommendation: "验证规范化后的路径在允许范围内",
			})
		}

		if strings.Contains(decoded, "..") {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelHigh,
				Pattern:        "contains_traversal_after_decode",
				Description:    "解码后包含遍历序列",
				Evidence:       "路径: " + decoded,
				Recommendation: "拒绝包含遍历序列的路径",
			})
		}

		for _, sensitive := range a.sensitivePaths {
			if strings.Contains(strings.ToLower(normalized), strings.ToLower(sensitive)) {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    ThreatLevelCritical,
					Pattern:        "sensitive_path_access",
					Description:    "尝试访问敏感路径",
					Evidence:       "敏感路径: " + sensitive,
					Recommendation: "阻止对敏感路径的访问",
				})
			}
		}
	}
}

func (a *PathTraversalAnalyzer) extractPaths(data string) []string {
	var paths []string

	pathPatterns := []string{
		`[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*`,
		`(?:/|^)(?:[^/\0]+/)*[^/\0]*`,
		`\.\./[^&\s]+`,
		`/[^\s]*\.\.[^\s]*`,
		`[^\s]*\.\./[^\s]*`,
		`%2f[^\s]*\.\.[^\s]*`,
		`[^\s]*\.\.%2f[^\s]*`,
	}

	for _, pattern := range pathPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllString(data, -1)
		paths = append(paths, matches...)
	}

	return paths
}

func (a *PathTraversalAnalyzer) decodePath(path string) string {
	decoded := path

	for {
		newDecoded, changed := a.decodeOnce(decoded)
		if !changed {
			break
		}
		decoded = newDecoded
	}

	return decoded
}

func (a *PathTraversalAnalyzer) decodeOnce(path string) (string, bool) {
	hexPattern := regexp.MustCompile(`%([0-9a-fA-F]{2})`)
	matches := hexPattern.FindAllStringSubmatchIndex(path, -1)
	if len(matches) == 0 {
		return path, false
	}

	var sb strings.Builder
	lastEnd := 0
	changed := false

	for _, match := range matches {
		if match[0] > lastEnd {
			sb.WriteString(path[lastEnd:match[0]])
		}
		hexStr := path[match[2]:match[3]]
		r, _ := utf8.DecodeRune([]byte{byte(a.hexToInt(hexStr))})
		sb.WriteRune(r)
		lastEnd = match[1]
		changed = true
	}
	sb.WriteString(path[lastEnd:])
	return sb.String(), changed
}

func (a *PathTraversalAnalyzer) hexToInt(s string) int {
	result := 0
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

func (a *PathTraversalAnalyzer) analyzeSensitivePathAccess(data string, result *AnalysisResult) {
	sensitivePatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)/etc/passwd`, "Unix密码文件", ThreatLevelCritical},
		{`(?i)/etc/shadow`, "Unix影子密码文件", ThreatLevelCritical},
		{`(?i)/etc/hosts`, "主机文件", ThreatLevelHigh},
		{`(?i)/etc/group`, "组文件", ThreatLevelMedium},
		{`(?i)/etc/my\.cnf`, "MySQL配置", ThreatLevelCritical},
		{`(?i)/etc/apache2/`, "Apache配置目录", ThreatLevelCritical},
		{`(?i)/etc/httpd/`, "HTTPd配置目录", ThreatLevelCritical},
		{`(?i)/etc/nginx/`, "Nginx配置目录", ThreatLevelCritical},
		{`(?i)/var/log/`, "日志目录", ThreatLevelHigh},
		{`(?i)/var/www/`, "Web根目录", ThreatLevelHigh},
		{`(?i)/home/`, "用户主目录", ThreatLevelHigh},
		{`(?i)/root/`, "Root主目录", ThreatLevelCritical},
		{`(?i)/\.ssh/`, "SSH目录", ThreatLevelCritical},
		{`(?i)/\.aws/`, "AWS配置", ThreatLevelCritical},
		{`(?i)/\.git/`, "Git仓库", ThreatLevelHigh},
		{`(?i)/\.env`, "环境变量文件", ThreatLevelCritical},
		{`(?i)/proc/self/environ`, "进程环境变量", ThreatLevelCritical},
		{`(?i)/proc/self/cmdline`, "进程命令行", ThreatLevelHigh},
		{`(?i)/proc/version`, "内核版本", ThreatLevelMedium},
		{`(?i)c:\\windows\\`, "Windows目录", ThreatLevelCritical},
		{`(?i)c:\\boot\.ini`, "启动配置", ThreatLevelHigh},
		{`(?i)c:\\Program Files/`, "程序文件目录", ThreatLevelHigh},
		{`(?i)c:\\Users/`, "用户目录", ThreatLevelCritical},
		{`(?i)/boot\.ini`, "Boot配置", ThreatLevelHigh},
		{`(?i)/web\.config`, "Web配置", ThreatLevelHigh},
		{`(?i)/\.htaccess`, "Apache配置", ThreatLevelHigh},
		{`(?i)/config\.php`, "PHP配置", ThreatLevelHigh},
		{`(?i)/wp-config\.php`, "WordPress配置", ThreatLevelHigh},
		{`(?i)/settings\.py`, "Python设置", ThreatLevelHigh},
		{`(?i)/application\.properties`, "Java属性配置", ThreatLevelHigh},
		{`(?i)\.ssh/authorized_keys`, "SSH授权密钥", ThreatLevelCritical},
		{`(?i)\.git/config`, "Git配置", ThreatLevelHigh},
		{`(?i)database\.yml`, "数据库配置", ThreatLevelCritical},
		{`(?i)config\.yaml`, "YAML配置", ThreatLevelHigh},
		{`(?i)secrets\.json`, "密钥JSON", ThreatLevelCritical},
	}

	for _, p := range sensitivePatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "敏感路径访问 - " + p.description,
				Recommendation: "阻止对敏感路径的访问",
			})
		}
	}
}

func (a *PathTraversalAnalyzer) analyzeSolarPathTraversal(data string, result *AnalysisResult) {
	solarPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\.\./\.\./\.\./\.\./\.\./\.\./\.\./`, "深层Unix遍历", ThreatLevelCritical},
		{`(?i)\.\.%c0%af\.\.%c0%af/`, "双编码遍历", ThreatLevelCritical},
		{`(?i)\.\.%c1%9c\.\.%c1%9c/`, "Windows UNC双遍历", ThreatLevelCritical},
		{`(?i)/\.\./\.\./\.\./\.\./`, "Unix多重遍历", ThreatLevelCritical},
		{`(?i)\\?\.\.\?\\\.\.\?\\\.\.`, "Windows ?通配符遍历", ThreatLevelCritical},
		{`(?i)\.\./\.\./\.\./\.\./\.\./\.\./\.\./\.\./`, "超深层遍历", ThreatLevelCritical},
		{`(?i)\.\.%5c\.\.%5c\.\.%5c`, "Windows反斜线多重遍历", ThreatLevelCritical},
		{`(?i)\.\.%252f\.\.%252f`, "多重双重编码遍历", ThreatLevelCritical},
		{`(?i)/\.\.%c0%af/`, "混合编码遍历", ThreatLevelCritical},
		{`(?i)\.\.%c0%af\.\.%c0%af\.\.%c0%af`, "多重曲棍球遍历", ThreatLevelCritical},
		{`(?i)\.\.%c0%ae%c0%ae/`, "Java曲棍球双遍历", ThreatLevelCritical},
		{`(?i)\.\.%u002e%u002e/`, "Unicode双遍历", ThreatLevelCritical},
		{`(?i)\.\.%2500/`, "空字节双遍历", ThreatLevelCritical},
		{`(?i)\.\.%00%00/`, "双空字节遍历", ThreatLevelCritical},
		{`(?i)\.\.%00/`, "单空字节遍历", ThreatLevelCritical},
	}

	for _, p := range solarPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Solar/深层路径遍历 - " + p.description,
				Recommendation: "阻止异常深度路径遍历",
			})
		}
	}
}

func (a *PathTraversalAnalyzer) analyzeWindowsPathTraversal(data string, result *AnalysisResult) {
	windowsPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`[a-zA-Z]:\\`, "Windows绝对路径", ThreatLevelHigh},
		{`[a-zA-Z]:\\\.\.\\`, "Windows双点遍历", ThreatLevelCritical},
		{`[a-zA-Z]:\\{2}[^\\]+\\`, "UNC路径", ThreatLevelHigh},
		{`\\\\`, "UNC路径风格", ThreatLevelHigh},
		{`\.\.\.\.\.\.\.\.`, "多重反斜线双点", ThreatLevelCritical},
		{`\.\.\\\\\\\\`, "超长反斜线遍历", ThreatLevelCritical},
		{`[a-zA-Z]:\\%windir%\\`, "Windows目录遍历", ThreatLevelHigh},
		{`[a-zA-Z]:\\system32\\`, "System32目录", ThreatLevelCritical},
		{`[a-zA-Z]:\\windows\\system`, "Windows系统目录", ThreatLevelCritical},
		{`(?i)c:\\windows\\system32\\cmd\.exe`, "CMD执行", ThreatLevelCritical},
		{`(?i)c:\\windows\\system32\\powershell\.exe`, "PowerShell执行", ThreatLevelCritical},
		{`(?i)\\\\localhost\\`, "UNC本地主机", ThreatLevelMedium},
		{`\\\\127\.0\.0\.1\\`, "UNC IP地址", ThreatLevelMedium},
		{`\\\\\.\.`, "Windows设备命名空间", ThreatLevelHigh},
		{`\\\\\?\\`, "NT命名空间路径", ThreatLevelHigh},
		{`\\\\\?\\UNC\\`, "UNC命名空间", ThreatLevelHigh},
		{`[a-zA-Z]:\\\.\\`, "Windows设备路径", ThreatLevelHigh},
		{`[a-zA-Z]:\\.\.\.\\`, "多重Windows遍历", ThreatLevelCritical},
	}

	for _, p := range windowsPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Windows路径遍历 - " + p.description,
				Recommendation: "阻止Windows路径遍历攻击",
			})
		}
	}
}

func (a *PathTraversalAnalyzer) analyzeWrapperTraversal(data string, result *AnalysisResult) {
	wrapperPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)php://filter/`, "PHP过滤器包装器", ThreatLevelCritical},
		{`(?i)php://input`, "PHP输入包装器", ThreatLevelCritical},
		{`(?i)php://fd/`, "PHP文件描述符", ThreatLevelHigh},
		{`(?i)php://temp/`, "PHP临时文件", ThreatLevelMedium},
		{`(?i)php://memory/`, "PHP内存包装器", ThreatLevelMedium},
		{`(?i)expect://`, "Expect协议包装器", ThreatLevelCritical},
		{`(?i)ogg://`, "Ogg协议包装器", ThreatLevelMedium},
		{`(?i)zlib://`, "Zlib协议包装器", ThreatLevelMedium},
		{`(?i)zip://`, "Zip协议包装器", ThreatLevelHigh},
		{`(?i)data://`, "Data协议包装器", ThreatLevelHigh},
		{`(?i)glob://`, "Glob协议包装器", ThreatLevelMedium},
		{`(?i)phar://`, "Phar协议包装器", ThreatLevelHigh},
		{`(?i)rar://`, "Rar协议包装器", ThreatLevelMedium},
		{`(?i)tar://`, "Tar协议包装器", ThreatLevelMedium},
		{`(?i)zip://`, "Zip文件包装器", ThreatLevelHigh},
		{`(?i)file://\.\./`, "File协议遍历", ThreatLevelCritical},
		{`(?i)file:///etc/`, "File协议敏感路径", ThreatLevelCritical},
		{`(?i)file://c:/`, "File协议Windows路径", ThreatLevelCritical},
		{`(?i)sftp://`, "SFTP协议包装器", ThreatLevelHigh},
		{`(?i)dict://`, "Dict协议包装器", ThreatLevelHigh},
		{`(?i)gopher://`, "Gopher协议包装器", ThreatLevelHigh},
		{`(?i)ldap://`, "LDAP协议包装器", ThreatLevelHigh},
		{`(?i)imap://`, "IMAP协议包装器", ThreatLevelMedium},
		{`(?i)pop3://`, "POP3协议包装器", ThreatLevelMedium},
		{`(?i)smtp://`, "SMTP协议包装器", ThreatLevelMedium},
		{`(?i)http://`, "HTTP协议包装器", ThreatLevelMedium},
		{`(?i)https://`, "HTTPS协议包装器", ThreatLevelMedium},
		{`(?i)jar://`, "Jar协议包装器", ThreatLevelCritical},
		{`(?i)webdav://`, "WebDAV协议包装器", ThreatLevelHigh},
		{`(?i)compress\\.zlib://`, "压缩zlib包装器", ThreatLevelMedium},
		{`(?i)bzip2://`, "Bzip2包装器", ThreatLevelMedium},
	}

	for _, p := range wrapperPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "协议包装器遍历 - " + p.description,
				Recommendation: "禁用危险协议包装器",
			})
		}
	}
}

func (a *PathTraversalAnalyzer) detectPathTraversalInURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}

	path := parsed.Path
	if strings.Contains(path, "..") {
		return true
	}

	query := parsed.RawQuery
	if query != "" {
		if strings.Contains(query, "..") || strings.Contains(query, "%2e%2e") {
			return true
		}
	}

	return false
}
