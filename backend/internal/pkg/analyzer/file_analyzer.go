package analyzer

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

type FilePathAnalyzer struct {
	name         string
	version      string
	analyzerType string
	enabled      bool
	config       map[string]interface{}
	mu           sync.RWMutex
}

func NewFilePathAnalyzer() *FilePathAnalyzer {
	return &FilePathAnalyzer{
		name:         "file_path_analyzer",
		version:      "1.0.0",
		analyzerType: "file_path",
		enabled:      true,
		config:       make(map[string]interface{}),
	}
}

func (a *FilePathAnalyzer) Name() string {
	return a.name
}

func (a *FilePathAnalyzer) Type() string {
	return a.analyzerType
}

func (a *FilePathAnalyzer) Version() string {
	return a.version
}

func (a *FilePathAnalyzer) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

func (a *FilePathAnalyzer) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

func (a *FilePathAnalyzer) Configure(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = config
	return nil
}

func (a *FilePathAnalyzer) Analyze(input *AnalysisInput) *AnalysisResult {
	start := time.Now()
	result := NewAnalysisResult(a)

	if input == nil || input.Raw == "" {
		return result
	}

	dataToAnalyze := a.prepareData(input)

	a.analyzeDirectoryTraversal(dataToAnalyze, result)
	a.analyzePseudoProtocols(dataToAnalyze, result)
	a.analyzeSensitivePaths(dataToAnalyze, result)
	a.analyzeWindowsShortNames(dataToAnalyze, result)
	a.analyzeEncodedTraversal(dataToAnalyze, result)
	a.analyzeNullByteInjection(dataToAnalyze, result)

	result.ProcessingTime = time.Since(start)
	result.ShouldBlock = result.ShouldBlockRequest(0.6)
	if len(result.Matches) > 0 {
		result.ShouldLog = true
		result.ShouldAllow = !result.ShouldBlock
	}

	return result
}

func (a *FilePathAnalyzer) prepareData(input *AnalysisInput) string {
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

func (a *FilePathAnalyzer) analyzeDirectoryTraversal(data string, result *AnalysisResult) {
	traversalPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\.\.[\\/]`, "Directory traversal: ../", ThreatLevelHigh},
		{`\.\.[\\/][\\/]+\.\.`, "Double directory traversal", ThreatLevelCritical},
		{`\.\.[\\/]+\.\.[\\/]`, "Multiple traversal sequences", ThreatLevelCritical},
		{`\.\.\\\.\\`, "Windows directory traversal: ..\\.\\", ThreatLevelHigh},
		{`\.\.[\\/]+\.`, "Traversal ending with dot", ThreatLevelMedium},
		{`\.\.[\\/]+[\\/]`, "Traversal with extra slash", ThreatLevelMedium},
		{`\.\.[\\/]+\.\.[\\/]+\.\.[\\/]`, "Triple nested traversal", ThreatLevelCritical},
		{`[^a-zA-Z]\.\.[\\/]`, "Traversal after non-alpha char", ThreatLevelHigh},
		{`[\\/]\.\.[\\/]`, "Traversal after root path", ThreatLevelHigh},
		{`\.\.[\\/]$`, "Traversal at path end", ThreatLevelMedium},
		{`\.\.%[00](?:[\\/]|$)`, "Traversal with null byte", ThreatLevelCritical},
		{`\.\.[\\/]+\.\.[\\/]+\.\.[\\/]+\.\.[\\/]`, "Quadruple traversal", ThreatLevelCritical},
		{`[^a-zA-Z0-9]\.\.[\\/]`, "Traversal after special char", ThreatLevelHigh},
		{`\.\.[\\/][a-zA-Z]+[\\/]+\.\.[\\/]`, "Traversal with directory name", ThreatLevelHigh},
		{`\.\.[\\/]{2,}`, "Multiple consecutive slashes in traversal", ThreatLevelHigh},
	}

	for _, p := range traversalPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			matches := re.FindAllStringIndex(data, -1)
			for _, match := range matches {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    p.threatLevel,
					Pattern:        p.pattern,
					Position:       match[0],
					Length:         match[1] - match[0],
					Description:    p.description,
					Evidence:       data[match[0]:min(match[1], match[0]+50)],
					Recommendation: "Block directory traversal attempts; validate and sanitize file paths",
				})
			}
		}
	}
}

func (a *FilePathAnalyzer) analyzePseudoProtocols(data string, result *AnalysisResult) {
	protocolPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)file\s*:\s*[\\/]+[\\/]`, "file:// protocol", ThreatLevelHigh},
		{`(?i)php\s*:\s*`, "php:// protocol", ThreatLevelCritical},
		{`(?i)php\s*:\s*input`, "php://input (remote code execution)", ThreatLevelCritical},
		{`(?i)php\s*:\s*filter`, "php://filter (source disclosure)", ThreatLevelCritical},
		{`(?i)php\s*:\s*output`, "php://output", ThreatLevelHigh},
		{`(?i)php\s*:\s*memory`, "php://memory", ThreatLevelMedium},
		{`(?i)php\s*:\s*temp`, "php://temp", ThreatLevelMedium},
		{`(?i)phar\s*:\s*`, "phar:// protocol (archive injection)", ThreatLevelCritical},
		{`(?i)zip\s*:\s*`, "zip:// protocol (archive injection)", ThreatLevelCritical},
		{`(?i)zlib\s*:\s*`, "zlib:// protocol", ThreatLevelHigh},
		{`(?i)bzip2\s*:\s*`, "bzip2:// protocol", ThreatLevelHigh},
		{`(?i)ogg\s*:\s*`, "ogg:// protocol (audio injection)", ThreatLevelMedium},
		{`(?i)http\s*:\s*`, "http:// protocol", ThreatLevelMedium},
		{`(?i)https\s*:\s*`, "https:// protocol", ThreatLevelMedium},
		{`(?i)ftp\s*:\s*`, "ftp:// protocol", ThreatLevelMedium},
		{`(?i)data\s*:\s*`, "data:// protocol (XSS/SSRF)", ThreatLevelCritical},
		{`(?i)data\s*:\s*text/html`, "data:text/html (XSS vector)", ThreatLevelCritical},
		{`(?i)data\s*:\s*image/`, "data:image/ (MIME type smuggling)", ThreatLevelHigh},
		{`(?i)expect\s*:\s*`, "expect:// protocol (command execution)", ThreatLevelCritical},
		{`(?i)glob\s*:\s*`, "glob:// protocol (file discovery)", ThreatLevelHigh},
		{`(?i)phar\s*:\s*[\\/]+`, "phar:// with path traversal", ThreatLevelCritical},
		{`(?i)php\s*:\s*[/\\]+`, "php:// with absolute path attempt", ThreatLevelCritical},
	}

	for _, p := range protocolPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			matches := re.FindAllStringIndex(data, -1)
			for _, match := range matches {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    p.threatLevel,
					Pattern:        p.description,
					Position:       match[0],
					Length:         match[1] - match[0],
					Description:    "Pseudo-protocol detected: " + p.description,
					Evidence:       data[match[0]:min(match[1], match[0]+80)],
					Recommendation: "Block dangerous pseudo-protocols; use whitelist for allowed protocols",
				})
			}
		}
	}
}

func (a *FilePathAnalyzer) analyzeSensitivePaths(data string, result *AnalysisResult) {
	sensitivePathPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)[\\/]etc[\\/]passwd`, "/etc/passwd (user database)", ThreatLevelHigh},
		{`(?i)[\\/]etc[\\/]shadow`, "/etc/shadow (password hashes)", ThreatLevelCritical},
		{`(?i)[\\/]etc[\\/]group`, "/etc/group", ThreatLevelMedium},
		{`(?i)[\\/]etc[\\/]hosts`, "/etc/hosts", ThreatLevelMedium},
		{`(?i)[\\/]etc[\\/]hostname`, "/etc/hostname", ThreatLevelMedium},
		{`(?i)[\\/]etc[\\/]issue`, "/etc/issue (distribution info)", ThreatLevelLow},
		{`(?i)[\\/]etc[\\/]motd`, "/etc/motd (message of the day)", ThreatLevelLow},
		{`(?i)[\\/]etc[\\/]profile`, "/etc/profile", ThreatLevelMedium},
		{`(?i)[\\/]etc[\\/]shells`, "/etc/shells", ThreatLevelMedium},
		{`(?i)[\\/]etc[\\/]cron`, "/etc/cron", ThreatLevelHigh},
		{`(?i)[\\/]etc[\\/]crontab`, "/etc/crontab", ThreatLevelHigh},
		{`(?i)[\\/]var[\\/]log[\\/]`, "/var/log/", ThreatLevelMedium},
		{`(?i)[\\/]var[\\/]www[\\/]`, "/var/www/", ThreatLevelMedium},
		{`(?i)[\\/]home[\\/]`, "/home/", ThreatLevelMedium},
		{`(?i)[\\/]root[\\/]`, "/root/", ThreatLevelHigh},
		{`(?i)[\\/]usr[\\/]bin[\\/]`, "/usr/bin/", ThreatLevelMedium},
		{`(?i)[\\/]usr[\\/]sbin[\\/]`, "/usr/sbin/", ThreatLevelMedium},
		{`(?i)[\\/]bin[\\/]`, "/bin/", ThreatLevelMedium},
		{`(?i)[\\/]sbin[\\/]`, "/sbin/", ThreatLevelMedium},
		{`(?i)[\\/]lib[\\/]`, "/lib/", ThreatLevelMedium},
		{`(?i)[\\/]boot[\\/]ini`, "/boot.ini (Windows boot config)", ThreatLevelHigh},
		{`(?i)[\\/]boot[\\/]bcd`, "BCD store (Windows boot)", ThreatLevelCritical},
		{`(?i)c:\\[\\/]windows[\\/]`, "Windows system directory", ThreatLevelHigh},
		{`(?i)c:\\[\\/]windows[\\/]system32[\\/]`, "Windows System32", ThreatLevelCritical},
		{`(?i)c:\\[\\/]windows[\\/]system[\\/]`, "Windows System", ThreatLevelHigh},
		{`(?i)c:\\[\\/]winnt[\\/]`, "Windows NT directory", ThreatLevelHigh},
		{`(?i)c:\\[\\/]program files[\\/]`, "Program Files", ThreatLevelMedium},
		{`(?i)c:\\[\\/]program data[\\/]`, "Program Data", ThreatLevelMedium},
		{`(?i)c:\\[\\/]users[\\/]`, "Users directory", ThreatLevelMedium},
		{`(?i)c:\\[\\/]documents and settings[\\/]`, "Documents and Settings (XP)", ThreatLevelHigh},
		{`(?i)[\\/]proc[\\/]self[\\/]`, "/proc/self/", ThreatLevelHigh},
		{`(?i)[\\/]proc[\\/]version`, "/proc/version", ThreatLevelMedium},
		{`(?i)[\\/]proc[\\/]cmdline`, "/proc/cmdline", ThreatLevelMedium},
		{`(?i)[\\/]proc[\\/]environ`, "/proc/environ", ThreatLevelHigh},
		{`(?i)[\\/]proc[\\/]fd[\\/]`, "/proc/fd/", ThreatLevelMedium},
		{`(?i)[\\/]dev[\\/]null`, "/dev/null", ThreatLevelLow},
		{`(?i)[\\/]dev[\\/]zero`, "/dev/zero", ThreatLevelMedium},
		{`(?i)[\\/]dev[\\/]urandom`, "/dev/urandom", ThreatLevelLow},
		{`(?i)[\\/]sys[\\/]`, "/sys/ kernel info", ThreatLevelMedium},
		{`(?i)[\\/]tmp[\\/]`, "/tmp/ temporary files", ThreatLevelLow},
		{`(?i)[\\/]var[\\/]tmp[\\/]`, "/var/tmp/", ThreatLevelLow},
		{`(?i)\.ssh[\\/]`, ".ssh directory", ThreatLevelHigh},
		{`(?i)\.bash_history`, ".bash_history", ThreatLevelHigh},
		{`(?i)\.bashrc`, ".bashrc", ThreatLevelMedium},
		{`(?i)\.bash_profile`, ".bash_profile", ThreatLevelMedium},
		{`(?i)\.git[\\/]config`, ".git/config", ThreatLevelMedium},
		{`(?i)\.git[\\/]HEAD`, ".git/HEAD", ThreatLevelMedium},
		{`(?i)\.svn[\\/]`, ".svn directory", ThreatLevelMedium},
		{`(?i)\.htaccess`, ".htaccess file", ThreatLevelHigh},
		{`(?i)\.htpasswd`, ".htpasswd file", ThreatLevelHigh},
		{`(?i)wp-config\.php`, "WordPress config", ThreatLevelCritical},
		{`(?i)config\.php`, "config.php generic", ThreatLevelHigh},
		{`(?i)configuration\.php`, "configuration.php", ThreatLevelHigh},
		{`(?i)database\.php`, "database.php config", ThreatLevelHigh},
		{`(?i)\.env`, ".env file (secrets)", ThreatLevelCritical},
		{`(?i)\.git`, ".git directory", ThreatLevelHigh},
		{`(?i)composer\.json`, "composer.json (dependencies)", ThreatLevelLow},
		{`(?i)package\.json`, "package.json (dependencies)", ThreatLevelLow},
		{`(?i)Dockerfile`, "Dockerfile", ThreatLevelHigh},
		{`(?i)\.dockerignore`, ".dockerignore", ThreatLevelLow},
		{`(?i)docker-compose\.yml`, "docker-compose.yml", ThreatLevelMedium},
	}

	for _, p := range sensitivePathPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			matches := re.FindAllStringIndex(data, -1)
			for _, match := range matches {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    p.threatLevel,
					Pattern:        p.description,
					Position:       match[0],
					Length:         match[1] - match[0],
					Description:    "Sensitive path access: " + p.description,
					Evidence:       data[match[0]:min(match[1], match[0]+100)],
					Recommendation: "Block access to sensitive system files; implement path allowlisting",
				})
			}
		}
	}
}

func (a *FilePathAnalyzer) analyzeWindowsShortNames(data string, result *AnalysisResult) {
	shortNamePatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)PROGRA~1`, "Program Files short name", ThreatLevelHigh},
		{`(?i)PROGRA~2`, "Program Files (x86) short name", ThreatLevelHigh},
		{`(?i)PROGRA~3`, "ProgramData short name", ThreatLevelHigh},
		{`(?i)CONFIG~1`, "Config short name", ThreatLevelHigh},
		{`(?i)SETUP~1`, "Setup short name", ThreatLevelMedium},
		{`(?i)SYSTEM~1`, "System short name", ThreatLevelHigh},
		{`(?i)WINDOWS~1`, "Windows short name", ThreatLevelHigh},
		{`(?i)DOCUME~1`, "Documents short name", ThreatLevelMedium},
		{`(?i)LOCALS~1`, "LocalService short name", ThreatLevelMedium},
		{`(?i)NETWOR~1`, "NetworkService short name", ThreatLevelMedium},
		{`(?i)COMMON~1`, "Common Files short name", ThreatLevelMedium},
		{`(?i)SPECIA~1`, "Special directories", ThreatLevelHigh},
		{`(?i)GLOBAL~1`, "Global settings", ThreatLevelHigh},
		{`(?i)LOCAL~1`, "Local settings", ThreatLevelMedium},
		{`(?i)TEMP~1`, "Temp short name", ThreatLevelLow},
		{`(?i)MSMQ~1`, "MSMQ short name", ThreatLevelMedium},
		{`(?i)INTEL~1`, "Intel directory", ThreatLevelLow},
		{`(?i)AMD64~1`, "AMD64 directory", ThreatLevelLow},
		{`(?i)SYSVOL~1`, "Sysvol short name", ThreatLevelMedium},
		{`(?i)SECURITY~1`, "Security directory", ThreatLevelHigh},
		{`(?i)ADMIN\$`, "Admin share (remote)", ThreatLevelCritical},
		{`(?i)C\$`, "C drive share (remote)", ThreatLevelCritical},
		{`(?i)D\$`, "D drive share (remote)", ThreatLevelCritical},
		{`(?i)IPC\$`, "IPC share (remote)", ThreatLevelHigh},
	}

	for _, p := range shortNamePatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			matches := re.FindAllStringIndex(data, -1)
			for _, match := range matches {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    p.threatLevel,
					Pattern:        p.pattern,
					Position:       match[0],
					Length:         match[1] - match[0],
					Description:    "Windows short name detected: " + p.description,
					Evidence:       data[match[0]:min(match[1], match[0]+50)],
					Recommendation: "Block Windows short name access; disable 8.3 naming convention",
				})
			}
		}
	}
}

func (a *FilePathAnalyzer) analyzeEncodedTraversal(data string, result *AnalysisResult) {
	encodedPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`%2e%2e[\\/]`, "Double encoded: %2e%2e/", ThreatLevelHigh},
		{`%2e%2e%2f`, "Double encoded: %2e%2e%2f", ThreatLevelHigh},
		{`%2e%2e%5c`, "Double encoded: %2e%2e%5c", ThreatLevelHigh},
		{`%252e%252e[\\/]`, "Triple encoded: %252e%252e/", ThreatLevelCritical},
		{`%c0%ae%c0%ae[\\/]`, "Unicode codepoint C0 double dot", ThreatLevelCritical},
		{`%c0%af[\\/]`, "Unicode codepoint C0 slash", ThreatLevelCritical},
		{`%c1%9c[\\/]`, "Unicode codepoint C1 backslash", ThreatLevelCritical},
		{`%c1%9p`, "Unicode codepoint C1 vertical bar", ThreatLevelHigh},
		{`%c1%81`, "Unicode codepoint C1 control", ThreatLevelHigh},
		{`%u002e%u002e[\\/]`, "Unicode UTF-16 double dot", ThreatLevelCritical},
		{`%u2215`, "Unicode division slash", ThreatLevelMedium},
		{`%u2216`, "Unicode set minus", ThreatLevelMedium},
		{`\.\xe2\x88\x95`, "UTF-8 encoded division slash", ThreatLevelMedium},
		{`\.\xe2\x88\x96`, "UTF-8 encoded set minus", ThreatLevelMedium},
		{`\.\x2f`, "Hex encoded forward slash", ThreatLevelMedium},
		{`\.\x5c`, "Hex encoded backslash", ThreatLevelMedium},
		{`\.\%2f`, "Mixed encoding slash", ThreatLevelMedium},
		{`\%2e\%2e`, "Lowercase encoded dots", ThreatLevelHigh},
		{`\%2E\%2E`, "Uppercase encoded dots", ThreatLevelHigh},
		{`\.\.[\x00-\x1f]`, "Control char after dots", ThreatLevelHigh},
		{`\.\.[\x7f-\xff]`, "High ASCII after dots", ThreatLevelMedium},
	}

	for _, p := range encodedPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			matches := re.FindAllStringIndex(data, -1)
			for _, match := range matches {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    p.threatLevel,
					Pattern:        p.description,
					Position:       match[0],
					Length:         match[1] - match[0],
					Description:    "Encoded path traversal: " + p.description,
					Evidence:       data[match[0]:min(match[1], match[0]+60)],
					Recommendation: "Decode all encodings before path validation; normalize paths",
				})
			}
		}
	}
}

func (a *FilePathAnalyzer) analyzeNullByteInjection(data string, result *AnalysisResult) {
	nullBytePatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`%00`, "Null byte injection (URL encoded)", ThreatLevelCritical},
		{`\x00`, "Null byte injection (hex)", ThreatLevelCritical},
		{`\0`, "Octal null byte", ThreatLevelCritical},
		{`[^\x00]*\x00[^\x00]*`, "Null byte in string", ThreatLevelCritical},
		{`%2500`, "Double encoded null byte", ThreatLevelCritical},
		{`\u0000`, "Unicode null byte", ThreatLevelCritical},
		{`%00[\\/]`, "Null byte followed by path sep", ThreatLevelCritical},
		{`%00\.\.`, "Null byte before dots", ThreatLevelCritical},
		{`\x00[\\/]`, "Hex null byte with path", ThreatLevelCritical},
	}

	for _, p := range nullBytePatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			matches := re.FindAllStringIndex(data, -1)
			for _, match := range matches {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    p.threatLevel,
					Pattern:        p.pattern,
					Position:       match[0],
					Length:         match[1] - match[0],
					Description:    "Null byte injection: " + p.description,
					Evidence:       data[match[0]:min(match[1], match[0]+50)],
					Recommendation: "Block null byte injection; validate input encoding strictly",
				})
			}
		}
	}
}
