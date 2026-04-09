package analyzer

import (
	"encoding/base64"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type CommandChainAnalyzer struct {
	name         string
	version      string
	analyzerType string
	enabled      bool
	config       map[string]interface{}
	mu           sync.RWMutex
}

func NewCommandChainAnalyzer() *CommandChainAnalyzer {
	return &CommandChainAnalyzer{
		name:         "command_chain_analyzer",
		version:      "1.0.0",
		analyzerType: "command_chain",
		enabled:      true,
		config:       make(map[string]interface{}),
	}
}

func (a *CommandChainAnalyzer) Name() string {
	return a.name
}

func (a *CommandChainAnalyzer) Type() string {
	return a.analyzerType
}

func (a *CommandChainAnalyzer) Version() string {
	return a.version
}

func (a *CommandChainAnalyzer) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

func (a *CommandChainAnalyzer) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

func (a *CommandChainAnalyzer) Configure(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = config
	return nil
}

func (a *CommandChainAnalyzer) Analyze(input *AnalysisInput) *AnalysisResult {
	start := time.Now()
	result := NewAnalysisResult(a)

	if input == nil || input.Raw == "" {
		return result
	}

	dataToAnalyze := a.prepareData(input)

	a.analyzeCommandSeparators(dataToAnalyze, result)
	a.analyzePipes(dataToAnalyze, result)
	a.analyzeReverseShells(dataToAnalyze, result)
	a.analyzeEncodedCommands(dataToAnalyze, result)
	a.analyzeSystemCommands(dataToAnalyze, result)
	a.analyzeNetworkCommands(dataToAnalyze, result)
	a.analyzeCodeExecutionFunctions(dataToAnalyze, result)
	a.analyzeTrojanDownload(dataToAnalyze, result)

	result.ProcessingTime = time.Since(start)
	result.ShouldBlock = result.ShouldBlockRequest(0.6)
	if len(result.Matches) > 0 {
		result.ShouldLog = true
		result.ShouldAllow = !result.ShouldBlock
	}

	return result
}

func (a *CommandChainAnalyzer) prepareData(input *AnalysisInput) string {
	var sb strings.Builder
	sb.WriteString(input.Raw)
	sb.WriteString(" ")
	sb.WriteString(input.Path)
	sb.WriteString(" ")
	sb.WriteString(input.QueryString)
	sb.WriteString(" ")
	sb.WriteString(input.Body)
	if input.UserAgent != "" {
		sb.WriteString(" ")
		sb.WriteString(input.UserAgent)
	}
	return sb.String()
}

type TokenType int

const (
	TokenUnknown TokenType = iota
	TokenCommand
	TokenSeparator
	TokenPipe
	TokenRedirect
	TokenSubstitution
	TokenQuote
	TokenVariable
)

type Token struct {
	Type     TokenType
	Value    string
	Position int
}

type CommandNode struct {
	Command   string
	Args      []string
	SubNodes  []*CommandNode
	Connector string
}

func (a *CommandChainAnalyzer) analyzeCommandSeparators(data string, result *AnalysisResult) {
	separatorPatterns := []struct {
		pattern     *regexp.Regexp
		separator   string
		description string
		threatLevel ThreatLevel
	}{
		{regexp.MustCompile(`;`), ";", "Semicolon command separator", ThreatLevelMedium},
		{regexp.MustCompile(`&&`), "&&", "AND operator (sequential execution)", ThreatLevelMedium},
		{regexp.MustCompile(`\|\|`), "||", "OR operator (conditional execution)", ThreatLevelMedium},
		{regexp.MustCompile(`&(?!&)`), "&", "Background execution operator", ThreatLevelMedium},
		{regexp.MustCompile(`\|(?!\|)`), "|", "Pipe operator", ThreatLevelMedium},
		{regexp.MustCompile(`>`), ">", "Output redirection (overwrite)", ThreatLevelMedium},
		{regexp.MustCompile(`>>`), ">>", "Output redirection (append)", ThreatLevelMedium},
		{regexp.MustCompile(`<\s*`), "<", "Input redirection", ThreatLevelMedium},
		{regexp.MustCompile(`<<`), "<<", "Here-document operator", ThreatLevelHigh},
		{regexp.MustCompile(`<<-`), "<<-", "Here-document with tab stripping", ThreatLevelHigh},
		{regexp.MustCompile(`2>`), "2>", "Error redirection (stderr)", ThreatLevelMedium},
		{regexp.MustCompile(`2>>`), "2>>", "Error redirection (append)", ThreatLevelMedium},
		{regexp.MustCompile(`>&`), ">&", "Duplication redirection", ThreatLevelMedium},
		{regexp.MustCompile(`<>`), "<>", "Input/output file descriptor", ThreatLevelMedium},
		{regexp.MustCompile(`;\s*;`), ";;", "Case statement terminator", ThreatLevelMedium},
		{regexp.MustCompile(`\||;`), "pipe-semicolon combo", ThreatLevelMedium},
		{regexp.MustCompile(`&\s*;`), "&; combo", ThreatLevelLow},
	}

	for _, p := range separatorPatterns {
		if p.pattern.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.separator,
				Description:    "Command separator detected: " + p.description,
				Recommendation: "Validate input contains no shell metacharacters",
			})
		}
	}
}

func (a *CommandChainAnalyzer) analyzePipes(data string, result *AnalysisResult) {
	pipePatterns := []struct {
		pattern     *regexp.Regexp
		description string
		threatLevel ThreatLevel
	}{
		{regexp.MustCompile(`(?i)\|\s*\w+`), "Pipe to command", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\w+\s*\|\s*\w+`), "Command pipe chain", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\w+\s*\|\s*\w+\s*\|\s*\w+`), "Multi-stage pipe chain", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\|\s*cat\b`), "Pipe to cat", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\|\s*sh\b`), "Pipe to shell", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\|\s*bash\b`), "Pipe to bash", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\|\s*nc\b`), "Pipe to netcat", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)\|\s*ncat\b`), "Pipe to ncat", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)\|\s*python\b`), "Pipe to python", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\|\s*perl\b`), "Pipe to perl", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\|\s*php\b`), "Pipe to php", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\|\s*ruby\b`), "Pipe to ruby", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\|\s*bash\s+-i\b`), "Pipe to interactive bash", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)\|\s*exec\b`), "Pipe to exec", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)tee\b`), "Tee command (read+write)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)xargs\b`), "Xargs command", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\|\s*xargs\b`), "Pipe to xargs", ThreatLevelCritical},
	}

	for _, p := range pipePatterns {
		if p.pattern.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern.String(),
				Description:    "Pipe analysis: " + p.description,
				Recommendation: "Validate piped commands; block suspicious pipe chains",
			})
		}
	}
}

func (a *CommandChainAnalyzer) analyzeReverseShells(data string, result *AnalysisResult) {
	reverseShellPatterns := []struct {
		pattern     *regexp.Regexp
		description string
		threatLevel ThreatLevel
	}{
		{regexp.MustCompile(`(?i)/dev/tcp`), "/dev/tcp pseudo-protocol (bash reverse shell)", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)/dev/udp`), "/dev/udp pseudo-protocol", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)bash\s+-i\b`), "Bash interactive mode", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)bash\s+-i\s+.*/dev/(stdin|stdout|stderr)`), "Bash interactive with device redirect", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)bash\s+-i\s+[<>]?\s*&\d`), "Bash interactive with file descriptor", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)sh\s+-i\b`), "Sh interactive mode", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)nc\s+-e\b`), "Netcat execute mode (-e flag)", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)nc\s+--exec\b`), "Netcat execute mode (--exec flag)", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)nc\s+-c\b`), "Netcat command execution (-c flag)", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)ncat\s+--exec\b`), "Ncat execute mode", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)ncat\s+-e\b`), "Ncat execute mode (-e flag)", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)nc\.exe\s+-e\b`), "Windows netcat execute", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)nc\.exe\s+-c\b`), "Windows netcat command", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)rm\s+/tmp/f\;.*/tmp/f`), "FIFO reverse shell technique", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)/tmp/f.*mkfifo`), "FIFO file creation for reverse shell", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)python.*-c.*import\s+socket`), "Python socket import", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)python3.*-c.*import\s+socket`), "Python3 socket import", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)perl.*-e.*socket`), "Perl socket reverse shell", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)php.*-r.*socket`), "PHP socket reverse shell", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)ruby.*-rsocket`), "Ruby socket require", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)ruby.*-e.*TCPSocket`), "Ruby TCP socket", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)telnet.*\|\s*bash`), "Telnet to bash pipe", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)telnet.*\|.*sh`), "Telnet to shell pipe", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)busybox.*nc.*-e`), "Busybox netcat execute", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)mknod.*/tmp/.*p`), "Named pipe creation for reverse shell", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)curl.*\|.*sh`), "Curl pipe to shell download", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)wget.*\|.*sh`), "Wget pipe to shell download", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)exec\s+\d+.*<>&`), "File descriptor manipulation for shell", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)\d+<>&\d+`), "File descriptor duplication", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)0<&(\d+|-)`), "Input redirection from fd", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)1>&(\d+|-)`), "Output redirection to fd", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)2>&(\d+|-)`), "Error redirection to fd", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\d+>&\d+`), "Bidirectional fd redirection", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)/bin/sh.*-i\b`), "Sh interactive invocation", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)/bin/bash.*-i\b`), "Bash interactive invocation", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)script.*/dev/null`), "Script command with null device", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)socat\s+.*,\fork,`), "Socat fork mode for reverse shell", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)openssl\s+s_client`), "OpenSSL client for encrypted shell", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)powershell.*-nop.*-c`), "PowerShell no-profile command", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)powershell.*-enc\b`), "PowerShell encoded command", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)cmd.*/c\s+`), "Windows cmd with command", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)rzsz`), "RZ/SZ file transfer (potential backdoor)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)busybox\s+\w+\s+--reverse`), "Busybox reverse shell", ThreatLevelCritical},
	}

	for _, p := range reverseShellPatterns {
		if p.pattern.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern.String(),
				Description:    "Reverse shell detected: " + p.description,
				Recommendation: "BLOCK: Detected reverse shell attack pattern",
			})
		}
	}

	a.analyzeObfuscatedReverseShells(data, result)
}

func (a *CommandChainAnalyzer) analyzeObfuscatedReverseShells(data string, result *AnalysisResult) {
	obfuscatedPatterns := []struct {
		pattern     *regexp.Regexp
		description string
		threatLevel ThreatLevel
	}{
		{regexp.MustCompile(`(?i)eval\s*\(\s*base64_decode`), "Base64 decoded eval (obfuscated shell)", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)system\s*\(\s*base64_decode`), "Base64 decoded system()", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)exec\s*\(\s*base64_decode`), "Base64 decoded exec()", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)passthru\s*\(\s*base64_decode`), "Base64 decoded passthru()", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)shell_exec\s*\(\s*base64_decode`), "Base64 decoded shell_exec()", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)assert\s*\(\s*base64_decode`), "Base64 decoded assert()", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)preg_replace.*base64_decode`), "Preg replace with base64 (code injection)", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)str_rot13.*base64_decode`), "Str rot13 + base64 obfuscation", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)gzip.*base64_decode`), "Gzip decompression + base64", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)gzinflate.*base64_decode`), "Gzinflate + base64 obfuscation", ThreatLevelCritical},
		{regexp.MustCompile(`(?i) rawurldecode `), "Raw URL decode obfuscation", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)chr\(.*chr\(`), "Chr concatenation obfuscation", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\\\x[0-9a-f]{2}`), "Hex escape sequence", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\\\d{3}`), "Octal escape sequence", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\$\{.*\}.*\$\{.*\}`), "Variable concatenation obfuscation", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)concat\(.*,.*\)`), "String concat obfuscation", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)implode.*array_map`), "Array map obfuscation", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)create_function`), "Dynamic function creation (code injection)", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)call_user_func`), "Callback function call (code injection)", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)call_user_func_array`), "Callback array call (code injection)", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)forward_static_call`), "Forward static call (code injection)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)register_tick_function`), "Register tick function (potential code execution)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)register_shutdown_function`), "Register shutdown function", ThreatLevelMedium},
	}

	for _, p := range obfuscatedPatterns {
		if p.pattern.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern.String(),
				Description:    "Obfuscated shell detected: " + p.description,
				Recommendation: "BLOCK: Detected obfuscated shell execution pattern",
			})
		}
	}
}

func (a *CommandChainAnalyzer) analyzeEncodedCommands(data string, result *AnalysisResult) {
	a.analyzeURLEncodedCommands(data, result)
	a.analyzeBase64EncodedCommands(data, result)
	a.analyzeHexEncodedCommands(data, result)
	a.analyzeUnicodeEncodedCommands(data, result)
}

func (a *CommandChainAnalyzer) analyzeURLEncodedCommands(data string, result *AnalysisResult) {
	urlEncodedPatterns := []struct {
		pattern     *regexp.Regexp
		description string
		threatLevel ThreatLevel
	}{
		{regexp.MustCompile(`(?i)%3[Bb]`), "URL encoded semicolon (;)", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)%7[Cc]`), "URL encoded pipe (|)", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)%26`), "URL encoded ampersand (&)", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)%24`), "URL encoded dollar ($)", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)%60`), "URL encoded backtick (`)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)%28`), "URL encoded open parenthesis", ThreatLevelLow},
		{regexp.MustCompile(`(?i)%29`), "URL encoded close parenthesis", ThreatLevelLow},
		{regexp.MustCompile(`(?i)%3[Ee]`), "URL encoded greater than (>)", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)%3[Cc]`), "URL encoded less than (<)", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)%0[Dd]%0[Aa]`), "URL encoded CRLF injection", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)%0[Aa]`), "URL encoded newline (\\n)", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)%0[Dd]`), "URL encoded carriage return (\\r)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)%00`), "URL encoded null byte", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)%09`), "URL encoded tab", ThreatLevelLow},
		{regexp.MustCompile(`(?i)%2[Ff]`), "URL encoded forward slash (/)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)%5[Cc]`), "URL encoded backslash (\\\\)", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)%20`), "URL encoded space", ThreatLevelLow},
		{regexp.MustCompile(`(?i)%3[Dd]`), "URL encoded equals (=)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)%21`), "URL encoded exclamation (!)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)%7[Bb]`), "URL encoded open brace ({)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)%7[Dd]`), "URL encoded close brace (})", ThreatLevelLow},
		{regexp.MustCompile(`(?i)%5[Bb]`), "URL encoded open bracket ([)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)%5[Dd]`), "URL encoded close bracket (])", ThreatLevelLow},
		{regexp.MustCompile(`(?i)%3[Cc]%3[Ee]`), "URL encoded <> (XSS vector)", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)%2e%2e%2f`), "Double encoded path traversal (/../)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)%2e%2e\/`), "Double encoded ../", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)%252e%252e%252f`), "Triple encoded path traversal", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)%c0%ae`), "Unicode codepoint C0 byte (path traversal)", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)%c1%9c`), "Unicode codepoint C1 byte (path traversal)", ThreatLevelCritical},
	}

	for _, p := range urlEncodedPatterns {
		if p.pattern.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern.String(),
				Description:    "URL encoded command: " + p.description,
				Recommendation: "Decode URL encoding before validation",
			})
		}
	}

	decodedData, _ := url.QueryUnescape(data)
	if decodedData != data && decodedData != "" {
		a.checkDecodedForThreats(decodedData, result, "URL")
	}
}

func (a *CommandChainAnalyzer) analyzeBase64EncodedCommands(data string, result *AnalysisResult) {
	base64Patterns := []struct {
		pattern     *regexp.Regexp
		description string
		threatLevel ThreatLevel
	}{
		{regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`), "Potential base64 string", ThreatLevelLow},
		{regexp.MustCompile(`(?i)base64_decode\s*\(`), "Base64 decode function call", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)base64_encode\s*\(`), "Base64 encode function call", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)frombase64string`), "FromBase64String (.NET)", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)convert\.frombase64string`), ".NET Base64 conversion", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)atob\s*\(`), "Atob function (JS base64 decode)", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)btoa\s*\(`), "Btoa function (JS base64 encode)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)openssl_decrypt.*base64`), "OpenSSL decrypt with base64", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)mcrypt.*base64`), "MCrypt with base64", ThreatLevelHigh},
	}

	for _, p := range base64Patterns {
		if p.pattern.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern.String(),
				Description:    "Base64 encoding detected: " + p.description,
				Recommendation: "Decode and validate base64 content",
			})
		}
	}

	base64Regex := regexp.MustCompile(`([A-Za-z0-9+/]{16,}={0,2})`)
	matches := base64Regex.FindAllString(data, -1)
	for _, match := range matches {
		if decoded, err := base64.StdEncoding.DecodeString(match); err == nil {
			if utf8.Valid(decoded) {
				decodedStr := string(decoded)
				a.checkDecodedForThreats(decodedStr, result, "Base64")
			}
		}
	}
}

func (a *CommandChainAnalyzer) analyzeHexEncodedCommands(data string, result *AnalysisResult) {
	hexPatterns := []struct {
		pattern     *regexp.Regexp
		description string
		threatLevel ThreatLevel
	}{
		{regexp.MustCompile(`\\x[0-9a-fA-F]{2}`), "Hex escape sequence (\\\\x)", ThreatLevelMedium},
		{regexp.MustCompile(`0x[0-9a-fA-F]+`), "Hex number literal", ThreatLevelLow},
		{regexp.MustCompile(`\\x{.*?}`), "Hex brace escape", ThreatLevelMedium},
		{regexp.MustCompile(`(?:[0-9a-fA-F]{2}){4,}`), "Multi-byte hex sequence", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)chr\s*\(\s*0x`), "PHP hex chr()", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)chr\s*\(\s*\d+`), "PHP chr() with decimal", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)dechex\s*\(`), "PHP dechex() (decimal to hex)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)hex2bin\s*\(`), "PHP hex2bin() function", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)pack\s*\('H\*'`), "PHP pack with H* format", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)unpack\s*\('H\*'`), "PHP unpack with H* format", ThreatLevelMedium},
	}

	for _, p := range hexPatterns {
		if p.pattern.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern.String(),
				Description:    "Hex encoding detected: " + p.description,
				Recommendation: "Decode hex encoding before validation",
			})
		}
	}

	hexEscapeRegex := regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	matches := hexEscapeRegex.FindAllStringSubmatch(data, -1)
	for _, match := range matches {
		if len(match) > 1 {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelMedium,
				Pattern:        match[0],
				Description:    "Hex escape: " + match[1],
				Recommendation: "Validate hex escaped content",
			})
		}
	}
}

func (a *CommandChainAnalyzer) analyzeUnicodeEncodedCommands(data string, result *AnalysisResult) {
	unicodePatterns := []struct {
		pattern     *regexp.Regexp
		description string
		threatLevel ThreatLevel
	}{
		{regexp.MustCompile(`\\u[0-9a-fA-F]{4}`), "Unicode escape (4 digits)", ThreatLevelMedium},
		{regexp.MustCompile(`\\U[0-9a-fA-F]{8}`), "Unicode escape (8 digits)", ThreatLevelMedium},
		{regexp.MustCompile(`&#x[0-9a-fA-F]+;`), "HTML/XML hex entity", ThreatLevelMedium},
		{regexp.MustCompile(`&#\d+;`), "HTML/XML decimal entity", ThreatLevelMedium},
		{regexp.MustCompile(`%u[0-9a-fA-F]{4}`), "Unicode percent encoding", ThreatLevelHigh},
		{regexp.MustCompile(`\\N\{.*?\}`), "Unicode named character", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)c2%A0`), "Non-breaking space (bypass)", ThreatLevelHigh},
	}

	for _, p := range unicodePatterns {
		if p.pattern.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern.String(),
				Description:    "Unicode encoding detected: " + p.description,
				Recommendation: "Normalize unicode encoding before validation",
			})
		}
	}
}

func (a *CommandChainAnalyzer) checkDecodedForThreats(decoded string, result *AnalysisResult, encodingType string) {
	criticalPatterns := []struct {
		pattern     *regexp.Regexp
		description string
		threatLevel ThreatLevel
	}{
		{regexp.MustCompile(`(?i)/dev/tcp`), "Reverse shell /dev/tcp", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)bash\s+-i`), "Interactive bash", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)nc\s+-e`), "Netcat execute", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)ncat\s+--exec`), "Ncat execute", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)curl.*\|.*sh`), "Curl pipe to shell", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)wget.*\|.*sh`), "Wget pipe to shell", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)python.*socket`), "Python socket", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)system\s*\(`), "System function call", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)exec\s*\(`), "Exec function call", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)passthru\s*\(`), "Passthru function call", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)shell_exec\s*\(`), "Shell exec function call", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)popen\s*\(`), "Popen function call", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)proc_open\s*\(`), "Proc open function call", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)<\?php.*eval`), "PHP eval injection", ThreatLevelCritical},
	}

	for _, p := range criticalPatterns {
		if p.pattern.MatchString(decoded) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        encodingType + " decoded: " + p.pattern.String(),
				Description:    "Threat found in decoded " + encodingType + ": " + p.description,
				Recommendation: "BLOCK: Malicious content detected after " + encodingType + " decoding",
			})
		}
	}
}

func (a *CommandChainAnalyzer) analyzeSystemCommands(data string, result *AnalysisResult) {
	systemCommands := []struct {
		pattern     *regexp.Regexp
		description string
		threatLevel ThreatLevel
	}{
		{regexp.MustCompile(`(?i)\bls\b`), "ls command (list directory)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bls\s+-la\b`), "ls -la (list all files)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bls\s+-l\b`), "ls -l (long format)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bcat\b`), "cat command (read file)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bcd\b`), "cd command (change directory)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bpwd\b`), "pwd command (print working directory)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bmkdir\b`), "mkdir command (create directory)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bmkdir\s+-p\b`), "mkdir -p (create nested directories)", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\brmdir\b`), "rmdir command (remove directory)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\brm\b`), "rm command (remove file)", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\brm\s+-rf\b`), "rm -rf (recursive force delete)", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)\bcp\b`), "cp command (copy file)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bmv\b`), "mv command (move file)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bchmod\b`), "chmod command (change permissions)", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\bchown\b`), "chown command (change owner)", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\bchgrp\b`), "chgrp command (change group)", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\btouch\b`), "touch command (create file)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bln\b`), "ln command (create link)", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\bln\s+-s\b`), "ln -s (create symbolic link)", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\breadlink\b`), "readlink command", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bstat\b`), "stat command (file info)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bfile\b`), "file command (file type)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bwc\b`), "wc command (word count)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bhead\b`), "head command (file beginning)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\btail\b`), "tail command (file end)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bmore\b`), "more command (paged view)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bless\b`), "less command", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bsort\b`), "sort command", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\buniq\b`), "uniq command", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bcut\b`), "cut command", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bawk\b`), "awk command (text processing)", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\bsed\b`), "sed command (stream editor)", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\bgrep\b`), "grep command (pattern search)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\begrep\b`), "egrep command (extended grep)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bfgrep\b`), "fgrep command (fixed grep)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bfind\b`), "find command", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\bwhich\b`), "which command (locate binary)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bwhereis\b`), "whereis command", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\btype\b`), "type command (command type)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bdirname\b`), "dirname command", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bbasename\b`), "basename command", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bdd\b`), "dd command (raw copy)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bmknod\b`), "mknod command (create device)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bmkfifo\b`), "mkfifo command (create FIFO)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\binotifywait\b`), "inotifywait (file monitor)", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\bstrace\b`), "strace (system call trace)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bltrace\b`), "ltrace (library call trace)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\blsof\b`), "lsof (list open files)", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\bfuser\b`), "fuser (process/file info)", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\bcrontab\b`), "crontab command", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bat\b`), "at command (scheduled task)", ThreatLevelHigh},
	}

	for _, p := range systemCommands {
		if p.pattern.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern.String(),
				Description:    "System command detected: " + p.description,
				Recommendation: "Validate system command usage",
			})
		}
	}
}

func (a *CommandChainAnalyzer) analyzeNetworkCommands(data string, result *AnalysisResult) {
	networkCommands := []struct {
		pattern     *regexp.Regexp
		description string
		threatLevel ThreatLevel
	}{
		{regexp.MustCompile(`(?i)\bwget\b`), "wget command (file download)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bwget\s+.*\s+-O\b`), "wget with output file", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bwget\s+.*\s+--output-document\b`), "wget with output document", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bwget\s+.*\s+-o\b`), "wget with log file", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\bcurl\b`), "curl command (HTTP client)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bcurl\s+.*\s+-o\b`), "curl with output file", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bcurl\s+.*\s+--output\b`), "curl with output option", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bcurl\s+.*\s+-T\b`), "curl file upload", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bnc\b`), "netcat command", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bnc\s+-l\b`), "netcat listener mode", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)\bnc\s+-p\b`), "netcat with port", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)\bnc\s+-e\b`), "netcat execute mode", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)\bncat\b`), "ncat command", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bncat\s+--ssl\b`), "ncat with SSL", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\btelnet\b`), "telnet command", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bssh\b`), "ssh command", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bssh\s+-p\b`), "ssh with port", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bscp\b`), "scp command (secure copy)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bsftp\b`), "sftp command (secure FTP)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bftp\b`), "ftp command", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\bping\b`), "ping command", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bping\s+-c\b`), "ping with count", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bifconfig\b`), "ifconfig (network config)", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\bip\s+addr\b`), "ip address command", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\bip\s+link\b`), "ip link command", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\bip\s+route\b`), "ip route command", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\bnetstat\b`), "netstat (network statistics)", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\bnetstat\s+-an\b`), "netstat all numeric", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\bss\s+-t\b`), "socket statistics TCP", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\bss\s+-u\b`), "socket statistics UDP", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\bnmap\b`), "nmap port scanner", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)\bnmap\s+-sS\b`), "nmap SYN scan", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)\bnmap\s+-sT\b`), "nmap TCP scan", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)\nnmap\s+-O\b`), "nmap OS detection", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)\bnmap\s+-A\b`), "nmap aggressive scan", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)\btraceroute\b`), "traceroute command", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\btracepath\b`), "tracepath command", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\btracert\b`), "tracert (Windows)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bpathping\b`), "pathping (Windows)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bnslookup\b`), "nslookup (DNS query)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bdig\b`), "dig (DNS query)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bhost\b`), "host (DNS query)", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\bwhois\b`), "whois lookup", ThreatLevelLow},
		{regexp.MustCompile(`(?i)\biptables\b`), "iptables (firewall)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bip6tables\b`), "ip6tables (IPv6 firewall)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bfirewalld\b`), "firewalld (firewall daemon)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bufw\b`), "ufw (uncomplicated firewall)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bsystemctl\b`), "systemctl (service manager)", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\bservice\b`), "service command", ThreatLevelMedium},
	}

	for _, p := range networkCommands {
		if p.pattern.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern.String(),
				Description:    "Network command detected: " + p.description,
				Recommendation: "Validate network command usage",
			})
		}
	}
}

func (a *CommandChainAnalyzer) analyzeCodeExecutionFunctions(data string, result *AnalysisResult) {
	codeExecFunctions := []struct {
		pattern     *regexp.Regexp
		description string
		threatLevel ThreatLevel
	}{
		{regexp.MustCompile(`(?i)\bsystem\s*\(`), "PHP system() function", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bexec\s*\(`), "PHP exec() function", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bpassthru\s*\(`), "PHP passthru() function", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bshell_exec\s*\(`), "PHP shell_exec() function", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bpopen\s*\(`), "PHP popen() function", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bproc_open\s*\(`), "PHP proc_open() function", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bpcntl_exec\s*\(`), "PHP pcntl_exec() function", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)\beval\s*\(`), "PHP eval() function", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)\bassert\s*\(`), "PHP assert() function", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)\bpreg_replace.*e`), "PHP preg_replace with /e modifier", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)\bcreate_function\s*\(`), "PHP create_function()", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)\bcall_user_func\s*\(`), "PHP call_user_func()", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bcall_user_func_array\s*\(`), "PHP call_user_func_array()", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bunserialize\s*\(`), "PHP unserialize()", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\binclude\s*\(`), "PHP include()", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\binclude_once\s*\(`), "PHP include_once()", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\brequire\s*\(`), "PHP require()", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\brequire_once\s*\(`), "PHP require_once()", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\bVirtualAlloc`), "Windows VirtualAlloc (memory allocation)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bVirtualProtect`), "Windows VirtualProtect (memory protection)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bCreateRemoteThread`), "Windows CreateRemoteThread (process injection)", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)\bWriteProcessMemory`), "Windows WriteProcessMemory", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)\bReadProcessMemory`), "Windows ReadProcessMemory", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bWinExec`), "Windows WinExec (execute program)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bShellExecute`), "Windows ShellExecute", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bruntime\.exec`), "Java Runtime.exec()", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bprocessbuilder\s*\(`), "Java ProcessBuilder", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bjavascript:eval`), "JavaScript eval in URL", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)\beval\s*\(\s*atob`), "JavaScript eval(atob()) obfuscation", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)\bFunction\s*\(`), "JavaScript Function() constructor", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bsetTimeout\s*\(.*,0\)`), "JavaScript setTimeout(,0)", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\bsetInterval\s*\(.*,0\)`), "JavaScript setInterval(,0)", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)\bexec\s*\(`), "Python exec()", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)\beval\s*\(`), "Python eval()", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)\bos\.system\s*\(`), "Python os.system()", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bos\.popen\s*\(`), "Python os.popen()", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bsubprocess\.call\s*\(`), "Python subprocess.call()", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bsubprocess\.run\s*\(`), "Python subprocess.run()", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bsubprocess\.Popen\s*\(`), "Python subprocess.Popen()", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bplatform\.os\.popen\s*\(`), "Python platform.os.popen()", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bexec\s*\(`), "Ruby exec()", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)\bsystem\s*\(`), "Ruby system()", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)` + "`" + `.*` + "`"), "Ruby backtick execution", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)%x\{.*\}`), "Ruby %x{} execution", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)\bopen\s*\([^)]*\|`), "Ruby open with pipe", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)\beval\s*\(`), "Perl eval()", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)\bsystem\s*\(`), "Perl system()", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bexec\s*\(`), "Perl exec()", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bopen\s*\(`), "Perl open() (file/shell)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bUse.*Win32::`), "Perl Win32 module", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\bProcess::`), "Perl Process module", ThreatLevelHigh},
	}

	for _, p := range codeExecFunctions {
		if p.pattern.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern.String(),
				Description:    "Code execution function detected: " + p.description,
				Recommendation: "Block dangerous code execution functions in user input",
			})
		}
	}
}

func (a *CommandChainAnalyzer) analyzeTrojanDownload(data string, result *AnalysisResult) {
	trojanPatterns := []struct {
		pattern     *regexp.Regexp
		description string
		threatLevel ThreatLevel
	}{
		{regexp.MustCompile(`(?i)powershell.*webclient`), "PowerShell WebClient download", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)powershell.*downloadfile`), "PowerShell DownloadFile", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)powershell.*downloadstring`), "PowerShell DownloadString", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)powershell.*invoke-webrequest`), "PowerShell Invoke-WebRequest", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)powershell.*invoke-restmethod`), "PowerShell Invoke-RestMethod", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)powershell.*bitsadmin`), "PowerShell/BitsAdmin download", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)bitsadmin\s+/transfer`), "BitsAdmin transfer", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)certutil.*-urlcache`), "CertUtil URL cache (download)", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)certutil.*-decode`), "CertUtil decode", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)certutil.*-encode`), "CertUtil encode", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)mshta.*http`), "MSHTA with HTTP (HT A execution)", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)mshta.*vbscript`), "MSHTA with VBScript", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)mshta.*javascript`), "MSHTA with JavaScript", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)wscript.*http`), "WScript with HTTP", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)cscript.*http`), "CScript with HTTP", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)rundll32.*http`), "Rundll32 with HTTP", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)regsvr32.*http`), "Regsvr32 with HTTP (Squiblydoo)", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)regsvr32.*/s.*/n.*/u`), "Regsvr32 with bypass flags", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)msiexec.*http`), "Msiexec with HTTP", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)cmstp.*http`), "CMSTP with HTTP", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)mobaxterm`), "MobaXterm (terminal emulator with FTP/SFTP)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)putty`), "PuTTY (SSH client with PSCP/PSFTP)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)pscp`), "PSCP (PuTTY SCP)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)psftp`), "PSFTP (PuTTY SFTP)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)plink`), "Plink (PuTTY link)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)winscp`), "WinSCP (SFTP/SCP client)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)filezilla`), "FileZilla (FTP client)", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)fetch`), "Fetch (macOS FTP/SFTP)", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)scp`), "SCP command (secure copy)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)sftp`), "SFTP command", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)tftp`), "TFTP command (trivial FTP)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)ftp.*-e`), "FTP with execute", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)ftp.*-s:`), "FTP with script file", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)vbscript.*download`), "VBScript download", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)echo.*>.*\.vbs`), "VBScript file creation via echo", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)echo.*>.*\.bat`), "Batch file creation via echo", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)echo.*>.*\.ps1`), "PowerShell file creation via echo", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)echo.*>.*\.scr`), "Screensaver file (possible malware)", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)echo.*>.*\.exe`), "Executable file creation", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)echo.*>.*\.dll`), "DLL file creation", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)type.*>.*\.exe`), "Binary file creation via type", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)certutil.*-f.*-p.*`), "CertUtil with force and password", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)curl.*-o.*\.exe`), "Curl download to exe", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)wget.*-O.*\.exe`), "Wget download to exe", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)powershell.*-EncodedCommand`), "PowerShell EncodedCommand", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)powershell.*-nop.*-w\s+hidden`), "PowerShell no-profile hidden window", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)powershell.*-windowstyle\s+hidden`), "PowerShell hidden window", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)powershell.*-b\s+NoProfile`), "PowerShell no profile", ThreatLevelCritical},
	}

	for _, p := range trojanPatterns {
		if p.pattern.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern.String(),
				Description:    "Trojan download behavior detected: " + p.description,
				Recommendation: "BLOCK: Detected malware download or trojan execution pattern",
			})
		}
	}
}
