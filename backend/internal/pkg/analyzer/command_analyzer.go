package analyzer

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

type CommandInjectionAnalyzer struct {
	name         string
	version      string
	analyzerType string
	enabled      bool
	config       map[string]interface{}
	mu           sync.RWMutex
}

func NewCommandInjectionAnalyzer() *CommandInjectionAnalyzer {
	return &CommandInjectionAnalyzer{
		name:         "command_injection_analyzer",
		version:      "1.0.0",
		analyzerType: "command_injection",
		enabled:      true,
		config:       make(map[string]interface{}),
	}
}

func (a *CommandInjectionAnalyzer) Name() string {
	return a.name
}

func (a *CommandInjectionAnalyzer) Type() string {
	return a.analyzerType
}

func (a *CommandInjectionAnalyzer) Version() string {
	return a.version
}

func (a *CommandInjectionAnalyzer) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

func (a *CommandInjectionAnalyzer) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

func (a *CommandInjectionAnalyzer) Configure(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = config
	return nil
}

func (a *CommandInjectionAnalyzer) Analyze(input *AnalysisInput) *AnalysisResult {
	start := time.Now()
	result := NewAnalysisResult(a)

	if input == nil || input.Raw == "" {
		return result
	}

	dataToAnalyze := a.prepareData(input)

	a.analyzeShellOperators(dataToAnalyze, result)
	a.analyzeCommandChaining(dataToAnalyze, result)
	a.analyzeSubstitution(dataToAnalyze, result)
	a.analyzeRedirection(dataToAnalyze, result)
	a.analyzeNetworkDiscovery(dataToAnalyze, result)
	a.analyzeFileOperations(dataToAnalyze, result)
	a.analyzeProcessManipulation(dataToAnalyze, result)
	a.analyzeEncodedCommands(dataToAnalyze, result)
	a.analyzeDangerousCommands(dataToAnalyze, result)
	a.analyzeEnvironmentManipulation(dataToAnalyze, result)

	result.ProcessingTime = time.Since(start)
	result.ShouldBlock = result.ShouldBlockRequest(0.65)
	if len(result.Matches) > 0 {
		result.ShouldLog = true
		result.ShouldAllow = !result.ShouldBlock
	}

	return result
}

func (a *CommandInjectionAnalyzer) prepareData(input *AnalysisInput) string {
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

func (a *CommandInjectionAnalyzer) analyzeShellOperators(data string, result *AnalysisResult) {
	operatorPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`;`, "Semicolon command separator", ThreatLevelHigh},
		{`|`, "Pipe operator", ThreatLevelHigh},
		{`\|\|`, "OR operator (second command runs if first fails)", ThreatLevelHigh},
		{`&&`, "AND operator (second command runs if first succeeds)", ThreatLevelHigh},
		{`&`, "Background execution operator", ThreatLevelMedium},
		{`\n`, "Newline (command separator in some contexts)", ThreatLevelMedium},
		{`0<&`, "Input redirection", ThreatLevelMedium},
		{`0>&`, "Output redirection", ThreatLevelMedium},
		{`>&`, "Redirect stdout and stderr", ThreatLevelMedium},
		{`<>`, "Input/output file descriptor", ThreatLevelMedium},
		{`;;`, "Case statement terminator (bash)", ThreatLevelMedium},
		{`|;`, "Pipe followed by semicolon", ThreatLevelHigh},
		{`&;`, "Background followed by semicolon", ThreatLevelMedium},
	}

	for _, p := range operatorPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Shell operator detected: " + p.description,
				Recommendation: "Validate input contains no shell metacharacters",
			})
		}
	}
}

func (a *CommandInjectionAnalyzer) analyzeCommandChaining(data string, result *AnalysisResult) {
	chainingPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i);\s*cat\b`, "Chaining with cat command", ThreatLevelHigh},
		{`(?i);\s*ls\b`, "Chaining with ls command", ThreatLevelMedium},
		{`(?i);\s*wget\b`, "Chaining with wget (file download)", ThreatLevelCritical},
		{`(?i);\s*curl\b`, "Chaining with curl (file download)", ThreatLevelCritical},
		{`(?i);\s*bash\b`, "Chaining with bash shell", ThreatLevelCritical},
		{`(?i);\s*sh\b`, "Chaining with sh shell", ThreatLevelCritical},
		{`(?i);\s*python\b`, "Chaining with python interpreter", ThreatLevelHigh},
		{`(?i);\s*perl\b`, "Chaining with perl interpreter", ThreatLevelHigh},
		{`(?i);\s*php\b`, "Chaining with php interpreter", ThreatLevelHigh},
		{`(?i);\s*ruby\b`, "Chaining with ruby interpreter", ThreatLevelHigh},
		{`(?i);\s*nc\b`, "Chaining with netcat", ThreatLevelCritical},
		{`(?i);\s*ncat\b`, "Chaining with ncat", ThreatLevelCritical},
		{`(?i);\s*rm\b`, "Chaining with rm (file deletion)", ThreatLevelHigh},
		{`(?i);\s*mkdir\b`, "Chaining with mkdir", ThreatLevelMedium},
		{`(?i);\s*chmod\b`, "Chaining with chmod", ThreatLevelHigh},
		{`(?i);\s*chown\b`, "Chaining with chown", ThreatLevelHigh},
		{`(?i);\s*mv\b`, "Chaining with mv (file move)", ThreatLevelMedium},
		{`(?i);\s*cp\b`, "Chaining with cp (file copy)", ThreatLevelMedium},
		{`(?i);\s*dd\b`, "Chaining with dd (raw disk operation)", ThreatLevelCritical},
		{`(?i);\s*mkfs\b`, "Chaining with mkfs (filesystem creation)", ThreatLevelCritical},
		{`(?i);\s*mount\b`, "Chaining with mount", ThreatLevelCritical},
		{`(?i);\s*umount\b`, "Chaining with umount", ThreatLevelHigh},
		{`(?i);\s*reboot\b`, "Chaining with reboot (system restart)", ThreatLevelCritical},
		{`(?i);\s*shutdown\b`, "Chaining with shutdown", ThreatLevelCritical},
		{`(?i);\s*init\b`, "Chaining with init (service manager)", ThreatLevelCritical},
		{`(?i);\s*systemctl\b`, "Chaining with systemctl", ThreatLevelCritical},
		{`(?i);\s*service\b`, "Chaining with service", ThreatLevelCritical},
		{`(?i);\s*yum\b`, "Chaining with yum (package manager)", ThreatLevelCritical},
		{`(?i);\s*apt\b`, "Chaining with apt (package manager)", ThreatLevelCritical},
		{`(?i);\s*apt-get\b`, "Chaining with apt-get", ThreatLevelCritical},
		{`(?i);\s*dpkg\b`, "Chaining with dpkg", ThreatLevelCritical},
		{`(?i);\s*rpm\b`, "Chaining with rpm", ThreatLevelCritical},
		{`(?i);\s*pip\b`, "Chaining with pip (Python packages)", ThreatLevelHigh},
		{`(?i);\s*npm\b`, "Chaining with npm", ThreatLevelHigh},
		{`(?i);\s*gem\b`, "Chaining with gem (Ruby packages)", ThreatLevelHigh},
		{`(?i);\s*composer\b`, "Chaining with composer (PHP packages)", ThreatLevelHigh},
	}

	for _, p := range chainingPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.description,
				Description:    "Command chaining detected: " + p.description,
				Evidence:       p.pattern,
				Recommendation: "Block command chaining; use parameterized commands only",
			})
		}
	}
}

func (a *CommandInjectionAnalyzer) analyzeSubstitution(data string, result *AnalysisResult) {
	substitutionPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{"`[^`]+`", "Backtick command substitution", ThreatLevelCritical},
		{"\\$\\([^)]+\\)", "Dollar-parenthesis command substitution", ThreatLevelCritical},
		{"\\$\\{[^}]+\\}", "Brace expansion / indirect variable", ThreatLevelMedium},
		{"\\$\\w+", "Simple variable expansion", ThreatLevelMedium},
		{"\\$\\(", "Unclosed command substitution", ThreatLevelHigh},
		{"`", "Lone backtick", ThreatLevelMedium},
		{"\\$\\(\\)", "Empty command substitution", ThreatLevelLow},
		{"\\$\\{", "Unclosed brace expansion", ThreatLevelMedium},
		{"\\$\\(\\(.*\\)\\)", "Arithmetic expansion with command", ThreatLevelHigh},
		{"\\$[{(]", "Variable expansion prefix without closing", ThreatLevelMedium},
	}

	for _, p := range substitutionPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Command substitution detected: " + p.description,
				Recommendation: "Escape or remove command substitution syntax",
			})
		}
	}

	commandInSubst := regexp.MustCompile(`(?i)\$\([^)]*(?:cat|ls|dir|wget|curl|bash|sh|nc|rm|mkdir)\b`)
	if commandInSubst.MatchString(data) {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelCritical,
			Pattern:        "command_in_substitution",
			Description:    "Dangerous command inside substitution",
			Recommendation: "Block request - dangerous command injection via substitution",
		})
	}
}

func (a *CommandInjectionAnalyzer) analyzeRedirection(data string, result *AnalysisResult) {
	redirectionPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`>\s*/`, "Output redirection to root (overwrite)", ThreatLevelCritical},
		{`>>\s*/`, "Output redirection to root (append)", ThreatLevelCritical},
		{`<\s*/dev/`, "Input from /dev/", ThreatLevelHigh},
		{`>\s*/etc/`, "Output to /etc/", ThreatLevelCritical},
		{`>\s*/var/`, "Output to /var/", ThreatLevelHigh},
		{`>\s*/tmp/`, "Output to /tmp/", ThreatLevelMedium},
		{`>\s*/proc/`, "Output to /proc/", ThreatLevelCritical},
		{`2>&1`, "Redirect stderr to stdout", ThreatLevelMedium},
		{`1>&2`, "Redirect stdout to stderr", ThreatLevelMedium},
		{`&>&`, "Combined redirection", ThreatLevelMedium},
		{`>|`, "Forceful redirection (noclobber)", ThreatLevelMedium},
		{`>>`, "Append operator", ThreatLevelMedium},
		{`>&`, "Redirect with ampersand", ThreatLevelMedium},
		{`<<`, "Here-document operator", ThreatLevelHigh},
		{`<<-`, "Here-document with tab stripping", ThreatLevelHigh},
		{`<&`, "Input duplication", ThreatLevelMedium},
		{`>\s*\.`, "Output to hidden file", ThreatLevelMedium},
		{`\s/bin/`, "Reference to /bin/", ThreatLevelMedium},
		{`\s/usr/bin/`, "Reference to /usr/bin/", ThreatLevelMedium},
		{`\s/sbin/`, "Reference to /sbin/", ThreatLevelMedium},
	}

	for _, p := range redirectionPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Redirection detected: " + p.description,
				Recommendation: "Block redirection to sensitive paths",
			})
		}
	}
}

func (a *CommandInjectionAnalyzer) analyzeNetworkDiscovery(data string, result *AnalysisResult) {
	networkPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\bping\b`, "Ping command (reachability check)", ThreatLevelMedium},
		{`(?i)\bping\s+-c\b`, "Ping with count option", ThreatLevelMedium},
		{`(?i)\bping\s+-w\b`, "Ping with timeout", ThreatLevelMedium},
		{`(?i)\bifconfig\b`, "Ifconfig (network config)", ThreatLevelHigh},
		{`(?i)\bip\s+addr\b`, "IP address command", ThreatLevelHigh},
		{`(?i)\bip\s+link\b`, "IP link command", ThreatLevelHigh},
		{`(?i)\bnetstat\b`, "Netstat (network statistics)", ThreatLevelHigh},
		{`(?i)\bss\s+-t\b`, "Socket statistics (TCP)", ThreatLevelMedium},
		{`(?i)\bss\s+-u\b`, "Socket statistics (UDP)", ThreatLevelMedium},
		{`(?i)\bnc\s+-l\b`, "Netcat listener mode", ThreatLevelCritical},
		{`(?i)\bnc\s+-e\b`, "Netcat execute mode", ThreatLevelCritical},
		{`(?i)\nncat\s+--exec\b`, "Ncat execute mode", ThreatLevelCritical},
		{`(?i)\btelnet\b`, "Telnet protocol", ThreatLevelHigh},
		{`(?i)\bssh\b`, "SSH client", ThreatLevelHigh},
		{`(?i)\bscp\b`, "Secure copy", ThreatLevelHigh},
		{`(?i)\bsftp\b`, "Secure FTP", ThreatLevelHigh},
		{`(?i)\bftp\b`, "FTP client", ThreatLevelHigh},
		{`(?i)\bwget\b`, "Wget (file download)", ThreatLevelHigh},
		{`(?i)\bcurl\b`, "Curl (HTTP client)", ThreatLevelHigh},
		{`(?i)\bcurl\s+.*\s+-o\b`, "Curl with output file", ThreatLevelHigh},
		{`(?i)\bcurl\s+.*\s+--output\b`, "Curl with output option", ThreatLevelHigh},
		{`(?i)\bwireshark\b`, "Wireshark network analyzer", ThreatLevelHigh},
		{`(?i)\btshark\b`, "TShark CLI analyzer", ThreatLevelHigh},
		{`(?i)\bnmap\b`, "Nmap port scanner", ThreatLevelCritical},
		{`(?i)\bnmap\s+--\w+`, "Nmap with options", ThreatLevelCritical},
		{`(?i)\btraceroute\b`, "Traceroute", ThreatLevelMedium},
		{`(?i)\btracepath\b`, "Tracepath", ThreatLevelMedium},
		{`(?i)\btracert\b`, "Tracert (Windows)", ThreatLevelMedium},
		{`(?i)\bpathping\b`, "Pathping (Windows)", ThreatLevelMedium},
		{`(?i)\bnbtstat\b`, "NetBIOS statistics", ThreatLevelMedium},
		{`(?i)\barp\s+-a\b`, "ARP table display", ThreatLevelMedium},
		{`(?i)\broute\s+print\b`, "Route table display", ThreatLevelMedium},
		{`(?i)\bnet\s+use\b`, "Net use (Windows share)", ThreatLevelHigh},
		{`(?i)\bnet\s+share\b`, "Net share (Windows)", ThreatLevelHigh},
		{`(?i)\bnet\s+user\b`, "Net user (Windows)", ThreatLevelCritical},
		{`(?i)\bnslookup\b`, "NSLookup (DNS query)", ThreatLevelMedium},
		{`(?i)\bdig\b`, "Dig (DNS query)", ThreatLevelMedium},
		{`(?i)\bhost\b`, "Host (DNS query)", ThreatLevelMedium},
		{`(?i)\bwhois\b`, "Whois lookup", ThreatLevelLow},
	}

	for _, p := range networkPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Network discovery/attack command: " + p.description,
				Recommendation: "Block network commands; log for investigation",
			})
		}
	}
}

func (a *CommandInjectionAnalyzer) analyzeFileOperations(data string, result *AnalysisResult) {
	fileOpPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\bcat\b.*\|`, "Cat command with pipe", ThreatLevelMedium},
		{`(?i)\bcat\s+/etc/passwd`, "Reading /etc/passwd", ThreatLevelCritical},
		{`(?i)\bcat\s+/etc/shadow`, "Reading /etc/shadow", ThreatLevelCritical},
		{`(?i)\bcat\s+/etc/hosts`, "Reading /etc/hosts", ThreatLevelMedium},
		{`(?i)\bcat\s+/etc/group`, "Reading /etc/group", ThreatLevelMedium},
		{`(?i)\btype\b.*\|`, "Type command (Windows) with pipe", ThreatLevelMedium},
		{`(?i)\btype\s+c:\\windows\\`, "Type command on Windows system files", ThreatLevelCritical},
		{`(?i)\bstrings\b`, "Strings command (extract text from binary)", ThreatLevelLow},
		{`(?i)\bhead\b`, "Head command (file beginning)", ThreatLevelLow},
		{`(?i)\btail\b`, "Tail command (file end)", ThreatLevelLow},
		{`(?i)\bmore\b`, "More command (paged view)", ThreatLevelLow},
		{`(?i)\bless\b`, "Less command", ThreatLevelLow},
		{`(?i)\buniq\b`, "Uniq command", ThreatLevelLow},
		{`(?i)\bsort\b`, "Sort command", ThreatLevelLow},
		{`(?i)\bgrep\b`, "Grep command", ThreatLevelLow},
		{`(?i)\bawk\b`, "Awk command", ThreatLevelMedium},
		{`(?i)\bsed\b`, "Sed command", ThreatLevelMedium},
		{`(?i)\bcut\b`, "Cut command", ThreatLevelLow},
		{`(?i)\bwc\b`, "Word count command", ThreatLevelLow},
		{`(?i)\btee\b`, "Tee command (read+write)", ThreatLevelMedium},
		{`(?i)\brsync\b`, "Rsync command", ThreatLevelHigh},
		{`(?i)\bscp\b`, "SCP command", ThreatLevelHigh},
		{`(?i)\bsftp\b`, "SFTP command", ThreatLevelHigh},
		{`(?i)\brm\s+-rf\b`, "Recursive force removal", ThreatLevelCritical},
		{`(?i)\brm\s+-\w*rf\b`, "Force removal with flags", ThreatLevelCritical},
		{`(?i)\brm\s+/`, "Removal starting from root", ThreatLevelCritical},
		{`(?i)\bunlink\b`, "Unlink command", ThreatLevelHigh},
		{`(?i)\bwget\s+.*\s+-O\b`, "Wget with output file", ThreatLevelHigh},
		{`(?i)\bwget\s+.*\s+--output-document\b`, "Wget output document", ThreatLevelHigh},
		{`(?i)\bcurl\s+.*\s+-o\b`, "Curl with output file", ThreatLevelHigh},
		{`(?i)\bcurl\s+.*\s+--output\b`, "Curl with output", ThreatLevelHigh},
		{`(?i)\btouch\b`, "Touch command (create file)", ThreatLevelLow},
		{`(?i)\bmkdir\s+-p\b`, "Mkdir with parents", ThreatLevelMedium},
		{`(?i)\bln\s+-s\b`, "Symlink creation", ThreatLevelHigh},
		{`(?i)\bsymlink\b`, "Symlink command", ThreatLevelHigh},
		{`(?i)\breadlink\b`, "Readlink command", ThreatLevelLow},
		{`(?i)\bstat\b`, "Stat command (file info)", ThreatLevelLow},
		{`(?i)\bfile\b`, "File command (determine type)", ThreatLevelLow},
		{`(?i)\blsof\b`, "List open files", ThreatLevelMedium},
		{`(?i)\bfuser\b`, "Fuser (process/file info)", ThreatLevelMedium},
	}

	for _, p := range fileOpPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.description,
				Description:    "File operation detected: " + p.description,
				Recommendation: "Validate file paths; restrict to allowed directories",
			})
		}
	}
}

func (a *CommandInjectionAnalyzer) analyzeProcessManipulation(data string, result *AnalysisResult) {
	processPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\bps\b`, "Process list command", ThreatLevelMedium},
		{`(?i)\bps\s+-e\b`, "Process list all", ThreatLevelMedium},
		{`(?i)\bps\s+-ef\b`, "Process list full format", ThreatLevelMedium},
		{`(?i)\bps\s+aux\b`, "Process list aux (BSD format)", ThreatLevelMedium},
		{`(?i)\btop\b`, "Top command (process monitor)", ThreatLevelLow},
		{`(?i)\bhtop\b`, "Htop interactive process", ThreatLevelLow},
		{`(?i)\bkill\b`, "Kill command", ThreatLevelHigh},
		{`(?i)\bkill\s+-\s*\d+\b`, "Kill with signal", ThreatLevelHigh},
		{`(?i)\bkillall\b`, "Killall command", ThreatLevelCritical},
		{`(?i)\bkillall\s+-9\b`, "Force kill all", ThreatLevelCritical},
		{`(?i)\bpkill\b`, "Pattern kill command", ThreatLevelHigh},
		{`(?i)\bxkill\b`, "X kill (GUI)", ThreatLevelHigh},
		{`(?i)\brkill\b`, "Rkill command", ThreatLevelHigh},
		{`(?i)\bkill\b.*\s+-9\b`, "Kill with SIGKILL", ThreatLevelCritical},
		{`(?i)\bkill\s+1\b`, "Kill init process", ThreatLevelCritical},
		{`(?i)\bkill\s+-\s*9\b`, "Force kill", ThreatLevelCritical},
		{`(?i)\bservice\s+--status-all\b`, "List all services", ThreatLevelMedium},
		{`(?i)\bsystemctl\s+list-units\b`, "Systemctl list units", ThreatLevelMedium},
		{`(?i)\bsystemctl\s+stop\b`, "Systemctl stop service", ThreatLevelHigh},
		{`(?i)\bsystemctl\s+start\b`, "Systemctl start service", ThreatLevelHigh},
		{`(?i)\bsystemctl\s+restart\b`, "Systemctl restart service", ThreatLevelHigh},
		{`(?i)\bsystemctl\s+kill\b`, "Systemctl kill", ThreatLevelHigh},
		{`(?i)\bsystemctl\s+disable\b`, "Systemctl disable service", ThreatLevelHigh},
		{`(?i)\binit\s+0\b`, "Init shutdown", ThreatLevelCritical},
		{`(?i)\binit\s+6\b`, "Init reboot", ThreatLevelCritical},
		{`(?i)\breboot\b`, "Reboot command", ThreatLevelCritical},
		{`(?i)\bshutdown\b.*\s+-h\b`, "Shutdown halt", ThreatLevelCritical},
		{`(?i)\bshutdown\b.*\s+-r\b`, "Shutdown reboot", ThreatLevelCritical},
		{`(?i)\bpoweroff\b`, "Poweroff command", ThreatLevelCritical},
		{`(?i)\bhalt\b`, "Halt command", ThreatLevelCritical},
		{`(?i)\bpidof\b`, "Pidof (find process)", ThreatLevelMedium},
		{`(?i)\bpgrep\b`, "Pattern grep for processes", ThreatLevelMedium},
		{`(?i)\bwatchdog\b`, "Watchdog command", ThreatLevelHigh},
		{`(?i)\bcrontab\b`, "Crontab command", ThreatLevelHigh},
		{`(?i)\bat\b`, "At command (scheduled task)", ThreatLevelHigh},
		{`(?i)\bat\b.*\s+-f\b`, "At with file", ThreatLevelHigh},
	}

	for _, p := range processPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Process manipulation detected: " + p.description,
				Recommendation: "Block process manipulation commands; log for investigation",
			})
		}
	}
}

func (a *CommandInjectionAnalyzer) analyzeEncodedCommands(data string, result *AnalysisResult) {
	encodedPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)%3B`, "URL Encoded semicolon", ThreatLevelHigh},
		{`(?i)%7C`, "URL Encoded pipe", ThreatLevelHigh},
		{`(?i)%26`, "URL Encoded ampersand", ThreatLevelMedium},
		{`(?i)%24`, "URL Encoded dollar", ThreatLevelMedium},
		{`(?i)%60`, "URL Encoded backtick", ThreatLevelCritical},
		{`(?i)%28`, "URL Encoded open parenthesis", ThreatLevelMedium},
		{`(?i)%29`, "URL Encoded close parenthesis", ThreatLevelMedium},
		{`(?i)%3E`, "URL Encoded >", ThreatLevelMedium},
		{`(?i)%3C`, "URL Encoded <", ThreatLevelMedium},
		{`(?i)%0A`, "URL Encoded newline", ThreatLevelHigh},
		{`(?i)%0D`, "URL Encoded carriage return", ThreatLevelMedium},
		{`(?i)%00`, "URL Encoded null byte", ThreatLevelHigh},
		{`(?i)%09`, "URL Encoded tab", ThreatLevelMedium},
		{`\\x[0-9a-f]{2}`, "Hex encoded character", ThreatLevelHigh},
		{`\\n`, "Escaped newline", ThreatLevelHigh},
		{`\\r`, "Escaped carriage return", ThreatLevelMedium},
		{`\\t`, "Escaped tab", ThreatLevelLow},
		{`\\0`, "Octal zero (null)", ThreatLevelHigh},
		{`%2F%2E%2E`, "URL Encoded ../ (path traversal)", ThreatLevelHigh},
		{`%2e%2e`, "Double encoded path traversal", ThreatLevelHigh},
		{`\.\.\\/`, "Path traversal variant", ThreatLevelHigh},
		{`%c0%ae`, "Unicode codepoint C0 (path traversal)", ThreatLevelHigh},
		{`%c1%9c`, "Unicode codepoint C1 (path traversal)", ThreatLevelHigh},
		{`%252e`, "Double encoded dot", ThreatLevelHigh},
		{`%255c`, "Double encoded backslash", ThreatLevelHigh},
	}

	for _, p := range encodedPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.description,
				Description:    "Encoded command injection: " + p.description,
				Recommendation: "Decode input before validation; block known encoding patterns",
			})
		}
	}
}

func (a *CommandInjectionAnalyzer) analyzeDangerousCommands(data string, result *AnalysisResult) {
	dangerousCommands := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\bxargs\b`, "Xargs (execute with arguments)", ThreatLevelHigh},
		{`(?i)\bxargs\s+-c\b`, "Xargs with command", ThreatLevelCritical},
		{`(?i)\bxargs\s+-s\b`, "Xargs with max chars", ThreatLevelHigh},
		{`(?i)\bexec\b`, "Exec command (replace shell)", ThreatLevelCritical},
		{`(?i)\beval\b`, "Eval command (dangerous shell)", ThreatLevelCritical},
		{`(?i)\bsource\b`, "Source command (load script)", ThreatLevelHigh},
		{`(?i)\b\.\s+\.\/`, "Source current directory", ThreatLevelHigh},
		{`(?i)\bset\b`, "Set command (shell options)", ThreatLevelMedium},
		{`(?i)\bunset\b`, "Unset environment variable", ThreatLevelMedium},
		{`(?i)\bexport\b`, "Export environment variable", ThreatLevelMedium},
		{`(?i)\benv\b`, "Env command (environment)", ThreatLevelMedium},
		{`(?i)\bchroot\b`, "Chroot command", ThreatLevelHigh},
		{`(?i)\bsudo\b`, "Sudo command", ThreatLevelHigh},
		{`(?i)\bsu\b`, "Switch user command", ThreatLevelHigh},
		{`(?i)\bgpasswd\b`, "Gpasswd (group password)", ThreatLevelMedium},
		{`(?i)\bnewgrp\b`, "New group command", ThreatLevelMedium},
		{`(?i)\bpasswd\b`, "Passwd command", ThreatLevelHigh},
		{`(?i)\bvisudo\b`, "Visudo command", ThreatLevelHigh},
		{`(?i)\buseradd\b`, "Useradd command", ThreatLevelCritical},
		{`(?i)\buserdel\b`, "Userdel command", ThreatLevelCritical},
		{`(?i)\busermod\b`, "Usermod command", ThreatLevelHigh},
		{`(?i)\bgroupadd\b`, "Groupadd command", ThreatLevelCritical},
		{`(?i)\bgroupdel\b`, "Groupdel command", ThreatLevelCritical},
		{`(?i)\bid\b`, "ID command (user info)", ThreatLevelLow},
		{`(?i)\bwhoami\b`, "Whoami command", ThreatLevelLow},
		{`(?i)\bwho\b`, "Who command (logged in users)", ThreatLevelLow},
		{`(?i)\bw\b`, "W command (who + what)", ThreatLevelLow},
		{`(?i)\blast\b`, "Last command (login history)", ThreatLevelLow},
		{`(?i)\blastlog\b`, "Lastlog command", ThreatLevelLow},
		{`(?i)\bfinger\b`, "Finger command", ThreatLevelMedium},
		{`(?i)\buptime\b`, "Uptime command", ThreatLevelLow},
		{`(?i)\bhostname\b`, "Hostname command", ThreatLevelLow},
		{`(?i)\buname\s+-a\b`, "Uname all info", ThreatLevelMedium},
		{`(?i)\barch\b`, "Architecture command", ThreatLevelLow},
		{`(?i)\bver\b`, "Version command (Windows)", ThreatLevelLow},
		{`(?i)\bcmd\b`, "Cmd command (Windows)", ThreatLevelHigh},
		{`(?i)\bcmd\s+/c\b`, "Cmd with command (Windows)", ThreatLevelHigh},
		{`(?i)\bpowershell\b`, "PowerShell command", ThreatLevelCritical},
		{`(?i)\bpowershell\s+-c\b`, "PowerShell with command", ThreatLevelCritical},
		{`(?i)\bpowershell\s+-e\b`, "PowerShell encoded command", ThreatLevelCritical},
		{`(?i)\bpowershell\s+-enc\b`, "PowerShell encoded command alt", ThreatLevelCritical},
		{`(?i)\breg\s+add\b`, "Reg add (Windows registry)", ThreatLevelCritical},
		{`(?i)\breg\s+delete\b`, "Reg delete (Windows registry)", ThreatLevelCritical},
		{`(?i)\breg\s+query\b`, "Reg query (Windows registry)", ThreatLevelHigh},
		{`(?i)\bsc\s+query\b`, "SC query (Windows service)", ThreatLevelMedium},
		{`(?i)\bsc\s+create\b`, "SC create (Windows service)", ThreatLevelCritical},
		{`(?i)\bsc\s+delete\b`, "SC delete (Windows service)", ThreatLevelCritical},
		{`(?i)\bsc\s+stop\b`, "SC stop (Windows service)", ThreatLevelHigh},
		{`(?i)\bsc\s+config\b`, "SC config (Windows service)", ThreatLevelCritical},
		{`(?i)\bschtasks\s+/create\b`, "Scheduled task create", ThreatLevelCritical},
		{`(?i)\bschtasks\s+/delete\b`, "Scheduled task delete", ThreatLevelCritical},
		{`(?i)\bmsiexec\b`, "MSIEXEC (package installer)", ThreatLevelHigh},
		{`(?i)\brundll32\b`, "Rundll32 (DLL execution)", ThreatLevelCritical},
		{`(?i)\bwscript\b`, "WScript (Windows scripting)", ThreatLevelHigh},
		{`(?i)\bcscript\b`, "CScript (Windows scripting)", ThreatLevelHigh},
		{`(?i)\biexpress\b`, "IExpress (Windows setup)", ThreatLevelHigh},
		{`(?i)\bmmc\b`, "MMC (Microsoft Management Console)", ThreatLevelHigh},
		{`(?i)\bdiskmgmt\.msc\b`, "Disk management", ThreatLevelHigh},
		{`(?i)\bdevmgmt\.msc\b`, "Device manager", ThreatLevelHigh},
		{`(?i)\bmstsc\b`, "Remote desktop", ThreatLevelHigh},
		{`(?i)\bcompmgmt\.msc\b`, "Computer management", ThreatLevelHigh},
	}

	for _, p := range dangerousCommands {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Dangerous command detected: " + p.description,
				Recommendation: "Block dangerous commands; use allowlist for permitted operations",
			})
		}
	}
}

func (a *CommandInjectionAnalyzer) analyzeEnvironmentManipulation(data string, result *AnalysisResult) {
	envPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)PATH\s*=`, "PATH environment variable manipulation", ThreatLevelHigh},
		{`(?i)LD_PRELOAD\s*=`, "LD_PRELOAD (shared library preload)", ThreatLevelCritical},
		{`(?i)LD_LIBRARY_PATH\s*=`, "LD_LIBRARY_PATH manipulation", ThreatLevelHigh},
		{`(?i)HOME\s*=`, "HOME environment manipulation", ThreatLevelMedium},
		{`(?i)SHELL\s*=`, "SHELL environment manipulation", ThreatLevelHigh},
		{`(?i)USER\s*=`, "USER environment manipulation", ThreatLevelMedium},
		{`(?i)USERNAME\s*=`, "USERNAME environment manipulation", ThreatLevelMedium},
		{`(?i)ENV\s*=`, "ENV variable manipulation", ThreatLevelMedium},
		{`(?i)BASH_ENV\s*=`, "BASH_ENV manipulation", ThreatLevelHigh},
		{`(?i)CDPATH\s*=`, "CDPATH manipulation", ThreatLevelLow},
		{`(?i)IFS\s*=`, "IFS (Internal Field Separator) manipulation", ThreatLevelHigh},
		{`(?i)MAIL\s*=`, "MAIL environment manipulation", ThreatLevelLow},
		{`(?i)HISTFILE\s*=`, "HISTFILE manipulation (history file)", ThreatLevelMedium},
		{`(?i)HISTSIZE\s*=`, "HISTSIZE manipulation", ThreatLevelLow},
		{`(?i)HOSTNAME\s*=`, "HOSTNAME manipulation", ThreatLevelMedium},
		{`(?i)PYTHONPATH\s*=`, "PYTHONPATH manipulation", ThreatLevelHigh},
		{`(?i)PERL5LIB\s*=`, "PERL5LIB manipulation", ThreatLevelHigh},
		{`(?i)PERL5OPT\s*=`, "PERL5OPT manipulation", ThreatLevelHigh},
		{`(?i)Ruby\n*\s*=`, "RUBYOPT manipulation", ThreatLevelHigh},
		{`(?i)JAVA_HOME\s*=`, "JAVA_HOME manipulation", ThreatLevelMedium},
		{`(?i)CLASSPATH\s*=`, "CLASSPATH manipulation", ThreatLevelMedium},
		{`(?i)NODE_PATH\s*=`, "NODE_PATH manipulation", ThreatLevelHigh},
		{`(?i)NODE_OPTIONS\s*=`, "NODE_OPTIONS manipulation", ThreatLevelHigh},
		{`(?i)npm_config_prefix\s*=`, "npm config prefix", ThreatLevelMedium},
		{`(?i)XDG_CONFIG_HOME\s*=`, "XDG config home manipulation", ThreatLevelMedium},
		{`(?i)XDG_DATA_HOME\s*=`, "XDG data home manipulation", ThreatLevelMedium},
		{`(?i)XDG_CACHE_HOME\s*=`, "XDG cache home manipulation", ThreatLevelMedium},
		{`(?i)GOPATH\s*=`, "GOPATH manipulation", ThreatLevelMedium},
		{`(?i)GOROOT\s*=`, "GOROOT manipulation", ThreatLevelMedium},
		{`(?i)CARGO_HOME\s*=`, "CARGO_HOME manipulation", ThreatLevelMedium},
		{`(?i)RUSTUP_HOME\s*=`, "RUSTUP_HOME manipulation", ThreatLevelMedium},
		{`(?i)_proxy\s*=`, "Proxy environment variable", ThreatLevelMedium},
		{`(?i)http_proxy\s*=`, "HTTP proxy setting", ThreatLevelMedium},
		{`(?i)https_proxy\s*=`, "HTTPS proxy setting", ThreatLevelMedium},
		{`(?i)all_proxy\s*=`, "All proxy setting", ThreatLevelMedium},
		{`(?i)no_proxy\s*=`, "No proxy setting", ThreatLevelMedium},
		{`(?i)HTTP_PROXY\s*=`, "HTTP proxy (uppercase)", ThreatLevelMedium},
		{`(?i)HTTPS_PROXY\s*=`, "HTTPS proxy (uppercase)", ThreatLevelMedium},
	}

	for _, p := range envPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.description,
				Description:    "Environment manipulation: " + p.description,
				Recommendation: "Block environment variable manipulation in user input",
			})
		}
	}
}
