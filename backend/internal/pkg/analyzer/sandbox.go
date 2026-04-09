package analyzer

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

type SandboxIntent int

const (
	IntentUnknown SandboxIntent = iota
	IntentCodeExecution
	IntentFileRead
	IntentFileWrite
	IntentFileDelete
	IntentNetworkAccess
	IntentSystemInfo
	IntentProcessCreation
	IntentRegistryAccess
)

func (i SandboxIntent) String() string {
	switch i {
	case IntentUnknown:
		return "未知意图"
	case IntentCodeExecution:
		return "代码执行"
	case IntentFileRead:
		return "文件读取"
	case IntentFileWrite:
		return "文件写入"
	case IntentFileDelete:
		return "文件删除"
	case IntentNetworkAccess:
		return "网络访问"
	case IntentSystemInfo:
		return "系统信息收集"
	case IntentProcessCreation:
		return "进程创建"
	case IntentRegistryAccess:
		return "注册表访问"
	default:
		return "未知"
	}
}

type SystemCallType int

const (
	SysCallUnknown SystemCallType = iota
	SysCallExec
	SysCallRead
	SysCallWrite
	SysCallOpen
	SysCallClose
	SysCallConnect
	SysCallBind
	SysCallListen
	SysCallAccept
	SysCallSend
	SysCallRecv
	SysCallGetuid
	SysCallGetgid
	SysCallGetpid
	SysCallGetppid
	SysCallUname
	SysCallStat
	SysCallLstat
	SysCallFstat
	SysCallAccess
	SysCallChmod
	SysCallChown
	SysCallMkdir
	SysCallRmdir
	SysCallUnlink
	SysCallRename
	SysCallLink
	SysCallSymlink
	SysCallReadlink
	SysCallTruncate
	SysCallChdir
	SysCallGetcwd
	SysCallDup
	SysCallDup2
	SysCallPipe
	SysCallSelect
	SysCallPoll
	SysCallSocket
	SysCallSetsockopt
	SysCallGetsockopt
	SysCallSendto
	SysCallRecvfrom
	SysCallShutdown
	SysCallBrk
	SysCallMmap
	SysCallMunmap
	SysCallMprotect
	SysCallMremap
	SysCallFork
	SysCallVfork
	SysCallClone
	SysCallExecve
	SysCallExit
	SysCallKill
	SysCallWait4
	SysCallPrctl
	SysCallArchPrctl
	SysCallModifyLdt
	SysCallPtrace
	SysCallPersonality
	SysCallUtimes
	SysCallVhangup
	SysCallVm86
	SysCallAdjtimex
	SysCallSetrlimit
	SysCallGetrlimit
	SysCallGetrusage
	SysCallSyslog
	SysCallGettimeofday
	SysCallSettimeofday
	SysCallIoctl
	SysCallFcntl
	SysCallSwapon
	SysCallSwapoff
	SysCallMlock
	SysCallMunlock
	SysCallMlockall
	SysCallMunlockall
	SysCallSchedSetparam
	SysCallSchedGetparam
	SysCallSchedSetscheduler
	SysCallSchedGetscheduler
	SysCallSchedYield
	SysCallSchedGetPriorityMax
	SysCallSchedGetPriorityMin
)

func (s SystemCallType) String() string {
	switch s {
	case SysCallExec:
		return "exec"
	case SysCallRead:
		return "read"
	case SysCallWrite:
		return "write"
	case SysCallOpen:
		return "open"
	case SysCallClose:
		return "close"
	case SysCallConnect:
		return "connect"
	case SysCallBind:
		return "bind"
	case SysCallListen:
		return "listen"
	case SysCallAccept:
		return "accept"
	case SysCallSend:
		return "send"
	case SysCallRecv:
		return "recv"
	case SysCallGetuid:
		return "getuid"
	case SysCallGetgid:
		return "getgid"
	case SysCallGetpid:
		return "getpid"
	case SysCallGetppid:
		return "getppid"
	case SysCallUname:
		return "uname"
	case SysCallStat:
		return "stat"
	case SysCallLstat:
		return "lstat"
	case SysCallFstat:
		return "fstat"
	case SysCallAccess:
		return "access"
	case SysCallChmod:
		return "chmod"
	case SysCallChown:
		return "chown"
	case SysCallMkdir:
		return "mkdir"
	case SysCallRmdir:
		return "rmdir"
	case SysCallUnlink:
		return "unlink"
	case SysCallRename:
		return "rename"
	case SysCallLink:
		return "link"
	case SysCallSymlink:
		return "symlink"
	case SysCallReadlink:
		return "readlink"
	case SysCallTruncate:
		return "truncate"
	case SysCallChdir:
		return "chdir"
	case SysCallGetcwd:
		return "getcwd"
	case SysCallDup:
		return "dup"
	case SysCallDup2:
		return "dup2"
	case SysCallPipe:
		return "pipe"
	case SysCallSelect:
		return "select"
	case SysCallPoll:
		return "poll"
	case SysCallSocket:
		return "socket"
	case SysCallSetsockopt:
		return "setsockopt"
	case SysCallGetsockopt:
		return "getsockopt"
	case SysCallSendto:
		return "sendto"
	case SysCallRecvfrom:
		return "recvfrom"
	case SysCallShutdown:
		return "shutdown"
	case SysCallBrk:
		return "brk"
	case SysCallMmap:
		return "mmap"
	case SysCallMunmap:
		return "munmap"
	case SysCallMprotect:
		return "mprotect"
	case SysCallMremap:
		return "mremap"
	case SysCallFork:
		return "fork"
	case SysCallVfork:
		return "vfork"
	case SysCallClone:
		return "clone"
	case SysCallExecve:
		return "execve"
	case SysCallExit:
		return "exit"
	case SysCallKill:
		return "kill"
	case SysCallWait4:
		return "wait4"
	case SysCallPrctl:
		return "prctl"
	case SysCallArchPrctl:
		return "arch_prctl"
	case SysCallModifyLdt:
		return "modify_ldt"
	case SysCallPtrace:
		return "ptrace"
	case SysCallPersonality:
		return "personality"
	case SysCallUtimes:
		return "utimes"
	case SysCallVhangup:
		return "vhangup"
	case SysCallVm86:
		return "vm86"
	case SysCallAdjtimex:
		return "adjtimex"
	case SysCallSetrlimit:
		return "setrlimit"
	case SysCallGetrlimit:
		return "getrlimit"
	case SysCallGetrusage:
		return "getrusage"
	case SysCallSyslog:
		return "syslog"
	case SysCallGettimeofday:
		return "gettimeofday"
	case SysCallSettimeofday:
		return "settimeofday"
	case SysCallIoctl:
		return "ioctl"
	case SysCallFcntl:
		return "fcntl"
	case SysCallSwapon:
		return "swapon"
	case SysCallSwapoff:
		return "swapoff"
	case SysCallMlock:
		return "mlock"
	case SysCallMunlock:
		return "munlock"
	case SysCallMlockall:
		return "mlockall"
	case SysCallMunlockall:
		return "munlockall"
	case SysCallSchedSetparam:
		return "sched_setparam"
	case SysCallSchedGetparam:
		return "sched_getparam"
	case SysCallSchedSetscheduler:
		return "sched_setscheduler"
	case SysCallSchedGetscheduler:
		return "sched_getscheduler"
	case SysCallSchedYield:
		return "sched_yield"
	case SysCallSchedGetPriorityMax:
		return "sched_get_priority_max"
	case SysCallSchedGetPriorityMin:
		return "sched_get_priority_min"
	default:
		return "unknown"
	}
}

type SimulatedCall struct {
	Type       SystemCallType
	Name       string
	Args       []string
	ReturnVal  string
	IsAllowed  bool
	Reason     string
	Timestamp  time.Time
	RiskLevel  ThreatLevel
}

type SimulatedFileSystem struct {
	AllowedPaths   map[string]bool
	BlockedPaths   map[string]bool
	ReadOnlyPaths  map[string]bool
	SimulatedFiles map[string]string
	mu             sync.RWMutex
}

func NewSimulatedFileSystem() *SimulatedFileSystem {
	return &SimulatedFileSystem{
		AllowedPaths:   make(map[string]bool),
		BlockedPaths:   make(map[string]bool),
		ReadOnlyPaths:  make(map[string]bool),
		SimulatedFiles: make(map[string]string),
	}
}

func (fs *SimulatedFileSystem) IsPathAllowed(path string) bool {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	if fs.BlockedPaths[path] {
		return false
	}

	if fs.AllowedPaths[path] {
		return true
	}

	blockedPrefixes := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/sudoers",
		"/root/.ssh",
		"/home/",
		"/var/log",
		"/var/www",
		"/usr/bin",
		"/usr/sbin",
		"/bin",
		"/sbin",
		"/boot",
		"/sys",
		"/proc",
		"/dev",
	}

	for _, prefix := range blockedPrefixes {
		if strings.HasPrefix(path, prefix) || strings.HasPrefix(strings.ToLower(path), strings.ToLower(prefix)) {
			return false
		}
	}

	return true
}

func (fs *SimulatedFileSystem) IsReadOnly(path string) bool {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return fs.ReadOnlyPaths[path]
}

type SimulatedNetwork struct {
	AllowedHosts   map[string]bool
	BlockedHosts   map[string]bool
	AllowedPorts   map[int]bool
	BlockedPorts   map[int]bool
	SimulatedConns []string
	mu             sync.RWMutex
}

func NewSimulatedNetwork() *SimulatedNetwork {
	return &SimulatedNetwork{
		AllowedHosts:   make(map[string]bool),
		BlockedHosts:   make(map[string]bool),
		AllowedPorts:   make(map[int]bool),
		BlockedPorts:   make(map[int]bool),
		SimulatedConns: make([]string, 0),
	}
}

func (net *SimulatedNetwork) IsHostAllowed(host string) bool {
	net.mu.RLock()
	defer net.mu.RUnlock()

	if net.BlockedHosts[host] {
		return false
	}

	if net.AllowedHosts[host] {
		return true
	}

	blockedHosts := []string{
		"localhost",
		"127.0.0.1",
		"0.0.0.0",
		"169.254.169.254",
		"metadata.google.internal",
		"aws.amazonaws.com",
	}

	hostLower := strings.ToLower(host)
	for _, blocked := range blockedHosts {
		if hostLower == strings.ToLower(blocked) || strings.HasPrefix(hostLower, strings.ToLower(blocked)) {
			return false
		}
	}

	return true
}

func (net *SimulatedNetwork) IsPortAllowed(port int) bool {
	net.mu.RLock()
	defer net.mu.RUnlock()

	if net.BlockedPorts[port] {
		return false
	}

	if net.AllowedPorts[port] {
		return true
	}

	blockedPorts := []int{
		22, 23, 25, 3306, 5432, 27017, 6379, 11211, 1433,
	}

	for _, blocked := range blockedPorts {
		if port == blocked {
			return false
		}
	}

	return true
}

type SandboxConfig struct {
	EnableFileSystem bool
	EnableNetwork    bool
	EnableProcess    bool
	EnableRegistry   bool
	Timeout          time.Duration
	MaxCalls         int
	MaxMemory        int64
}

func DefaultSandboxConfig() *SandboxConfig {
	return &SandboxConfig{
		EnableFileSystem: true,
		EnableNetwork:    true,
		EnableProcess:    true,
		EnableRegistry:   true,
		Timeout:          5 * time.Second,
		MaxCalls:         1000,
		MaxMemory:        100 * 1024 * 1024,
	}
}

type SandboxResult struct {
	Allowed            bool
	ThreatLevel        ThreatLevel
	RiskScore          float64
	Intents            []SandboxIntent
	DetectedBehaviors  []string
	SimulatedCalls     []SimulatedCall
	RiskFactors        []string
	Recommendations    []string
	AnalysisTime       time.Duration
	TimeoutReached     bool
}

type SandboxPayload struct {
	Raw           string
	Type          string
	TargetType    string
	Encoding      string
	Obfuscation   []string
	ExecutionPlan []string
}

type SandboxAnalyzer struct {
	name          string
	version       string
	analyzerType  string
	enabled       bool
	config        map[string]interface{}
	mu            sync.RWMutex
	patternCache  *PatternCache
	sandboxConfig *SandboxConfig
	fs            *SimulatedFileSystem
	net           *SimulatedNetwork
}

func NewSandboxAnalyzer() *SandboxAnalyzer {
	return &SandboxAnalyzer{
		name:          "sandbox_analyzer",
		version:       "1.0.0",
		analyzerType:  "sandbox_execution",
		enabled:       true,
		config:        make(map[string]interface{}),
		patternCache:  NewPatternCache(),
		sandboxConfig: DefaultSandboxConfig(),
		fs:            NewSimulatedFileSystem(),
		net:           NewSimulatedNetwork(),
	}
}

func (a *SandboxAnalyzer) Name() string {
	return a.name
}

func (a *SandboxAnalyzer) Type() string {
	return a.analyzerType
}

func (a *SandboxAnalyzer) Version() string {
	return a.version
}

func (a *SandboxAnalyzer) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

func (a *SandboxAnalyzer) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

func (a *SandboxAnalyzer) Configure(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = config
	return nil
}

func (a *SandboxAnalyzer) Analyze(input *AnalysisInput) *AnalysisResult {
	start := time.Now()
	result := NewAnalysisResult(a)

	if input == nil || input.Raw == "" {
		return result
	}

	rawData := input.Raw

	sandboxResult := a.simulateExecution(rawData, input)

	if !sandboxResult.Allowed {
		result.AddMatch(Match{
			Type:           MatchTypeBehavioral,
			ThreatLevel:    sandboxResult.ThreatLevel,
			Pattern:        "sandbox_blocked",
			Description:    "Sandbox detected malicious behavior",
			Recommendation: "Block request and log security event",
		})
	}

	for _, intent := range sandboxResult.Intents {
		result.AddMatch(Match{
			Type:           MatchTypeBehavioral,
			ThreatLevel:    a.intentToThreatLevel(intent),
			Pattern:        "intent:" + intent.String(),
			Description:    "Detected intent: " + intent.String(),
			Recommendation: a.getRecommendationForIntent(intent),
		})
	}

	for _, call := range sandboxResult.SimulatedCalls {
		if !call.IsAllowed {
			result.AddMatch(Match{
				Type:           MatchTypeBehavioral,
				ThreatLevel:    call.RiskLevel,
				Pattern:        "blocked_call:" + call.Name,
				Description:    "Blocked syscall: " + call.Name,
				Recommendation: call.Reason,
			})
		}
	}

	for _, behavior := range sandboxResult.DetectedBehaviors {
		result.AddMatch(Match{
			Type:           MatchTypeBehavioral,
			ThreatLevel:    ThreatLevelMedium,
			Pattern:        "behavior:" + behavior,
			Description:    "Detected malicious behavior: " + behavior,
			Recommendation: "Manual review required",
		})
	}

	result.RiskScore = sandboxResult.RiskScore

	if sandboxResult.TimeoutReached {
		result.AddMatch(Match{
			Type:           MatchTypeBehavioral,
			ThreatLevel:    ThreatLevelHigh,
			Pattern:        "timeout",
			Description:    "Sandbox execution timeout - possible resource exhaustion attack",
			Recommendation: "Block requests with long execution time",
		})
	}

	result.ProcessingTime = time.Since(start)

	if len(result.Matches) > 0 {
		result.ShouldBlock = result.ShouldBlockRequest(0.5)
		result.ShouldLog = true
		result.ShouldAllow = !result.ShouldBlock
	}

	if sandboxResult.RiskScore > 0.7 {
		result.ThreatLevel = ThreatLevelHigh
		result.ShouldBlock = true
		result.ShouldAllow = false
	}

	result.Details["sandbox_result"] = map[string]interface{}{
		"allowed":            sandboxResult.Allowed,
		"risk_score":          sandboxResult.RiskScore,
		"intents":             sandboxResult.Intents,
		"detected_behaviors":  sandboxResult.DetectedBehaviors,
		"timeout_reached":     sandboxResult.TimeoutReached,
	}

	return result
}

func (a *SandboxAnalyzer) simulateExecution(payload string, input *AnalysisInput) *SandboxResult {
	result := &SandboxResult{
		Allowed:           true,
		ThreatLevel:        ThreatLevelSafe,
		RiskScore:          0.0,
		Intents:            make([]SandboxIntent, 0),
		DetectedBehaviors:  make([]string, 0),
		SimulatedCalls:     make([]SimulatedCall, 0),
		RiskFactors:        make([]string, 0),
		Recommendations:    make([]string, 0),
		AnalysisTime:       0,
		TimeoutReached:     false,
	}

	analysisStart := time.Now()
	callCount := 0

	a.analyzeCodeExecution(payload, result)
	callCount++
	if callCount >= a.sandboxConfig.MaxCalls {
		result.TimeoutReached = true
		goto FINISH
	}

	a.analyzeFileSystemAccess(payload, result)
	callCount++
	if callCount >= a.sandboxConfig.MaxCalls {
		result.TimeoutReached = true
		goto FINISH
	}

	a.analyzeNetworkAccess(payload, result)
	callCount++
	if callCount >= a.sandboxConfig.MaxCalls {
		result.TimeoutReached = true
		goto FINISH
	}

	a.analyzeSystemInfoGathering(payload, result)
	callCount++
	if callCount >= a.sandboxConfig.MaxCalls {
		result.TimeoutReached = true
		goto FINISH
	}

	a.analyzeProcessCreation(payload, result)
	callCount++
	if callCount >= a.sandboxConfig.MaxCalls {
		result.TimeoutReached = true
		goto FINISH
	}

	a.detectObfuscationTechniques(payload, result)

	a.calculateOverallRisk(result)

FINISH:
	result.AnalysisTime = time.Since(analysisStart)

	if result.AnalysisTime > a.sandboxConfig.Timeout {
		result.TimeoutReached = true
	}

	return result
}

func (a *SandboxAnalyzer) analyzeCodeExecution(payload string, result *SandboxResult) {
	codePatterns := []struct {
		pattern     string
		intent      SandboxIntent
		riskLevel   ThreatLevel
		description string
	}{
		{`(?i)\beval\s*\(`, IntentCodeExecution, ThreatLevelHigh, "eval() function execution"},
		{`(?i)\bexec\s*\(`, IntentCodeExecution, ThreatLevelHigh, "exec() function execution"},
		{`(?i)\bsystem\s*\(`, IntentCodeExecution, ThreatLevelHigh, "system() command execution"},
		{`(?i)\bpassthru\s*\(`, IntentCodeExecution, ThreatLevelHigh, "passthru() command execution"},
		{`(?i)\bshell_exec\s*\(`, IntentCodeExecution, ThreatLevelHigh, "shell_exec() command execution"},
		{`(?i)\bproc_open\s*\(`, IntentProcessCreation, ThreatLevelHigh, "proc_open() process creation"},
		{`(?i)\bpopen\s*\(`, IntentProcessCreation, ThreatLevelHigh, "popen() process creation"},
		{`(?i)\bcurl_exec\s*\(`, IntentNetworkAccess, ThreatLevelMedium, "curl_exec() network request"},
		{`(?i)\bfile_get_contents\s*\(`, IntentFileRead, ThreatLevelMedium, "file_get_contents() file read"},
		{`(?i)\bfile_put_contents\s*\(`, IntentFileWrite, ThreatLevelHigh, "file_put_contents() file write"},
		{`(?i)\bunlink\s*\(`, IntentFileDelete, ThreatLevelHigh, "unlink() file deletion"},
		{`(?i)\brmdir\s*\(`, IntentFileDelete, ThreatLevelHigh, "rmdir() directory deletion"},
		{`(?i)\bmkdir\s*\(`, IntentFileWrite, ThreatLevelMedium, "mkdir() directory creation"},
		{`(?i)\bchmod\s*\(`, IntentFileWrite, ThreatLevelMedium, "chmod() permission modification"},
	}

	for _, p := range codePatterns {
		re := a.patternCache.GetMust(p.pattern)
		if re.MatchString(payload) {
			result.Intents = append(result.Intents, p.intent)
			result.DetectedBehaviors = append(result.DetectedBehaviors, p.description)

			result.SimulatedCalls = append(result.SimulatedCalls, SimulatedCall{
				Type:      a.intentToSysCall(p.intent),
				Name:      p.description,
				Args:      a.extractFunctionArgs(payload, p.pattern),
				ReturnVal: "blocked",
				IsAllowed: false,
				Reason:    "High-risk function call blocked by sandbox",
				Timestamp: time.Now(),
				RiskLevel: p.riskLevel,
			})

			result.RiskFactors = append(result.RiskFactors, p.description)
		}
	}

	a.analyzeCommandInjection(payload, result)
	a.analyzeSQLExecution(payload, result)
}

func (a *SandboxAnalyzer) analyzeCommandInjection(payload string, result *SandboxResult) {
	commandIndicators := []struct {
		keyword     string
		intent      SandboxIntent
		riskLevel   ThreatLevel
		description string
	}{
		{"cat ", IntentFileRead, ThreatLevelHigh, "Command injection - file read"},
		{"ls ", IntentFileRead, ThreatLevelHigh, "Command injection - list files"},
		{"dir ", IntentFileRead, ThreatLevelHigh, "Command injection - directory listing"},
		{"wget ", IntentNetworkAccess, ThreatLevelHigh, "Command injection - network download"},
		{"curl ", IntentNetworkAccess, ThreatLevelHigh, "Command injection - network request"},
		{"bash ", IntentCodeExecution, ThreatLevelCritical, "Command injection - bash execution"},
		{"sh ", IntentCodeExecution, ThreatLevelCritical, "Command injection - shell execution"},
		{"cmd ", IntentCodeExecution, ThreatLevelCritical, "Command injection - cmd execution"},
		{"powershell ", IntentCodeExecution, ThreatLevelCritical, "Command injection - powershell execution"},
		{"nc ", IntentNetworkAccess, ThreatLevelCritical, "Command injection - netcat"},
		{"netcat ", IntentNetworkAccess, ThreatLevelCritical, "Command injection - netcat"},
		{"telnet ", IntentNetworkAccess, ThreatLevelCritical, "Command injection - telnet"},
		{"whoami", IntentSystemInfo, ThreatLevelMedium, "Command injection - system info"},
		{"id ", IntentSystemInfo, ThreatLevelMedium, "Command injection - user id"},
		{"uname ", IntentSystemInfo, ThreatLevelMedium, "Command injection - system info"},
		{"gcc ", IntentProcessCreation, ThreatLevelHigh, "Command injection - compilation"},
		{"python ", IntentCodeExecution, ThreatLevelHigh, "Command injection - python execution"},
		{"perl ", IntentCodeExecution, ThreatLevelHigh, "Command injection - perl execution"},
		{"php ", IntentCodeExecution, ThreatLevelHigh, "Command injection - php execution"},
		{"ruby ", IntentCodeExecution, ThreatLevelHigh, "Command injection - ruby execution"},
		{"rm -rf", IntentFileDelete, ThreatLevelCritical, "Command injection - recursive delete"},
		{"/etc/passwd", IntentFileRead, ThreatLevelMedium, "Attempt to read /etc/passwd"},
		{"/etc/shadow", IntentFileRead, ThreatLevelCritical, "Attempt to read /etc/shadow"},
	}

	payloadLower := strings.ToLower(payload)
	for _, p := range commandIndicators {
		if strings.Contains(payloadLower, strings.ToLower(p.keyword)) {
			result.Intents = append(result.Intents, p.intent)
			result.DetectedBehaviors = append(result.DetectedBehaviors, p.description)
			result.RiskScore += a.riskLevelToScore(p.riskLevel)
		}
	}

	if strings.Contains(payload, "$(") && strings.Contains(payload, ")") {
		result.Intents = append(result.Intents, IntentCodeExecution)
		result.DetectedBehaviors = append(result.DetectedBehaviors, "Command substitution $(...)")
		result.RiskScore += a.riskLevelToScore(ThreatLevelHigh)
	}
}

func (a *SandboxAnalyzer) analyzeSQLExecution(payload string, result *SandboxResult) {
	sqlIndicators := []struct {
		keyword     string
		intent      SandboxIntent
		riskLevel   ThreatLevel
		description string
	}{
		{"xp_cmdshell", IntentCodeExecution, ThreatLevelCritical, "SQL xp_cmdshell command execution"},
		{"sp_executesql", IntentCodeExecution, ThreatLevelHigh, "SQL sp_executesql execution"},
		{"openrowset", IntentNetworkAccess, ThreatLevelHigh, "SQL openrowset remote query"},
		{"opendatasource", IntentNetworkAccess, ThreatLevelHigh, "SQL opendatasource query"},
		{"load_file", IntentFileRead, ThreatLevelHigh, "SQL load_file file read"},
		{"into outfile", IntentFileWrite, ThreatLevelCritical, "SQL file export"},
		{"into dumpfile", IntentFileWrite, ThreatLevelCritical, "SQL file export"},
		{"exec(", IntentCodeExecution, ThreatLevelCritical, "SQL exec dynamic execution"},
		{"declare ", IntentCodeExecution, ThreatLevelHigh, "SQL variable declaration injection"},
	}

	payloadLower := strings.ToLower(payload)
	for _, p := range sqlIndicators {
		if strings.Contains(payloadLower, strings.ToLower(p.keyword)) {
			result.Intents = append(result.Intents, p.intent)
			result.DetectedBehaviors = append(result.DetectedBehaviors, p.description)
			result.RiskScore += a.riskLevelToScore(p.riskLevel)
		}
	}
}

func (a *SandboxAnalyzer) analyzeFileSystemAccess(payload string, result *SandboxResult) {
	pathIndicators := []struct {
		keyword     string
		intent      SandboxIntent
		riskLevel   ThreatLevel
		description string
	}{
		{"/etc/passwd", IntentFileRead, ThreatLevelMedium, "Attempt to read /etc/passwd"},
		{"/etc/shadow", IntentFileRead, ThreatLevelCritical, "Attempt to read /etc/shadow"},
		{"/etc/sudoers", IntentFileRead, ThreatLevelCritical, "Attempt to read sudoers config"},
		{".ssh/", IntentFileRead, ThreatLevelCritical, "Attempt to access SSH directory"},
		{".aws/", IntentFileRead, ThreatLevelHigh, "Attempt to access AWS config"},
		{".git/", IntentFileRead, ThreatLevelMedium, "Attempt to access Git repository"},
		{"wp-config.php", IntentFileRead, ThreatLevelHigh, "Attempt to read WordPress config"},
		{"config.php", IntentFileRead, ThreatLevelHigh, "Attempt to read PHP config"},
		{".env", IntentFileRead, ThreatLevelCritical, "Attempt to read environment file"},
		{"/var/log/", IntentFileRead, ThreatLevelMedium, "Attempt to access log directory"},
		{".htaccess", IntentFileRead, ThreatLevelMedium, "Attempt to read htaccess config"},
		{".htpasswd", IntentFileRead, ThreatLevelMedium, "Attempt to read htpasswd"},
		{"/tmp/", IntentFileWrite, ThreatLevelMedium, "Attempt to access temp directory"},
		{"/var/tmp/", IntentFileWrite, ThreatLevelMedium, "Attempt to access temp directory"},
		{".bak", IntentFileRead, ThreatLevelMedium, "Attempt to read backup file"},
		{".sql", IntentFileRead, ThreatLevelMedium, "Attempt to read SQL file"},
	}

	payloadLower := strings.ToLower(payload)
	for _, p := range pathIndicators {
		if strings.Contains(payloadLower, strings.ToLower(p.keyword)) {
			result.Intents = append(result.Intents, p.intent)
			result.DetectedBehaviors = append(result.DetectedBehaviors, p.description)
			result.RiskScore += a.riskLevelToScore(p.riskLevel)

			if !a.fs.IsPathAllowed(p.description) {
				result.SimulatedCalls = append(result.SimulatedCalls, SimulatedCall{
					Type:      SysCallOpen,
					Name:      p.description,
					Args:      []string{"path: blocked"},
					ReturnVal: "EPERM",
					IsAllowed: false,
					Reason:    "Path access blocked by sandbox",
					Timestamp: time.Now(),
					RiskLevel: p.riskLevel,
				})
			}
		}
	}
}

func (a *SandboxAnalyzer) analyzeNetworkAccess(payload string, result *SandboxResult) {
	networkIndicators := []struct {
		keyword     string
		intent      SandboxIntent
		riskLevel   ThreatLevel
		description string
	}{
		{"http://", IntentNetworkAccess, ThreatLevelMedium, "HTTP request"},
		{"https://", IntentNetworkAccess, ThreatLevelMedium, "HTTPS request"},
		{"ftp://", IntentNetworkAccess, ThreatLevelMedium, "FTP request"},
		{"sftp://", IntentNetworkAccess, ThreatLevelHigh, "SFTP request"},
		{"smb://", IntentNetworkAccess, ThreatLevelHigh, "SMB request"},
		{"ssh://", IntentNetworkAccess, ThreatLevelCritical, "SSH connection"},
		{"telnet://", IntentNetworkAccess, ThreatLevelCritical, "Telnet connection"},
		{"mysql://", IntentNetworkAccess, ThreatLevelCritical, "MySQL connection"},
		{"postgresql://", IntentNetworkAccess, ThreatLevelCritical, "PostgreSQL connection"},
		{"mongodb://", IntentNetworkAccess, ThreatLevelCritical, "MongoDB connection"},
		{"redis://", IntentNetworkAccess, ThreatLevelCritical, "Redis connection"},
		{"127.0.0.1", IntentNetworkAccess, ThreatLevelMedium, "Local loopback connection"},
		{"localhost", IntentNetworkAccess, ThreatLevelMedium, "Localhost connection"},
		{"169.254.169.254", IntentSystemInfo, ThreatLevelCritical, "Cloud metadata service access"},
		{"metadata.google.internal", IntentSystemInfo, ThreatLevelCritical, "GCP metadata service"},
	}

	payloadLower := strings.ToLower(payload)
	for _, p := range networkIndicators {
		if strings.Contains(payloadLower, strings.ToLower(p.keyword)) {
			result.Intents = append(result.Intents, p.intent)
			result.DetectedBehaviors = append(result.DetectedBehaviors, p.description)
			result.RiskScore += a.riskLevelToScore(p.riskLevel)
		}
	}
}

func (a *SandboxAnalyzer) analyzeSystemInfoGathering(payload string, result *SandboxResult) {
	sysInfoIndicators := []struct {
		keyword     string
		intent      SandboxIntent
		riskLevel   ThreatLevel
		description string
	}{
		{"whoami", IntentSystemInfo, ThreatLevelLow, "Get current username"},
		{"id ", IntentSystemInfo, ThreatLevelLow, "Get user ID information"},
		{"uname", IntentSystemInfo, ThreatLevelLow, "Get system information"},
		{"hostname", IntentSystemInfo, ThreatLevelLow, "Get hostname"},
		{"env ", IntentSystemInfo, ThreatLevelMedium, "Get environment variables"},
		{"pwd", IntentSystemInfo, ThreatLevelLow, "Get current directory"},
		{"ifconfig", IntentSystemInfo, ThreatLevelMedium, "Get network configuration"},
		{"ip addr", IntentSystemInfo, ThreatLevelMedium, "Get IP address"},
		{"netstat", IntentSystemInfo, ThreatLevelMedium, "Get network status"},
		{"ps ", IntentSystemInfo, ThreatLevelMedium, "Get process list"},
		{"df ", IntentSystemInfo, ThreatLevelLow, "Get disk usage"},
		{"mount", IntentSystemInfo, ThreatLevelMedium, "Get mount information"},
		{"crontab", IntentSystemInfo, ThreatLevelMedium, "View scheduled tasks"},
		{"sudo ", IntentSystemInfo, ThreatLevelMedium, "View sudo privileges"},
	}

	payloadLower := strings.ToLower(payload)
	for _, p := range sysInfoIndicators {
		if strings.Contains(payloadLower, strings.ToLower(p.keyword)) {
			result.Intents = append(result.Intents, p.intent)
			result.DetectedBehaviors = append(result.DetectedBehaviors, p.description)
			result.RiskScore += a.riskLevelToScore(p.riskLevel)

			result.SimulatedCalls = append(result.SimulatedCalls, SimulatedCall{
				Type:      SysCallUname,
				Name:      p.description,
				Args:      []string{},
				ReturnVal: "simulated",
				IsAllowed: true,
				Reason:    "System info gathering - low risk",
				Timestamp: time.Now(),
				RiskLevel: p.riskLevel,
			})
		}
	}
}

func (a *SandboxAnalyzer) analyzeProcessCreation(payload string, result *SandboxResult) {
	processIndicators := []struct {
		keyword     string
		intent      SandboxIntent
		riskLevel   ThreatLevel
		description string
	}{
		{"fork(", IntentProcessCreation, ThreatLevelMedium, "Process fork"},
		{"vfork(", IntentProcessCreation, ThreatLevelMedium, "Process vfork"},
		{"clone(", IntentProcessCreation, ThreatLevelMedium, "Process clone"},
		{"wait4(", IntentProcessCreation, ThreatLevelMedium, "Wait for process"},
		{"kill(", IntentProcessCreation, ThreatLevelHigh, "Send signal"},
		{"ptrace(", IntentProcessCreation, ThreatLevelHigh, "Process tracing"},
		{"prctl(", IntentProcessCreation, ThreatLevelMedium, "Process control"},
		{"nohup ", IntentProcessCreation, ThreatLevelHigh, "Background process"},
	}

	payloadLower := strings.ToLower(payload)
	for _, p := range processIndicators {
		if strings.Contains(payloadLower, strings.ToLower(p.keyword)) {
			result.Intents = append(result.Intents, p.intent)
			result.DetectedBehaviors = append(result.DetectedBehaviors, p.description)
			result.RiskScore += a.riskLevelToScore(p.riskLevel)
		}
	}
}

func (a *SandboxAnalyzer) detectObfuscationTechniques(payload string, result *SandboxResult) {
	obfuscationIndicators := []struct {
		keyword     string
		description string
		riskLevel   ThreatLevel
	}{
		{"base64_decode", "Base64 decode obfuscation"},
		{"base64_encode", "Base64 encode obfuscation"},
		{"str_rot13", "ROT13 obfuscation"},
		{"hex2bin", "Hexadecimal obfuscation"},
		{"chr(", "Character conversion obfuscation"},
		{"ord(", "ASCII conversion obfuscation"},
		{"pack(", "Pack function obfuscation"},
		{"unpack(", "Unpack function obfuscation"},
		{"\\x", "Hexadecimal escape obfuscation"},
		{"\\u", "Unicode escape obfuscation"},
		{"$GLOBALS", "Global variable obfuscation"},
		{"assert(", "Assert code execution"},
		{"create_function", "Dynamic function creation"},
		{"call_user_func", "Callback function execution"},
		{"preg_replace", "Preg_replace code execution"},
	}

	payloadLower := strings.ToLower(payload)
	for _, p := range obfuscationIndicators {
		if strings.Contains(payloadLower, strings.ToLower(p.keyword)) {
			result.DetectedBehaviors = append(result.DetectedBehaviors, p.description)
			result.RiskScore += a.riskLevelToScore(p.riskLevel)

			if strings.Contains(p.description, "execution") || strings.Contains(p.description, "code") {
				result.Intents = append(result.Intents, IntentCodeExecution)
			}
		}
	}
}

func (a *SandboxAnalyzer) calculateOverallRisk(result *SandboxResult) {
	if len(result.Intents) == 0 && len(result.DetectedBehaviors) == 0 {
		result.ThreatLevel = ThreatLevelSafe
		result.RiskScore = 0.0
		result.Allowed = true
		return
	}

	highIntentCount := 0
	criticalIntentCount := 0

	for _, intent := range result.Intents {
		switch intent {
		case IntentCodeExecution, IntentFileWrite, IntentFileDelete, IntentProcessCreation:
			highIntentCount++
		case IntentRegistryAccess:
			criticalIntentCount++
		}
	}

	if criticalIntentCount > 0 {
		result.ThreatLevel = ThreatLevelCritical
		result.RiskScore = 1.0
		result.Allowed = false
		result.Recommendations = append(result.Recommendations, "Critical operation detected, recommend immediate block")
	} else if highIntentCount >= 2 {
		result.ThreatLevel = ThreatLevelHigh
		result.RiskScore = 0.8
		result.Allowed = false
		result.Recommendations = append(result.Recommendations, "Multiple high-risk operations detected, recommend block")
	} else if highIntentCount >= 1 {
		result.ThreatLevel = ThreatLevelMedium
		result.RiskScore = 0.5
		result.Allowed = true
		result.Recommendations = append(result.Recommendations, "Suspicious operation detected, recommend logging")
	} else {
		result.ThreatLevel = ThreatLevelLow
		result.RiskScore = 0.2
		result.Allowed = true
		result.Recommendations = append(result.Recommendations, "Minor suspicious behavior detected, monitor")
	}

	for _, factor := range result.RiskFactors {
		if strings.Contains(factor, "passwd") || strings.Contains(factor, "shadow") || strings.Contains(factor, "xp_cmdshell") {
			result.ThreatLevel = ThreatLevelCritical
			result.RiskScore = 1.0
			result.Allowed = false
			result.Recommendations = []string{"Critical security threat detected, must block"}
			break
		}
	}

	if result.RiskScore > 1.0 {
		result.RiskScore = 1.0
	}
}

func (a *SandboxAnalyzer) intentToThreatLevel(intent SandboxIntent) ThreatLevel {
	switch intent {
	case IntentCodeExecution:
		return ThreatLevelHigh
	case IntentFileWrite, IntentFileDelete:
		return ThreatLevelHigh
	case IntentNetworkAccess:
		return ThreatLevelMedium
	case IntentFileRead:
		return ThreatLevelMedium
	case IntentSystemInfo:
		return ThreatLevelLow
	case IntentProcessCreation:
		return ThreatLevelHigh
	case IntentRegistryAccess:
		return ThreatLevelHigh
	default:
		return ThreatLevelLow
	}
}

func (a *SandboxAnalyzer) intentToSysCall(intent SandboxIntent) SystemCallType {
	switch intent {
	case IntentCodeExecution:
		return SysCallExecve
	case IntentFileRead:
		return SysCallRead
	case IntentFileWrite:
		return SysCallWrite
	case IntentFileDelete:
		return SysCallUnlink
	case IntentNetworkAccess:
		return SysCallConnect
	case IntentSystemInfo:
		return SysCallUname
	case IntentProcessCreation:
		return SysCallFork
	case IntentRegistryAccess:
		return SysCallOpen
	default:
		return SysCallUnknown
	}
}

func (a *SandboxAnalyzer) riskLevelToScore(level ThreatLevel) float64 {
	switch level {
	case ThreatLevelCritical:
		return 0.4
	case ThreatLevelHigh:
		return 0.25
	case ThreatLevelMedium:
		return 0.15
	case ThreatLevelLow:
		return 0.05
	default:
		return 0.0
	}
}

func (a *SandboxAnalyzer) getRecommendationForIntent(intent SandboxIntent) string {
	switch intent {
	case IntentCodeExecution:
		return "Block code execution attack, check input validation"
	case IntentFileRead:
		return "Restrict path traversal, check permission config"
	case IntentFileWrite:
		return "Block unauthorized file write, verify file path"
	case IntentFileDelete:
		return "Block file deletion, check permissions"
	case IntentNetworkAccess:
		return "Restrict network requests, verify request target"
	case IntentSystemInfo:
		return "Monitor system info gathering behavior"
	case IntentProcessCreation:
		return "Restrict process creation, audit parent process"
	case IntentRegistryAccess:
		return "Block registry operations, security harden system"
	default:
		return "Manual review required"
	}
}

func (a *SandboxAnalyzer) extractFunctionArgs(payload string, pattern string) []string {
	re := a.patternCache.GetMust(pattern)
	matches := re.FindStringSubmatch(payload)
	if len(matches) > 0 {
		return []string{"matched: " + matches[0]}
	}
	return []string{}
}

type SandboxExecutionResult struct {
	Allowed          bool
	BlockedReason    string
	DetectedIntents  []SandboxIntent
	RiskAssessment   *RiskAssessment
	CallTrace        []SimulatedCall
	EnvironmentState map[string]interface{}
}

type RiskAssessment struct {
	OverallScore      float64
	ThreatCategory    string
	Severity          string
	RecommendedAction string
	DetailedAnalysis  []string
}

func SimulatePayloadExecution(payload string) *SandboxExecutionResult {
	analyzer := NewSandboxAnalyzer()
	input := &AnalysisInput{
		Raw: payload,
	}
	result := analyzer.Analyze(input)

	sandboxResult := &SandboxExecutionResult{
		Allowed:          result.ShouldAllow,
		DetectedIntents:  make([]SandboxIntent, 0),
		CallTrace:        make([]SimulatedCall, 0),
		EnvironmentState: make(map[string]interface{}),
	}

	if sandboxData, ok := result.Details["sandbox_result"].(map[string]interface{}); ok {
		if intents, ok := sandboxData["intents"].([]SandboxIntent); ok {
			sandboxResult.DetectedIntents = intents
		}
	}

	if len(result.Matches) > 0 {
		sandboxResult.BlockedReason = result.Matches[0].Recommendation
	}

	sandboxResult.RiskAssessment = &RiskAssessment{
		OverallScore:      result.RiskScore,
		ThreatCategory:    result.ThreatLevel.String(),
		Severity:          result.ThreatLevel.String(),
		RecommendedAction: "block",
		DetailedAnalysis:  make([]string, 0),
	}

	for _, match := range result.Matches {
		sandboxResult.RiskAssessment.DetailedAnalysis = append(
			sandboxResult.RiskAssessment.DetailedAnalysis,
			match.Description,
		)
	}

	return sandboxResult
}
