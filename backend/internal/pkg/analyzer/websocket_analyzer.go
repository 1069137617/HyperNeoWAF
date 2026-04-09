package analyzer

import (
	"crypto/sha1"
	"encoding/base64"
	"regexp"
	"strings"
	"sync"
	"time"
)

type WebSocketAnalyzer struct {
	name         string
	version      string
	analyzerType string
	enabled      bool
	config       map[string]interface{}
	mu           sync.RWMutex
}

func NewWebSocketAnalyzer() *WebSocketAnalyzer {
	return &WebSocketAnalyzer{
		name:         "websocket_analyzer",
		version:      "1.0.0",
		analyzerType: "websocket",
		enabled:      true,
		config:       make(map[string]interface{}),
	}
}

func (a *WebSocketAnalyzer) Name() string {
	return a.name
}

func (a *WebSocketAnalyzer) Type() string {
	return a.analyzerType
}

func (a *WebSocketAnalyzer) Version() string {
	return a.version
}

func (a *WebSocketAnalyzer) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

func (a *WebSocketAnalyzer) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

func (a *WebSocketAnalyzer) Configure(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = config
	return nil
}

func (a *WebSocketAnalyzer) Analyze(input *AnalysisInput) *AnalysisResult {
	start := time.Now()
	result := NewAnalysisResult(a)

	if input == nil {
		return result
	}

	a.analyzeWebSocketHandshake(input, result)
	a.analyzeWebSocketMessages(input, result)
	a.analyzeWebSocketAttacks(input, result)

	result.ProcessingTime = time.Since(start)
	result.ShouldBlock = result.ShouldBlockRequest(0.6)
	if len(result.Matches) > 0 {
		result.ShouldLog = true
		result.ShouldAllow = !result.ShouldBlock
	}

	return result
}

func (a *WebSocketAnalyzer) analyzeWebSocketHandshake(input *AnalysisInput, result *AnalysisResult) {
	if input.Headers == nil {
		return
	}

	upgrade := strings.ToLower(input.Headers["Upgrade"])
	if upgrade == "websocket" || upgrade == "websocket, chat" {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelLow,
			Pattern:        "Upgrade: websocket",
			Description:    "WebSocket握手请求检测",
			Recommendation: "监控WebSocket连接建立",
		})
	}

	hasKey := input.Headers["Sec-WebSocket-Key"] != ""
	hasAccept := input.Headers["Sec-WebSocket-Accept"] != ""
	hasVersion := input.Headers["Sec-WebSocket-Version"] != ""

	if hasKey {
		if !a.isValidWebSocketKey(input.Headers["Sec-WebSocket-Key"]) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelMedium,
				Pattern:        "Sec-WebSocket-Key",
				Description:    "无效的WebSocket Key格式",
				Recommendation: "验证WebSocket握手请求合法性",
			})
		} else {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelLow,
				Pattern:        "Sec-WebSocket-Key",
				Description:    "WebSocket握手Key有效",
				Recommendation: "正常WebSocket连接",
			})
		}
	}

	if hasAccept {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelLow,
			Pattern:        "Sec-WebSocket-Accept",
			Description:    "WebSocket握手Accept头存在",
			Recommendation: "服务端握手响应",
		})
	}

	if hasVersion {
		version := input.Headers["Sec-WebSocket-Version"]
		if version != "13" && version != "7" && version != "8" {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelLow,
				Pattern:        "Sec-WebSocket-Version",
				Description:    "非标准WebSocket版本: " + version,
				Recommendation: "建议使用标准版本13",
			})
		}
	}

	protocol := input.Headers["Sec-WebSocket-Protocol"]
	if protocol != "" {
		a.analyzeWebSocketProtocol(protocol, result)
	}

	extensions := input.Headers["Sec-WebSocket-Extensions"]
	if extensions != "" {
		a.analyzeWebSocketExtensions(extensions, result)
	}
}

func (a *WebSocketAnalyzer) isValidWebSocketKey(key string) bool {
	if len(key) < 16 || len(key) > 24 {
		return false
	}

	pattern := regexp.MustCompile(`^[A-Za-z0-9+\-=/]+$`)
	return pattern.MatchString(key)
}

func (a *WebSocketAnalyzer) analyzeWebSocketProtocol(protocol string, result *AnalysisResult) {
	dangerousProtocols := []string{
		"mqtt", "wamp", "graphql", "soap", "xml",
		"json-rpc", "jsonrpc", "protobuf", "msgpack",
	}

	protocolLower := strings.ToLower(protocol)
	for _, dp := range dangerousProtocols {
		if strings.Contains(protocolLower, dp) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelMedium,
				Pattern:        "Sec-WebSocket-Protocol",
				Description:    "WebSocket子协议包含敏感协议: " + dp,
				Recommendation: "验证子协议安全性",
			})
			break
		}
	}
}

func (a *WebSocketAnalyzer) analyzeWebSocketExtensions(extensions string, result *AnalysisResult) {
	extensionList := strings.Split(extensions, ",")
	for _, ext := range extensionList {
		ext = strings.TrimSpace(ext)
		extLower := strings.ToLower(ext)

		if strings.Contains(extLower, "permessage-deflate") {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelLow,
				Pattern:        "permessage-deflate",
				Description:    "WebSocket压缩扩展",
				Recommendation: "注意压缩相关攻击面",
			})
		}

		if strings.Contains(extLower, "x-webkit-deflate-frame") {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelLow,
				Pattern:        "x-webkit-deflate-frame",
				Description:    "WebKit压缩扩展(已废弃)",
				Recommendation: "建议使用标准permessage-deflate",
			})
		}

		if strings.Contains(extLower, "achment") || strings.Contains(extLower, "x-attachment") {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelMedium,
				Pattern:        ext,
				Description:    "WebSocket附件扩展",
				Recommendation: "验证文件传输安全性",
			})
		}
	}
}

func (a *WebSocketAnalyzer) analyzeWebSocketMessages(input *AnalysisInput, result *AnalysisResult) {
	if input.Body == "" {
		return
	}

	data := input.Body

	a.analyzeWebSocketFrame(data, result)
	a.analyzeMaskedData(data, result)
	a.analyzeWebSocketPayload(data, result)
}

func (a *WebSocketAnalyzer) analyzeWebSocketFrame(data string, result *AnalysisResult) {
	if len(data) < 2 {
		return
	}

	firstByte := data[0]
	secondByte := data[1]

	opcode := firstByte & 0x0F
	opcodes := map[uint8]string{
		0x0: "continuation",
		0x1: "text",
		0x2: "binary",
		0x8: "close",
		0x9: "ping",
		0xA: "pong",
	}

	opcodeName, exists := opcodes[opcode]
	if exists {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelLow,
			Pattern:        "opcode",
			Description:    "WebSocket帧类型: " + opcodeName,
			Recommendation: "监控WebSocket消息类型",
		})
	} else {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelHigh,
			Pattern:        "opcode",
			Description:    "未知WebSocket操作码: " + string(rune(opcode)),
			Recommendation: "拒绝未知操作码的帧",
		})
	}

	isMasked := (secondByte & 0x80) != 0
	payloadLen := uint64(secondByte & 0x7F)

	if isMasked {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelLow,
			Pattern:        "masked",
			Description:    "客户端发送的掩码帧",
			Recommendation: "正常WebSocket客户端行为",
		})
	} else {
		if len(data) > 2 {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelMedium,
				Pattern:        "unmasked",
				Description:    "客户端发送未掩码帧(协议违规)",
				Recommendation: "服务器应拒绝未掩码帧",
			})
		}
	}

	if payloadLen == 126 {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelLow,
			Pattern:        "extended-payload",
			Description:    "WebSocket扩展Payload长度",
			Recommendation: "正常大数据帧",
		})
	} else if payloadLen == 127 {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelLow,
			Pattern:        "large-payload",
			Description:    "WebSocket超长Payload长度",
			Recommendation: "监控大帧数据",
		})
	}
}

func (a *WebSocketAnalyzer) analyzeMaskedData(data string, result *AnalysisResult) {
	maskingPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`^[A-Za-z0-9+/=]{16,}$`, "Base64编码数据", ThreatLevelLow},
		{`[\x00-\x1F]`, "控制字符", ThreatLevelMedium},
		{`[\x80-\xFF]`, "高位字节(非ASCII)", ThreatLevelMedium},
	}

	for _, p := range maskingPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.description,
				Description:    "WebSocket数据包含: " + p.description,
				Recommendation: "验证数据内容",
			})
		}
	}
}

func (a *WebSocketAnalyzer) analyzeWebSocketPayload(data string, result *AnalysisResult) {
	xssPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)<script`, "Script标签注入", ThreatLevelCritical},
		{`(?i)javascript:`, "JavaScript协议", ThreatLevelCritical},
		{`(?i)on\w+\s*=`, "事件处理器", ThreatLevelCritical},
		{`(?i)<iframe`, "IFrame注入", ThreatLevelHigh},
		{`(?i)<img[^>]*src=`, "图片标签src属性", ThreatLevelHigh},
		{`(?i)<svg`, "SVG注入", ThreatLevelHigh},
		{`(?i)<object`, "对象注入", ThreatLevelHigh},
		{`(?i)<embed`, "Embed注入", ThreatLevelHigh},
		{`(?i)eval\s*\(`, "Eval执行", ThreatLevelCritical},
		{`(?i)Function\s*\(`, "函数构造", ThreatLevelCritical},
		{`(?i)document\.cookie`, "Cookie访问", ThreatLevelCritical},
		{`(?i)document\.write`, "文档写入", ThreatLevelCritical},
		{`(?i)innerHTML\s*=`, "InnerHTML赋值", ThreatLevelHigh},
		{`(?i)xmlhttprequest`, "AJAX请求", ThreatLevelMedium},
		{`(?i)fetch\s*\(`, "Fetch请求", ThreatLevelMedium},
	}

	for _, p := range xssPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "WebSocket XSS攻击: " + p.description,
				Recommendation: "在输出时进行HTML编码",
			})
		}
	}

	injectionPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\bSELECT\b.*\bFROM\b`, "SQL SELECT查询", ThreatLevelHigh},
		{`(?i)\bINSERT\b.*\bINTO\b`, "SQL INSERT语句", ThreatLevelHigh},
		{`(?i)\bUPDATE\b.*\bSET\b`, "SQL UPDATE语句", ThreatLevelHigh},
		{`(?i)\bDELETE\b.*\bFROM\b`, "SQL DELETE语句", ThreatLevelHigh},
		{`(?i)\bDROP\b.*\bTABLE\b`, "SQL DROP表", ThreatLevelCritical},
		{`(?i)\bUNION\b.*\bSELECT\b`, "SQL UNION注入", ThreatLevelCritical},
		{`--\s*$`, "SQL注释", ThreatLevelMedium},
		{`;\s*DROP\b`, "堆叠查询DROP", ThreatLevelCritical},
		{`;\s*DELETE\b`, "堆叠查询DELETE", ThreatLevelCritical},
	}

	for _, p := range injectionPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "WebSocket SQL注入: " + p.description,
				Recommendation: "使用参数化查询",
			})
		}
	}

	commandPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`[;|\$`(){}]`, "命令分隔符", ThreatLevelHigh},
		{`\b(cat|ls|dir|echo|cd|pwd)\b`, "系统命令", ThreatLevelHigh},
		{`\b(rm|mv|cp|chmod|chown)\b`, "文件操作命令", ThreatLevelHigh},
		{`\b(wget|curl|nc|telnet|ssh)\b`, "网络命令", ThreatLevelHigh},
		{`\b(whoami|id|uname|ps)\b`, "信息收集命令", ThreatLevelMedium},
		{`\b(python|perl|ruby|php|bash|sh)\b`, "脚本解释器", ThreatLevelHigh},
		{`>\s*/dev/null`, "输出重定向", ThreatLevelMedium},
		{`2>\s*&1`, "错误重定向", ThreatLevelMedium},
	}

	for _, p := range commandPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "WebSocket命令注入: " + p.description,
				Recommendation: "避免直接执行用户输入",
			})
		}
	}
}

func (a *WebSocketAnalyzer) analyzeWebSocketAttacks(input *AnalysisInput, result *AnalysisResult) {
	data := input.Raw + " " + input.Path + " " + input.QueryString + " " + input.Body

	a.analyzeWebSocketFlooding(data, result)
	a.analyzeWebSocketCrossSite(data, result)
	a.analyzeWebSocketHijacking(data, result)
	a.analyzeWebSocketProtocolAbuse(data, result)
}

func (a *WebSocketAnalyzer) analyzeWebSocketFlooding(data string, result *AnalysisResult) {
	highFrequencyPatterns := []string{
		`(?i)ping`,
		`(?i)pong`,
		`(?i)heartbeat`,
		`(?i)keep-alive`,
		`(?i)keepalive`,
	}

	matchCount := 0
	for _, pattern := range highFrequencyPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllString(data, -1)
		matchCount += len(matches)
	}

	if matchCount > 10 {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelHigh,
			Pattern:        "high-frequency",
			Description:    "高频WebSocket消息(疑似洪水攻击)",
			Recommendation: "限制连接频率和消息数量",
		})
	}
}

func (a *WebSocketAnalyzer) analyzeWebSocketCrossSite(data string, result *AnalysisResult) {
	crossSitePatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)origin:\s*http`, "跨域Origin头", ThreatLevelMedium},
		{`(?i)access-control`, "CORS相关", ThreatLevelMedium},
		{`(?i)postmessage`, "postMessage通信", ThreatLevelMedium},
		{`(?i)cors\.`, "CORS API", ThreatLevelLow},
		{`withCredentials`, "跨域凭证", ThreatLevelMedium},
	}

	for _, p := range crossSitePatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "跨域WebSocket: " + p.description,
				Recommendation: "验证Origin头限制",
			})
		}
	}
}

func (a *WebSocketAnalyzer) analyzeWebSocketHijacking(data string, result *AnalysisResult) {
	hijackingPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)stolen`, "被窃取的WebSocket", ThreatLevelCritical},
		{`(?i)hijack`, "WebSocket劫持", ThreatLevelCritical},
		{`(?i)intercept`, "WebSocket拦截", ThreatLevelHigh},
		{`(?i)tap`, "中间人攻击", ThreatLevelHigh},
		{`(?i)sniff`, "流量嗅探", ThreatLevelMedium},
		{`(?i)mitm`, "中间人", ThreatLevelHigh},
	}

	for _, p := range hijackingPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "WebSocket劫持攻击: " + p.description,
				Recommendation: "使用WSS加密连接",
			})
		}
	}
}

func (a *WebSocketAnalyzer) analyzeWebSocketProtocolAbuse(data string, result *AnalysisResult) {
	abusePatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`[\x00\xFF]`, "WebSocket控制字符", ThreatLevelMedium},
		{` fragmentation `, "WebSocket分片", ThreatLevelMedium},
		{`(?i)close\s*frame`, "WebSocket关闭帧", ThreatLevelLow},
		{`(?i)malformed`, "畸形WebSocket数据", ThreatLevelHigh},
		{`(?i)invalid`, "无效WebSocket数据", ThreatLevelMedium},
		{`(?i)overflow`, "缓冲区溢出", ThreatLevelCritical},
		{`(?i)underflow`, "缓冲区下溢", ThreatLevelHigh},
		{`(?i)NULL\s*byte`, "空字节注入", ThreatLevelMedium},
		{`[\xE0-\xEF][\x80-\xBF]`, "UTF-8无效序列", ThreatLevelMedium},
	}

	for _, p := range abusePatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "WebSocket协议滥用: " + p.description,
				Recommendation: "严格验证协议格式",
			})
		}
	}
}

func verifyWebSocketAccept(key string, expected string) bool {
	var keyData = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	h.Write([]byte(keyData))
	sha1Hash := h.Sum(nil)
	accept := base64.StdEncoding.EncodeToString(sha1Hash)
	return accept == expected
}
