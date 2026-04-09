package analyzer

import (
	"bytes"
	"encoding/binary"
	"regexp"
	"strings"
	"sync"
	"time"
)

type GrpcAnalyzer struct {
	name         string
	version      string
	analyzerType string
	enabled      bool
	config       map[string]interface{}
	mu           sync.RWMutex
}

func NewGrpcAnalyzer() *GrpcAnalyzer {
	return &GrpcAnalyzer{
		name:         "grpc_analyzer",
		version:      "1.0.0",
		analyzerType: "grpc",
		enabled:      true,
		config:       make(map[string]interface{}),
	}
}

func (a *GrpcAnalyzer) Name() string {
	return a.name
}

func (a *GrpcAnalyzer) Type() string {
	return a.analyzerType
}

func (a *GrpcAnalyzer) Version() string {
	return a.version
}

func (a *GrpcAnalyzer) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

func (a *GrpcAnalyzer) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

func (a *GrpcAnalyzer) Configure(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = config
	return nil
}

func (a *GrpcAnalyzer) Analyze(input *AnalysisInput) *AnalysisResult {
	start := time.Now()
	result := NewAnalysisResult(a)

	if input == nil {
		return result
	}

	a.analyzeGrpcTraffic(input, result)
	a.analyzeGrpcMessages(input, result)
	a.analyzeProtobufPayload(input, result)
	a.analyzeGrpcAttacks(input, result)

	result.ProcessingTime = time.Since(start)
	result.ShouldBlock = result.ShouldBlockRequest(0.6)
	if len(result.Matches) > 0 {
		result.ShouldLog = true
		result.ShouldAllow = !result.ShouldBlock
	}

	return result
}

func (a *GrpcAnalyzer) analyzeGrpcTraffic(input *AnalysisInput, result *AnalysisResult) {
	if input.ContentType != "" {
		contentType := strings.ToLower(input.ContentType)
		if strings.Contains(contentType, "application/grpc") {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelLow,
				Pattern:        "Content-Type: application/grpc",
				Description:    "gRPC流量检测",
				Recommendation: "正常gRPC请求",
			})
		}
	}

	if input.Headers != nil {
		te := strings.ToLower(input.Headers["TE"])
		if te == "trailers" {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelLow,
				Pattern:        "TE: trailers",
				Description:    "gRPC传输编码",
				Recommendation: "正常gRPC请求",
			})
		}

		grpcEncoding := strings.ToLower(input.Headers["Grpc-Encoding"])
		if grpcEncoding != "" {
			a.analyzeGrpcEncoding(grpcEncoding, result)
		}

		grpcAccept := strings.ToLower(input.Headers["Grpc-Accept-Encoding"])
		if grpcAccept != "" {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelLow,
				Pattern:        "Grpc-Accept-Encoding",
				Description:    "gRPC支持压缩: " + grpcAccept,
				Recommendation: "注意压缩相关攻击面",
			})
		}
	}

	grpcMethod := input.Headers["X-Grpc-Method"]
	if grpcMethod != "" {
		a.analyzeGrpcMethod(grpcMethod, result)
	}

	grpcScheme := input.Headers["X-Grpc-Scheme"]
	if grpcScheme != "" {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelLow,
			Pattern:        "X-Grpc-Scheme",
			Description:    "gRPC协议: " + grpcScheme,
			Recommendation: "正常gRPC请求",
		})
	}
}

func (a *GrpcAnalyzer) analyzeGrpcEncoding(encoding string, result *AnalysisResult) {
	dangerousEncodings := []string{
		"gzip", "deflate", "br", "zstd",
	}

	encodingLower := strings.ToLower(encoding)
	for _, de := range dangerousEncodings {
		if encodingLower == de {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelMedium,
				Pattern:        "Grpc-Encoding",
				Description:    "gRPC压缩: " + de,
				Recommendation: "验证压缩数据安全性",
			})
			break
		}
	}
}

func (a *GrpcAnalyzer) analyzeGrpcMethod(method string, result *AnalysisResult) {
	methodParts := strings.Split(method, "/")
	if len(methodParts) >= 3 {
		service := methodParts[1]
		methodName := methodParts[2]

		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelLow,
			Pattern:        "X-Grpc-Method",
			Description:    "gRPC方法: " + service + "/" + methodName,
			Recommendation: "记录gRPC方法调用",
		})

		a.analyzeGrpcMethodName(methodName, result)
	}
}

func (a *GrpcAnalyzer) analyzeGrpcMethodName(methodName string, result *AnalysisResult) {
	dangerousMethods := []string{
		"exec", "execute", "run", "spawn",
		"delete", "remove", "destroy", "drop",
		"create", "modify", "update", "write",
		"admin", "debug", "test", "setup",
	}

	methodLower := strings.ToLower(methodName)
	for _, dm := range dangerousMethods {
		if strings.Contains(methodLower, dm) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelMedium,
				Pattern:        "dangerous-method",
				Description:    "敏感gRPC方法名: " + methodName,
				Recommendation: "验证gRPC方法调用权限",
			})
			break
		}
	}
}

func (a *GrpcAnalyzer) analyzeGrpcMessages(input *AnalysisInput, result *AnalysisResult) {
	if input.Body == "" {
		return
	}

	data := input.Body

	if len(data) >= 5 {
		a.analyzeGrpcFrame(data, result)
	}

	a.analyzeGrpcHeaders(data, result)
	a.analyzeGrpcMessageBody(data, result)
}

func (a *GrpcAnalyzer) analyzeGrpcFrame(data string, result *AnalysisResult) {
	if len(data) < 5 {
		return
	}

	firstByte := data[0]

	compressionFlag := (firstByte & 0x01) != 0
	messageLength := 0

	if compressionFlag {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelMedium,
			Pattern:        "grpc-compressed",
			Description:    "gRPC压缩消息",
			Recommendation: "验证压缩数据安全性",
		})
	}

	lengthBytes := []byte(data[1:5])
	messageLength = int(binary.BigEndian.Uint32(lengthBytes))

	if messageLength > 1024*1024*16 {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelHigh,
			Pattern:        "large-message",
			Description:    "超大gRPC消息: " + string(rune(messageLength)),
			Recommendation: "限制gRPC消息大小",
		})
	} else if messageLength > 1024*1024 {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelLow,
			Pattern:        "large-message",
			Description:    "大gRPC消息",
			Recommendation: "监控大消息传输",
		})
	}
}

func (a *GrpcAnalyzer) analyzeGrpcHeaders(data string, result *AnalysisResult) {
	headerPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)grpc-status`, "gRPC状态头", ThreatLevelLow},
		{`(?i)grpc-message`, "gRPC消息头", ThreatLevelLow},
		{`(?i)grpc-timeout`, "gRPC超时头", ThreatLevelMedium},
		{`(?i)grpc-encoding`, "gRPC编码头", ThreatLevelMedium},
		{`(?i)grpc-accept-encoding`, "gRPC接受编码头", ThreatLevelMedium},
		{`(?i)x-grpc-`, "gRPC自定义头", ThreatLevelLow},
	}

	for _, p := range headerPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "gRPC头信息: " + p.description,
				Recommendation: "正常gRPC流量",
			})
		}
	}
}

func (a *GrpcAnalyzer) analyzeGrpcMessageBody(data string, result *AnalysisResult) {
	a.analyzeProtobufParsing(data, result)
	a.analyzeJsonPayload(data, result)
}

func (a *GrpcAnalyzer) analyzeProtobufParsing(data string, result *AnalysisResult) {
	protobufPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`[\x0A\x12\x1A]`, "Protobuf字段标签", ThreatLevelLow},
		{`\x08\x01`, "Protobuf布尔true", ThreatLevelLow},
		{`\x08\x00`, "Protobuf布尔false", ThreatLevelLow},
		{`\x10[\x00-\xFF]`, "ProtobufVarInt", ThreatLevelLow},
		{`[\x12\x1A][\x00-\xFF]`, "Protobuf长度分隔字段", ThreatLevelLow},
		{`[\x0A\x12][\x00-\xFF]`, "Protobuf字符串字段", ThreatLevelLow},
	}

	for _, p := range protobufPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        "protobuf-tag",
				Description:    "Protobuf解析: " + p.description,
				Recommendation: "监控Protobuf反序列化",
			})
		}
	}
}

func (a *GrpcAnalyzer) analyzeJsonPayload(data string, result *AnalysisResult) {
	if strings.HasPrefix(data, "{") || strings.HasPrefix(data, "[") {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelLow,
			Pattern:        "json-payload",
			Description:    "JSON payload in gRPC",
			Recommendation: "验证JSON数据安全性",
		})

		jsonPatterns := []struct {
			pattern     string
			description string
			threatLevel ThreatLevel
		}{
			{`"type"\s*:\s*"`, "JSON类型字段", ThreatLevelMedium},
			{`"data"\s*:\s*"`, "JSON数据字段", ThreatLevelMedium},
			{`"cmd"\s*:\s*"`, "JSON命令字段", ThreatLevelHigh},
			{`"exec"\s*:\s*"`, "JSON执行字段", ThreatLevelCritical},
			{`"eval"\s*:\s*"`, "JSON eval字段", ThreatLevelCritical},
			{`"script"\s*:\s*"`, "JSON脚本字段", ThreatLevelHigh},
			{`"code"\s*:\s*"`, "JSON代码字段", ThreatLevelHigh},
		}

		for _, p := range jsonPatterns {
			re := regexp.MustCompile(p.pattern)
			if re.MatchString(data) {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    p.threatLevel,
					Pattern:        p.pattern,
					Description:    "可疑JSON字段: " + p.description,
					Recommendation: "验证JSON字段安全性",
				})
			}
		}
	}
}

func (a *GrpcAnalyzer) analyzeProtobufPayload(input *AnalysisInput, result *AnalysisResult) {
	if input.Body == "" {
		return
	}

	data := input.Body

	a.analyzeProtobufInjection(data, result)
	a.analyzeProtobufDeserialization(data, result)
	a.analyzeProtobufMalformed(data, result)
}

func (a *GrpcAnalyzer) analyzeProtobufInjection(data string, result *AnalysisResult) {
	injectionPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\bselect\b.*\bfrom\b`, "SQL SELECT注入", ThreatLevelHigh},
		{`(?i)\binsert\b.*\binto\b`, "SQL INSERT注入", ThreatLevelHigh},
		{`(?i)\bupdate\b.*\bset\b`, "SQL UPDATE注入", ThreatLevelHigh},
		{`(?i)\bdelete\b.*\bfrom\b`, "SQL DELETE注入", ThreatLevelHigh},
		{`(?i)\bdrop\b.*\btable\b`, "SQL DROP注入", ThreatLevelCritical},
		{`(?i)\bunion\b.*\bselect\b`, "SQL UNION注入", ThreatLevelCritical},
		{`(?i)\bexec\b`, "命令执行", ThreatLevelCritical},
		{`(?i)\beval\b`, "Eval执行", ThreatLevelCritical},
		{`(?i)\bassert\b`, "Assert执行", ThreatLevelHigh},
		{`(?i)\bsystem\b`, "系统调用", ThreatLevelCritical},
		{`\.\./`, "路径遍历", ThreatLevelHigh},
		{`\.\.\\`, "Windows路径遍历", ThreatLevelHigh},
		{`/etc/passwd`, "敏感文件访问", ThreatLevelCritical},
		{`c:\\windows`, "Windows敏感路径", ThreatLevelHigh},
	}

	for _, p := range injectionPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Protobuf注入攻击: " + p.description,
				Recommendation: "验证输入数据安全性",
			})
		}
	}
}

func (a *GrpcAnalyzer) analyzeProtobufDeserialization(data string, result *AnalysisResult) {
	deserializationPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)deserialize`, "反序列化操作", ThreatLevelHigh},
		{`(?i)unserialize`, "PHP反序列化", ThreatLevelCritical},
		{`(?i)pickle\.loads`, "Python pickle反序列化", ThreatLevelCritical},
		{`(?i)yaml\.load`, "YAML反序列化", ThreatLevelHigh},
		{`(?i)xml\.parse`, "XML解析", ThreatLevelMedium},
		{`(?i)xxe`, "XXE攻击", ThreatLevelCritical},
		{`(?i)external-entity`, "外部实体", ThreatLevelCritical},
	}

	for _, p := range deserializationPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Protobuf反序列化攻击: " + p.description,
				Recommendation: "避免不安全的反序列化",
			})
		}
	}
}

func (a *GrpcAnalyzer) analyzeProtobufMalformed(data string, result *AnalysisResult) {
	malformedPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`[\x00-\x08]`, "控制字符注入", ThreatLevelMedium},
		{`[\xE0-\xEF][\x80-\xBF][\x80-\xBF]`, "无效UTF-8序列", ThreatLevelMedium},
		{`[\xF0-\xF7][\x80-\xBF]{3}`, "无效UTF-8四字节序列", ThreatLevelMedium},
		{`[\xC0-\xC1]`, "过短UTF-8序列", ThreatLevelMedium},
		{`[\xF5-\xFF]`, "无效首字节", ThreatLevelMedium},
		{`[\xFE\xFF]`, "BOM字符", ThreatLevelLow},
	}

	for _, p := range malformedPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "畸形Protobuf数据: " + p.description,
				Recommendation: "严格验证Protobuf格式",
			})
		}
	}
}

func (a *GrpcAnalyzer) analyzeGrpcAttacks(input *AnalysisInput, result *AnalysisResult) {
	data := input.Raw + " " + input.Path + " " + input.QueryString + " " + input.Body

	a.analyzeGrpcReflected攻击(data, result)
	a.analyzeGrpcBufferOverflow(data, result)
	a.analyzeGrpcIntrusionPatterns(data, result)
}

func (a *GrpcAnalyzer) analyzeGrpcReflected攻击(data string, result *AnalysisResult) {
	reflectedPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)<script`, "Script标签", ThreatLevelCritical},
		{`(?i)javascript:`, "JavaScript协议", ThreatLevelCritical},
		{`(?i)on\w+\s*=`, "事件处理器", ThreatLevelCritical},
		{`(?i)<iframe`, "IFrame注入", ThreatLevelHigh},
		{`(?i)<img`, "图片标签", ThreatLevelMedium},
		{`(?i)<svg`, "SVG注入", ThreatLevelHigh},
	}

	for _, p := range reflectedPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "gRPC反射型攻击: " + p.description,
				Recommendation: "正确编码输出数据",
			})
		}
	}
}

func (a *GrpcAnalyzer) analyzeGrpcBufferOverflow(data string, result *AnalysisResult) {
	overflowPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`.{10000,}`, "超长字符串", ThreatLevelHigh},
		{`[\x41]{1000,}`, "重复字符A", ThreatLevelMedium},
		{`%s{100,}`, "格式化字符串%s", ThreatLevelHigh},
		{`%x{100,}`, "格式化字符串%x", ThreatLevelHigh},
		{`%n{100,}`, "格式化字符串%n", ThreatLevelCritical},
		{`\{.{1000,} \}`, "大括号嵌套", ThreatLevelMedium},
	}

	for _, p := range overflowPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "gRPC缓冲区溢出: " + p.description,
				Recommendation: "限制输入长度",
			})
		}
	}
}

func (a *GrpcAnalyzer) analyzeGrpcIntrusionPatterns(data string, result *AnalysisResult) {
	intrusionPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\.\./\.\./`, "目录遍历上级", ThreatLevelHigh},
		{`(?i)/etc/shadow`, "影子密码文件", ThreatLevelCritical},
		{`(?i)win\.ini`, "Windows配置文件", ThreatLevelMedium},
		{`(?i)\.htaccess`, "Apache配置文件", ThreatLevelHigh},
		{`(?i)\.git/config`, "Git配置文件", ThreatLevelMedium},
		{`(?i)phpmyadmin`, "PHPMyAdmin路径", ThreatLevelHigh},
		{`(?i)WEB-INF`, "Java WEB配置", ThreatLevelHigh},
		{`(?i)web\.config`, "NET配置文件", ThreatLevelHigh},
		{`(?i)sqlmap`, "SQLMap扫描工具", ThreatLevelHigh},
		{`(?i)nikto`, "Nikto扫描工具", ThreatLevelHigh},
		{`(?i)burp`, "BurpSuite工具", ThreatLevelMedium},
		{`(?i)netsparker`, "Netsparker扫描", ThreatLevelMedium},
	}

	for _, p := range intrusionPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "gRPC入侵检测: " + p.description,
				Recommendation: "记录并告警扫描行为",
			})
		}
	}
}

func detectGrpcTraffic(body []byte) bool {
	if len(body) < 5 {
		return false
	}

	firstByte := body[0]
	if firstByte&0x80 == 0 && firstByte&0x7F <= 127 {
		return true
	}

	return bytes.HasPrefix(body, []byte{0x00, 0x00, 0x00, 0x00, 0x00})
}

func parseGrpcMessageType(data []byte) string {
	if len(data) < 5 {
		return "unknown"
	}

	compressionFlag := (data[0] & 0x01) != 0
	if compressionFlag {
		return "compressed"
	}

	headerSize := 5
	messageLength := int(binary.BigEndian.Uint32(data[1:headerSize]))

	if len(data) >= headerSize+messageLength {
		messageData := data[headerSize : headerSize+messageLength]
		if len(messageData) > 0 {
			firstFieldTag := messageData[0]
			wireType := firstFieldTag & 0x07

			switch wireType {
			case 0:
				return "varint"
			case 1:
				return "fixed64"
			case 2:
				return "length-delimited"
			case 5:
				return "fixed32"
			}
		}
	}

	return "unknown"
}
