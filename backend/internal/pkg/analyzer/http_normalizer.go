package analyzer

import (
	"bufio"
	"bytes"
	regexp "regexp"
	"strings"
	"sync"
	"time"
)

type HTTPNormalizerAnalyzer struct {
	name         string
	version      string
	analyzerType string
	enabled      bool
	config       map[string]interface{}
	mu           sync.RWMutex
}

func NewHTTPNormalizerAnalyzer() *HTTPNormalizerAnalyzer {
	return &HTTPNormalizerAnalyzer{
		name:         "http_normalizer_analyzer",
		version:      "1.0.0",
		analyzerType: "http_normalizer",
		enabled:      true,
		config:       make(map[string]interface{}),
	}
}

func (a *HTTPNormalizerAnalyzer) Name() string {
	return a.name
}

func (a *HTTPNormalizerAnalyzer) Type() string {
	return a.analyzerType
}

func (a *HTTPNormalizerAnalyzer) Version() string {
	return a.version
}

func (a *HTTPNormalizerAnalyzer) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

func (a *HTTPNormalizerAnalyzer) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

func (a *HTTPNormalizerAnalyzer) Configure(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = config
	return nil
}

func (a *HTTPNormalizerAnalyzer) Analyze(input *AnalysisInput) *AnalysisResult {
	start := time.Now()
	result := NewAnalysisResult(a)

	if input == nil {
		result.ProcessingTime = time.Since(start)
		return result
	}

	a.analyzeHTTPMalformation(input, result)
	a.analyzeChunkedTransfer(input, result)
	a.analyzeHeaderAnomalies(input, result)
	a.analyzeMethodAnomalies(input, result)
	a.analyzeProtocolAnomalies(input, result)
	a.analyzeNewlineInjection(input, result)

	result.ProcessingTime = time.Since(start)

	if len(result.Matches) > 0 {
		result.ShouldBlock = result.ShouldBlockRequest(0.5)
		result.ShouldLog = true
		result.ShouldAllow = !result.ShouldBlock
	}

	return result
}

func (a *HTTPNormalizerAnalyzer) analyzeHTTPMalformation(input *AnalysisInput, result *AnalysisResult) {
	malformedPatterns := []struct {
		pattern     *regexp.Regexp
		description string
		threatLevel ThreatLevel
	}{
		{regexp.MustCompile(`(?:^|[^\\r])\n(?:[^\n])`), "缺少CR的换行符", ThreatLevelMedium},
		{regexp.MustCompile(`(?:^|[^\\r])\n\\r\\n(?:[^\n])`), "CRLF注入尝试", ThreatLevelHigh},
		{regexp.MustCompile(`\\r\\n\\r\\n\\r\\n`), "重复空行", ThreatLevelMedium},
		{regexp.MustCompile(`[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F]`), "非法控制字符", ThreatLevelHigh},
		{regexp.MustCompile(`(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\\x20{2,}`), "多个空格分隔", ThreatLevelMedium},
		{regexp.MustCompile(`(?:[^\\r])\\n$`), "行尾异常换行", ThreatLevelLow},
		{regexp.MustCompile(`\\r$`), "单独CR字符", ThreatLevelMedium},
	}

	for _, p := range malformedPatterns {
		if p.pattern.MatchString(input.Raw) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern.String(),
				Description:    p.description,
				Recommendation: "规范化HTTP请求格式",
				AnalyzerName:   a.name,
			})
		}
	}
}

func (a *HTTPNormalizerAnalyzer) analyzeChunkedTransfer(input *AnalysisInput, result *AnalysisResult) {
	if input.Headers == nil {
		return
	}

	teHeader := ""
	for k, v := range input.Headers {
		if strings.ToLower(k) == "transfer-encoding" {
			teHeader = v
			break
		}
	}

	if strings.Contains(strings.ToLower(teHeader), "chunked") {
		if !a.isValidChunkedBody(input.Body) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelMedium,
				Pattern:        "chunked_encoding",
				Description:    "分块传输编码格式异常",
				Recommendation: "验证分块传输编码格式是否正确",
				AnalyzerName:   a.name,
			})
		}

		chunkSizePattern := regexp.MustCompile(`(?i)([0-9a-f]+)\r\n`)
		matches := chunkSizePattern.FindAllStringSubmatchIndex(input.Body, -1)
		for _, match := range matches {
			sizeStr := input.Body[match[2]:match[3]]
			if len(sizeStr) > 8 {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    ThreatLevelHigh,
					Pattern:        "chunk_size_overflow",
					Description:    "分块大小异常大",
					Evidence:       sizeStr,
					Recommendation: "检查分块大小是否超出合理范围",
					AnalyzerName:   a.name,
				})
			}
		}

		if strings.Contains(input.Body, "0\r\n\r\n") {
			lastChunkPattern := regexp.MustCompile(`0\r\n\r\n$`)
			if !lastChunkPattern.MatchString(input.Body) {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    ThreatLevelMedium,
					Pattern:        "chunked_termination",
					Description:    "分块传输终止符异常",
					Recommendation: "验证分块传输是否正确终止",
					AnalyzerName:   a.name,
				})
			}
		}
	}
}

func (a *HTTPNormalizerAnalyzer) isValidChunkedBody(body string) bool {
	if !strings.Contains(strings.ToLower(body), "transfer-encoding") && body != "" {
		scanner := bufio.NewScanner(bytes.NewReader([]byte(body)))
		lineNum := 0
		inBody := false
		expectedSize := -1

		for scanner.Scan() {
			line := scanner.Text()
			lineNum++

			if lineNum > 100 {
				return false
			}

			if !inBody {
				sizeStr := strings.TrimSpace(line)
				if sizeStr == "" {
					continue
				}

				if sizeStr == "0" {
					inBody = true
					continue
				}

				var size int
				for _, c := range sizeStr {
					if c >= '0' && c <= '9' {
						size = size*16 + int(c-'0')
					} else if c >= 'a' && c <= 'f' {
						size = size*16 + int(c-'a'+10)
					} else if c >= 'A' && c <= 'F' {
						size = size*16 + int(c-'A'+10)
					} else {
						break
					}
				}
				expectedSize = size
				inBody = true
			} else {
				if expectedSize >= 0 && len(line) != expectedSize {
					return false
				}
				expectedSize = -1
				inBody = false
			}
		}

		if !inBody && expectedSize == -1 {
			return true
		}
	}

	return true
}

func (a *HTTPNormalizerAnalyzer) analyzeHeaderAnomalies(input *AnalysisInput, result *AnalysisResult) {
	if input.Headers == nil {
		return
	}

	duplicateHeaders := make(map[string]bool)
	for name := range input.Headers {
		lowerName := strings.ToLower(name)
		if strings.HasPrefix(lowerName, "x-") || strings.HasPrefix(lowerName, "x_") {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelLow,
				Pattern:        "custom_header",
				Description:    "自定义HTTP头: " + name,
				Recommendation: "记录自定义头以便审计",
				AnalyzerName:   a.name,
			})
		}

		if duplicateHeaders[lowerName] {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelMedium,
				Pattern:        "duplicate_header",
				Description:    "重复HTTP头: " + name,
				Recommendation: "检查是否存在重复头注入",
				AnalyzerName:   a.name,
			})
		}
		duplicateHeaders[lowerName] = true
	}

	hostHeaderSeen := false
	for name, value := range input.Headers {
		if strings.ToLower(name) == "host" {
			if hostHeaderSeen {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    ThreatLevelHigh,
					Pattern:        "multiple_host_headers",
					Description:    "多个Host头",
					Recommendation: "拒绝包含多个Host头的请求",
					AnalyzerName:   a.name,
				})
			}
			hostHeaderSeen = true

			if strings.Contains(value, "@") {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    ThreatLevelHigh,
					Pattern:        "host_header_injection",
					Description:    "Host头包含特殊字符",
					Evidence:       value,
					Recommendation: "验证Host头格式",
					AnalyzerName:   a.name,
				})
			}
		}

		if strings.Contains(value, "\r") || strings.Contains(value, "\n") {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelCritical,
				Pattern:        "header_newline_injection",
				Description:    "HTTP头包含换行符: " + name,
				Evidence:       value,
				Recommendation: "拒绝包含非法换行符的请求头",
				AnalyzerName:   a.name,
			})
		}
	}

	essentialHeaders := []string{"host"}
	for _, essential := range essentialHeaders {
		found := false
		for name := range input.Headers {
			if strings.ToLower(name) == essential {
				found = true
				break
			}
		}
		if !found {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelMedium,
				Pattern:        "missing_header",
				Description:    "缺少必要HTTP头: " + essential,
				Recommendation: "要求请求包含必要的HTTP头",
				AnalyzerName:   a.name,
			})
		}
	}
}

func (a *HTTPNormalizerAnalyzer) analyzeMethodAnomalies(input *AnalysisInput, result *AnalysisResult) {
	validMethods := map[string]bool{
		"GET":     true,
		"POST":    true,
		"PUT":     true,
		"DELETE":  true,
		"HEAD":    true,
		"OPTIONS": true,
		"PATCH":   true,
		"TRACE":   true,
		"CONNECT": true,
	}

	method := input.Method
	if method == "" {
		return
	}

	if !validMethods[strings.ToUpper(method)] {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelMedium,
			Pattern:        "non_standard_method",
			Description:    "非标准HTTP方法: " + method,
			Recommendation: "验证HTTP方法是否合法",
			AnalyzerName:   a.name,
		})
	}

	methodCasePattern := regexp.MustCompile(`^[A-Z]+$`)
	if !methodCasePattern.MatchString(method) {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelLow,
			Pattern:        "method_case_anomaly",
			Description:    "HTTP方法大小写异常: " + method,
			Recommendation: "HTTP方法应为大写",
			AnalyzerName:   a.name,
		})
	}

	lowercasePattern := regexp.MustCompile(`^[a-z]+$`)
	if lowercasePattern.MatchString(method) {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelLow,
			Pattern:        "method_lowercase",
			Description:    "HTTP方法为小写: " + method,
			Recommendation: "标准化HTTP方法为大写",
			AnalyzerName:   a.name,
		})
	}

	methodSpacingPattern := regexp.MustCompile(`(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)[\\x20]+\S+`)
	if methodSpacingPattern.MatchString(input.Raw) {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelMedium,
			Pattern:        "method_spacing",
			Description:    "HTTP方法后有多余空格或其他字符",
			Recommendation: "检查请求行格式",
			AnalyzerName:   a.name,
		})
	}
}

func (a *HTTPNormalizerAnalyzer) analyzeProtocolAnomalies(input *AnalysisInput, result *AnalysisResult) {
	protocolVersionPattern := regexp.MustCompile(`HTTP/(\d+)\.(\d+)`)
	matches := protocolVersionPattern.FindAllStringSubmatch(input.Raw, -1)

	for _, match := range matches {
		major := match[1]
		minor := match[2]

		if major != "1" {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelMedium,
				Pattern:        "non_http10_11",
				Description:    "非标准HTTP协议版本: HTTP/" + major + "." + minor,
				Recommendation: "仅支持HTTP/1.0和HTTP/1.1",
				AnalyzerName:   a.name,
			})
		}

		if major == "1" && minor != "0" && minor != "1" {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelLow,
				Pattern:        "http_version_minor",
				Description:    "HTTP/1子版本异常: HTTP/1." + minor,
				Recommendation: "仅支持HTTP/1.0和HTTP/1.1",
				AnalyzerName:   a.name,
			})
		}
	}

	versionSpacingPattern := regexp.MustCompile(`HTTP/\\s+(\\d+)\\.(\\d+)`)
	if versionSpacingPattern.MatchString(input.Raw) {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelMedium,
			Pattern:        "http_version_spacing",
			Description:    "HTTP版本与协议名之间有空格",
			Recommendation: "标准化HTTP版本格式",
			AnalyzerName:   a.name,
		})
	}

	versionCasePattern := regexp.MustCompile(`http/\d+\.\d+`)
	if versionCasePattern.MatchString(input.Raw) {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelLow,
			Pattern:        "http_version_case",
			Description:    "HTTP版本小写",
			Recommendation: "HTTP版本应为大写(HTTP/1.1)",
			AnalyzerName:   a.name,
		})
	}
}

func (a *HTTPNormalizerAnalyzer) analyzeNewlineInjection(input *AnalysisInput, result *AnalysisResult) {
	newlineInjectionPatterns := []struct {
		pattern     *regexp.Regexp
		description string
		threatLevel ThreatLevel
	}{
		{regexp.MustCompile(`(?:^|[^\\r])\\n(?:[\\x00-\\x1F]|GET |POST |PUT |DELETE )`), "请求行换行注入", ThreatLevelCritical},
		{regexp.MustCompile(`(?:^|[^\\r])\\r\\n(?:[\\x00-\\x1F]|GET |POST )`), "CRLF注入尝试", ThreatLevelCritical},
		{regexp.MustCompile(`\\r\\n(?:[\\x00-\\x1F]|Location\\s*:)`), "HTTP响应分裂头", ThreatLevelCritical},
		{regexp.MustCompile(`(?:^|[^\\r])\\n\\n`), "双换行注入", ThreatLevelHigh},
		{regexp.MustCompile(`(?:^|[^\\r])\\r\\n\\r\\n(?:[^\\r])`), "HTTP头注入", ThreatLevelHigh},
	}

	for _, p := range newlineInjectionPatterns {
		if p.pattern.MatchString(input.Raw) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern.String(),
				Description:    p.description,
				Recommendation: "拒绝包含非法换行序列的请求",
				AnalyzerName:   a.name,
			})
		}
	}

	if strings.Contains(input.Raw, "%0d%0a") || strings.Contains(input.Raw, "%0D%0A") {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelHigh,
			Pattern:        "url_encoded_crlf",
			Description:    "URL编码的CRLF注入",
			Recommendation: "解码后检测换行符",
			AnalyzerName:   a.name,
		})
	}

	nullBytePattern := regexp.MustCompile(`(?:^|[^\\x00])\\x00(?:[^\\x00]|$)`)
	if nullBytePattern.MatchString(input.Raw) {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelHigh,
			Pattern:        "null_byte_injection",
			Description:    "空字节注入",
			Recommendation: "移除空字节或拒绝请求",
			AnalyzerName:   a.name,
		})
	}
}

func (a *HTTPNormalizerAnalyzer) reassembleChunkedBody(body string) string {
	var result bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader([]byte(body)))

	for scanner.Scan() {
		line := scanner.Text()

		sizeStr := strings.TrimSpace(line)
		var size int
		for _, c := range sizeStr {
			if c >= '0' && c <= '9' {
				size = size*16 + int(c-'0')
			} else if c >= 'a' && c <= 'f' {
				size = size*16 + int(c-'a'+10)
			} else if c >= 'A' && c <= 'F' {
				size = size*16 + int(c-'A'+10)
			} else {
				break
			}
		}

		if size == 0 {
			break
		}

		buf := make([]byte, size)
		n := 0
		for n < size && scanner.Scan() {
			lineBytes := scanner.Bytes()
			copy(buf[n:], lineBytes)
			n += len(lineBytes)
		}
		result.Write(buf[:size])
	}

	return result.String()
}
