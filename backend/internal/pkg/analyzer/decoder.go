package analyzer

import (
	"encoding/base64"
	"html"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type DecoderAnalyzer struct {
	name         string
	version      string
	analyzerType string
	enabled      bool
	config       map[string]interface{}
	maxDepth     int
	mu           sync.RWMutex
	seenHashes   map[string]bool
	hashMu       sync.Mutex
}

func NewDecoderAnalyzer() *DecoderAnalyzer {
	return &DecoderAnalyzer{
		name:         "decoder_analyzer",
		version:      "1.0.0",
		analyzerType: "decoder",
		enabled:      true,
		config:       make(map[string]interface{}),
		maxDepth:     10,
		seenHashes:   make(map[string]bool),
	}
}

func (a *DecoderAnalyzer) Name() string {
	return a.name
}

func (a *DecoderAnalyzer) Type() string {
	return a.analyzerType
}

func (a *DecoderAnalyzer) Version() string {
	return a.version
}

func (a *DecoderAnalyzer) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

func (a *DecoderAnalyzer) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

func (a *DecoderAnalyzer) Configure(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = config
	if depth, ok := config["maxDepth"].(int); ok && depth > 0 {
		a.maxDepth = depth
	}
	return nil
}

func (a *DecoderAnalyzer) Analyze(input *AnalysisInput) *AnalysisResult {
	start := time.Now()
	result := NewAnalysisResult(a)

	if input == nil {
		result.ProcessingTime = time.Since(start)
		return result
	}

	a.hashMu.Lock()
	a.seenHashes = make(map[string]bool)
	a.hashMu.Unlock()

	dataToAnalyze := a.prepareData(input)
	allDecoded := a.decodeRecursive(dataToAnalyze, 0)

	a.analyzeEncodingDepth(dataToAnalyze, allDecoded, result)
	a.analyzeMultiLayerEncoded(dataToAnalyze, result)
	a.analyzeObfuscationPatterns(allDecoded, result)

	result.ProcessingTime = time.Since(start)

	if len(result.Matches) > 0 {
		result.ShouldBlock = result.ShouldBlockRequest(0.5)
		result.ShouldLog = true
		result.ShouldAllow = !result.ShouldBlock
	}

	return result
}

func (a *DecoderAnalyzer) prepareData(input *AnalysisInput) string {
	var sb strings.Builder
	sb.WriteString(input.Raw)
	sb.WriteString(" ")
	sb.WriteString(input.Path)
	sb.WriteString(" ")
	sb.WriteString(input.QueryString)
	sb.WriteString(" ")
	sb.WriteString(input.Body)
	return sb.String()
}

func (a *DecoderAnalyzer) decodeRecursive(data string, depth int) string {
	if depth >= a.maxDepth {
		return data
	}

	original := data

	data = a.decodeURLRecursive(data, 0)
	data = a.decodeUnicodeRecursive(data, 0)
	data = a.decodeHexRecursive(data, 0)
	data = a.decodeHTMLEntityRecursive(data, 0)
	data = a.decodeUTF7Recursive(data, 0)
	data = a.decodeJSEscapeRecursive(data, 0)
	data = a.decodeBase64Recursive(data, 0)

	if data == original {
		return data
	}

	if a.checkCycle(original, data) {
		return data
	}

	return a.decodeRecursive(data, depth+1)
}

func (a *DecoderAnalyzer) checkCycle(original, decoded string) bool {
	a.hashMu.Lock()
	defer a.hashMu.Unlock()

	hash := simpleHash(original + "->" + decoded)
	if a.seenHashes[hash] {
		return true
	}
	a.seenHashes[hash] = true
	return false
}

func simpleHash(s string) string {
	var hash int64 = 5381
	for _, c := range s {
		hash = ((hash << 5) + hash) + int64(c)
	}
	return strings.ToLower(itoa(hash))
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var result []byte
	for n > 0 {
		result = append([]byte{byte('0' + n%10)}, result...)
		n /= 10
	}
	return string(result)
}

func (a *DecoderAnalyzer) decodeURLRecursive(data string, depth int) string {
	if depth >= a.maxDepth {
		return data
	}

	decoded, err := url.QueryUnescape(data)
	if err != nil {
		return data
	}

	if decoded == data {
		return data
	}

	return a.decodeURLRecursive(decoded, depth+1)
}

func (a *DecoderAnalyzer) decodeUnicodeRecursive(data string, depth int) string {
	if depth >= a.maxDepth {
		return data
	}

	pattern := regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
	decoded := pattern.ReplaceAllStringFunc(data, func(match string) string {
		hex := match[2:]
		r, _ := utf8.DecodeRune([]byte{
			byte(hexToInt(hex[:2])),
			byte(hexToInt(hex[2:])),
		})
		return string(r)
	})

	if decoded == data {
		return data
	}

	return a.decodeUnicodeRecursive(decoded, depth+1)
}

func (a *DecoderAnalyzer) decodeHexRecursive(data string, depth int) string {
	if depth >= a.maxDepth {
		return data
	}

	pattern := regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	decoded := pattern.ReplaceAllStringFunc(data, func(match string) string {
		hex := match[2:]
		r, _ := utf8.DecodeRune([]byte{byte(hexToInt(hex))})
		return string(r)
	})

	if decoded == data {
		return data
	}

	return a.decodeHexRecursive(decoded, depth+1)
}

func (a *DecoderAnalyzer) decodeHTMLEntityRecursive(data string, depth int) string {
	if depth >= a.maxDepth {
		return data
	}

	decoded := html.UnescapeString(data)

	pattern := regexp.MustCompile(`&#x([0-9a-fA-F]+);`)
	decoded = pattern.ReplaceAllStringFunc(decoded, func(match string) string {
		hex := match[3 : len(match)-1]
		codePoint := int64(0)
		for _, c := range hex {
			codePoint = codePoint*16 + int64(hexToInt(string(c)))
		}
		r, _ := utf8.DecodeRune([]byte{byte(codePoint)})
		return string(r)
	})

	pattern2 := regexp.MustCompile(`&#(\d+);`)
	decoded = pattern2.ReplaceAllStringFunc(decoded, func(match string) string {
		numStr := match[2 : len(match)-1]
		var codePoint int64
		for _, c := range numStr {
			codePoint = codePoint*10 + int64(c-'0')
		}
		r, _ := utf8.DecodeRune([]byte{byte(codePoint)})
		return string(r)
	})

	if decoded == data {
		return data
	}

	return a.decodeHTMLEntityRecursive(decoded, depth+1)
}

func (a *DecoderAnalyzer) decodeUTF7Recursive(data string, depth int) string {
	if depth >= a.maxDepth {
		return data
	}

	pattern := regexp.MustCompile(`\+([A-Za-z0-9+/]+)-?`)
	matches := pattern.FindAllStringSubmatchIndex(data, -1)
	if len(matches) == 0 {
		return data
	}

	result := pattern.ReplaceAllStringFunc(data, func(match string) string {
		inner := match[1 : len(match)-1]
		if decoded, err := base64.StdEncoding.DecodeString(inner); err == nil {
			return string(decoded)
		}
		return match
	})

	if result == data {
		return data
	}

	return a.decodeUTF7Recursive(result, depth+1)
}

func (a *DecoderAnalyzer) decodeJSEscapeRecursive(data string, depth int) string {
	if depth >= a.maxDepth {
		return data
	}

	var decoded strings.Builder
	i := 0
	for i < len(data) {
		if i+1 < len(data) && data[i] == '\\' && data[i+1] == 'x' {
			if i+3 < len(data) {
				hex := data[i+2 : i+4]
				decoded.WriteByte(byte(hexToInt(hex)))
				i += 4
				continue
			}
		}

		if i+1 < len(data) && data[i] == '\\' && data[i+1] == 'u' {
			if i+5 < len(data) {
				hex := data[i+2 : i+6]
				r, _ := utf8.DecodeRune([]byte{
					byte(hexToInt(hex[:2])),
					byte(hexToInt(hex[2:])),
				})
				decoded.WriteRune(r)
				i += 6
				continue
			}
		}

		if i+1 < len(data) && data[i] == '\\' {
			nextChar := data[i+1]
			switch nextChar {
			case 'n':
				decoded.WriteByte('\n')
			case 'r':
				decoded.WriteByte('\r')
			case 't':
				decoded.WriteByte('\t')
			case '\\':
				decoded.WriteByte('\\')
			case '"':
				decoded.WriteByte('"')
			case '\'':
				decoded.WriteByte('\'')
			default:
				decoded.WriteByte(data[i])
				decoded.WriteByte(nextChar)
			}
			i += 2
			continue
		}

		decoded.WriteByte(data[i])
		i++
	}

	result := decoded.String()
	if result == data {
		return data
	}

	return a.decodeJSEscapeRecursive(result, depth+1)
}

func (a *DecoderAnalyzer) decodeBase64Recursive(data string, depth int) string {
	if depth >= a.maxDepth {
		return data
	}

	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(data)
		if err != nil {
			return data
		}
	}

	result := string(decoded)
	if !utf8.Valid([]byte(result)) {
		return data
	}

	return a.decodeBase64Recursive(result, depth+1)
}

func (a *DecoderAnalyzer) analyzeEncodingDepth(original, decoded string, result *AnalysisResult) {
	depth := 0
	tmp := original
	for depth < a.maxDepth {
		newTmp := a.decodeURLRecursive(tmp, 0)
		newTmp = a.decodeHTMLEntityRecursive(newTmp, 0)
		if newTmp == tmp {
			break
		}
		tmp = newTmp
		depth++
	}

	if depth > 3 {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelHigh,
			Pattern:        "multi_layer_encoding",
			Position:       0,
			Length:         len(original),
			Description:    "多层编码嵌套检测",
			Evidence:       original[:min(len(original), 100)],
			Recommendation: "分析编码层数，识别潜在的混淆攻击",
			AnalyzerName:   a.name,
		})
	}

	if len(decoded) > len(original)*2 && len(decoded) > 100 {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelMedium,
			Pattern:        "encoding_expansion",
			Position:       0,
			Length:         len(original),
			Description:    "编码后数据显著膨胀",
			Evidence:       original[:min(len(original), 50)],
			Recommendation: "检查编码膨胀是否用于绕过检测",
			AnalyzerName:   a.name,
		})
	}
}

func (a *DecoderAnalyzer) analyzeMultiLayerEncoded(data string, result *AnalysisResult) {
	multiLayerPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`%25[0-9a-fA-F]{2}`, "双重URL编码", ThreatLevelHigh},
		{`%253[0-9a-fA-F]`, "多重URL编码", ThreatLevelCritical},
		{`&#x[0-9a-fA-F]+;&#x[0-9a-fA-F]+;`, "多重HTML实体编码", ThreatLevelHigh},
		{`\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}`, "多重十六进制编码", ThreatLevelMedium},
		{`\\u[0-9a-fA-F]{4}\\u[0-9a-fA-F]{4}`, "多重Unicode编码", ThreatLevelMedium},
		{`\+[A-Za-z0-9+/]+\-`, "UTF-7编码模式", ThreatLevelHigh},
	}

	for _, p := range multiLayerPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       data[:min(len(data), 100)],
				Recommendation: "解码后重新检测恶意特征",
				AnalyzerName:   a.name,
			})
		}
	}
}

func (a *DecoderAnalyzer) analyzeObfuscationPatterns(data string, result *AnalysisResult) {
	obfuscationPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`[\x00-\x08\x0B\x0C\x0E-\x1F]`, "控制字符注入", ThreatLevelMedium},
		{`%00`, "空字节注入", ThreatLevelMedium},
		{`%0d%0a|%0a%0d`, "CRLF注入序列", ThreatLevelHigh},
		{`%20%20%20%20`, "多个空格编码", ThreatLevelLow},
		{`[\u200B\u200C\u200D]`, "零宽字符", ThreatLevelMedium},
		{`[\uFEFF]`, "BOM字符", ThreatLevelMedium},
		{`%\d{2}`, "部分编码字符", ThreatLevelLow},
		{`&#\d+;[^<]`, "孤立HTML实体", ThreatLevelLow},
	}

	for _, p := range obfuscationPatterns {
		re := regexp.MustCompile(p.pattern)
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
				Recommendation: "标准化输入并移除混淆字符",
				AnalyzerName:   a.name,
			})
		}
	}
}
