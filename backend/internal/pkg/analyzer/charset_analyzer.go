package analyzer

import (
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type CharsetAnalyzer struct {
	name         string
	version      string
	analyzerType string
	enabled      bool
	config       map[string]interface{}
	mu           sync.RWMutex
}

func NewCharsetAnalyzer() *CharsetAnalyzer {
	return &CharsetAnalyzer{
		name:         "charset_analyzer",
		version:      "1.0.0",
		analyzerType: "charset",
		enabled:      true,
		config:       make(map[string]interface{}),
	}
}

func (a *CharsetAnalyzer) Name() string {
	return a.name
}

func (a *CharsetAnalyzer) Type() string {
	return a.analyzerType
}

func (a *CharsetAnalyzer) Version() string {
	return a.version
}

func (a *CharsetAnalyzer) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

func (a *CharsetAnalyzer) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

func (a *CharsetAnalyzer) Configure(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = config
	return nil
}

func (a *CharsetAnalyzer) Analyze(input *AnalysisInput) *AnalysisResult {
	start := time.Now()
	result := NewAnalysisResult(a)

	if input == nil {
		return result
	}

	a.analyzeCharsetHeaders(input, result)
	a.analyzeGBKCharset(input, result)
	a.analyzeUTF8Charset(input, result)
	a.analyzeWideCharacterInjection(input, result)
	a.analyzeCharsetConfusion(input, result)

	result.ProcessingTime = time.Since(start)
	result.ShouldBlock = result.ShouldBlockRequest(0.6)
	if len(result.Matches) > 0 {
		result.ShouldLog = true
		result.ShouldAllow = !result.ShouldBlock
	}

	return result
}

func (a *CharsetAnalyzer) analyzeCharsetHeaders(input *AnalysisInput, result *AnalysisResult) {
	if input.Headers == nil {
		return
	}

	contentType := input.Headers["Content-Type"]
	if contentType != "" {
		a.analyzeContentTypeCharset(contentType, result)
	}

	acceptCharset := input.Headers["Accept-Charset"]
	if acceptCharset != "" {
		a.analyzeAcceptCharset(acceptCharset, result)
	}
}

func (a *CharsetAnalyzer) analyzeContentTypeCharset(contentType string, result *AnalysisResult) {
	charsetPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)charset\s*=\s*gbk`, "GBK字符集", ThreatLevelMedium},
		{`(?i)charset\s*=\s*gb2312`, "GB2312字符集", ThreatLevelMedium},
		{`(?i)charset\s*=\s*gb18030`, "GB18030字符集", ThreatLevelMedium},
		{`(?i)charset\s*=\s*utf-?8`, "UTF-8字符集", ThreatLevelLow},
		{`(?i)charset\s*=\s*utf-?16`, "UTF-16字符集", ThreatLevelMedium},
		{`(?i)charset\s*=\s*iso-8859-1`, "ISO-8859-1字符集", ThreatLevelMedium},
		{`(?i)charset\s*=\s*windows-1252`, "Windows-1252字符集", ThreatLevelMedium},
		{`(?i)charset\s*=\s*big5`, "Big5字符集(繁体中文)", ThreatLevelMedium},
		{`(?i)charset\s*=\s*shift_jis`, "Shift_JIS字符集(日文)", ThreatLevelMedium},
		{`(?i)charset\s*=\s*euc-kr`, "EUC-KR字符集(韩文)", ThreatLevelMedium},
		{`(?i)charset\s*=\s*iso-2022-jp`, "ISO-2022-JP字符集", ThreatLevelMedium},
	}

	for _, p := range charsetPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(contentType) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Content-Type字符集: " + p.description,
				Recommendation: "验证字符集使用安全性",
			})
		}
	}
}

func (a *CharsetAnalyzer) analyzeAcceptCharset(acceptCharset string, result *AnalysisResult) {
	result.AddMatch(Match{
		Type:           MatchTypeSemantic,
		ThreatLevel:    ThreatLevelLow,
		Pattern:        "Accept-Charset",
		Description:    "客户端接受字符集: " + acceptCharset,
		Recommendation: "记录客户端字符集偏好",
	})

	dangerousCharsets := []string{
		"gbk", "gb2312", "gb18030", "big5", "shift_jis",
	}

	acceptLower := strings.ToLower(acceptCharset)
	for _, dc := range dangerousCharsets {
		if strings.Contains(acceptLower, dc) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelMedium,
				Pattern:        "dangerous-charset",
				Description:    "客户端请求危险字符集: " + dc,
				Recommendation: "验证字符集转换安全性",
			})
		}
	}
}

func (a *CharsetAnalyzer) analyzeGBKCharset(input *AnalysisInput, result *AnalysisResult) {
	data := input.Raw + " " + input.QueryString + " " + input.Body

	highByteSequence := regexp.MustCompile(`[\x80-\xFF]{2,}`)
	if highByteSequence.MatchString(data) {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelMedium,
			Pattern:        "high-byte-sequence",
			Description:    "检测到高位字节序列(可能为GBK/UTF-16等双字节字符)",
			Recommendation: "验证字符集转换",
		})
	}

	gbkSpecific := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`[\x81-\xFE][\x40-\xFE]`, "GBK高位字节范围", ThreatLevelMedium},
		{`[\x81-\xFE][\x80-\xFE]`, "GBK汉字范围", ThreatLevelMedium},
		{`[\xA1-\xF7][\xA1-\xFE]`, "GBK GB2312兼容区", ThreatLevelMedium},
		{`[\x81-\x84][\x30-\x39]`, "GBK用户定义区1", ThreatLevelMedium},
		{`[\x95-\x98][\x30-\x39]`, "GBK用户定义区2", ThreatLevelMedium},
	}

	for _, p := range gbkSpecific {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        "gbk-specific",
				Description:    "GBK编码: " + p.description,
				Recommendation: "验证GBK编码转换",
			})
		}
	}

	gbkTraversal := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`[\x81-\xFE][\x40-\xFE][/\\]`, "GBK路径遍历", ThreatLevelHigh},
		{`[\x81-\xFE][\x40-\xFE]\.\.[/\\]`, "GBK上级目录遍历", ThreatLevelCritical},
		{`[\x81-\xFE][\x40-\xFE]etc[\x81-\xFE][\x40-\xFE]passwd`, "GBK /etc/passwd", ThreatLevelCritical},
		{`[\x81-\xFE][\x40-\xFE]c[\x81-\xFE][\x40-\xFE]:[\x81-\xFE][\x40-\xFE]windows`, "GBK Windows路径", ThreatLevelHigh},
	}

	for _, p := range gbkTraversal {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "GBK宽字符攻击: " + p.description,
				Recommendation: "使用UTF-8编码避免宽字符问题",
			})
		}
	}
}

func (a *CharsetAnalyzer) analyzeUTF8Charset(input *AnalysisInput, result *AnalysisResult) {
	data := input.Raw + " " + input.QueryString + " " + input.Body

	utf8Patterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`[\xC0-\xDF][\x80-\xBF]`, "UTF-8 两字节序列", ThreatLevelLow},
		{`[\xE0-\xEF][\x80-\xBF]{2}`, "UTF-8 三字节序列", ThreatLevelLow},
		{`[\xF0-\xF7][\x80-\xBF]{3}`, "UTF-8 四字节序列", ThreatLevelLow},
		{`[\xF8-\xFB][\x80-\xBF]{4}`, "UTF-8 五字节序列", ThreatLevelMedium},
		{`[\xFC-\xFD][\x80-\xBF]{5}`, "UTF-8 六字节序列", ThreatLevelMedium},
	}

	for _, p := range utf8Patterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        "utf8-sequence",
				Description:    "UTF-8编码: " + p.description,
				Recommendation: "验证UTF-8编码有效性",
			})
		}
	}

	invalidUTF8 := a.detectInvalidUTF8(data)
	if len(invalidUTF8) > 0 {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelMedium,
			Pattern:        "invalid-utf8",
			Description:    "检测到无效UTF-8序列: " + invalidUTF8,
			Recommendation: "拒绝无效UTF-8序列",
		})
	}

	overlongUTF8 := a.detectOverlongUTF8(data)
	if len(overlongUTF8) > 0 {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelHigh,
			Pattern:        "overlong-utf8",
			Description:    "检测到超长UTF-8编码: " + overlongUTF8,
			Recommendation: "拒绝超长UTF-8编码",
		})
	}
}

func (a *CharsetAnalyzer) detectInvalidUTF8(data string) string {
	invalids := make([]string, 0)
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRuneInString(data[i:])
		if r == utf8.RuneError && size == 1 {
			invalidSeq := data[i:min(i+4, len(data))]
			invalids = append(invalids, invalidSeq)
			i++
		} else {
			i += size
		}
	}

	if len(invalids) > 0 {
		return joinStrings(invalids[:min(3, len(invalids))], ", ")
	}
	return ""
}

func (a *CharsetAnalyzer) detectOverlongUTF8(data string) string {
	overlongPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`[\xC0-\xC1][\x80-\xBF]`, "超长两字节(应使用单字节)", ThreatLevelHigh},
		{`[\xE0-\xEF][\xC0-\xDF][\x80-\xBF]`, "超长三字节(应使用两字节)", ThreatLevelHigh},
		{`[\xF0-\xF7][\xC0-\xDF][\x80-\xBF]{2}`, "超长四字节(应使用三字节)", ThreatLevelHigh},
		{`[\xF8-\xFB][\xC0-\xDF][\x80-\xBF]{3}`, "超长五字节(应使用四字节)", ThreatLevelCritical},
		{`[\xFC-\xFD][\xC0-\xDF][\x80-\xBF]{4}`, "超长六字节(应使用五字节)", ThreatLevelCritical},
	}

	for _, p := range overlongPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			return p.description
		}
	}
	return ""
}

func (a *CharsetAnalyzer) analyzeWideCharacterInjection(input *AnalysisInput, result *AnalysisResult) {
	data := input.Raw + " " + input.QueryString + " " + input.Body

	wideCharTraversal := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`%c0%ae%c0%ae`, "Unicode双点遍历(..)", ThreatLevelCritical},
		{`%c0%2e%c0%2e`, "Unicode双点遍历变体", ThreatLevelCritical},
		{`%c1%9c`, "Unicode斜杠(/在Windows ACP)", ThreatLevelHigh},
		{`%c1%1c`, "Unicode反斜杠(\\在Windows ACP)", ThreatLevelHigh},
		{`%e0%80%80`, "Unicode null字节", ThreatLevelCritical},
		{`\u002e\u002e`, "Unicode双点(..)", ThreatLevelCritical},
		{`\u00e2\u0088\u0087`, "Unicode箭头(→)", ThreatLevelHigh},
		{`\u2215`, "Unicode斜杠(/ )", ThreatLevelMedium},
		{`\u2216`, "Unicode反斜杠(\\ )", ThreatLevelMedium},
		{`\u25c9`, "Unicode安全符号", ThreatLevelMedium},
		{`\uff0e\uff0e`, "全角双点", ThreatLevelMedium},
		{`\uff0f`, "全角斜杠", ThreatLevelMedium},
		{`\uff3c`, "全角反斜杠", ThreatLevelMedium},
	}

	for _, p := range wideCharTraversal {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "宽字符路径遍历: " + p.description,
				Recommendation: "规范化路径并验证字符安全性",
			})
		}
	}

	wideCharSQL := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`[\xC0-\xDF][\x80-\xBF]['\";=]`, "宽字符SQL注入引号", ThreatLevelHigh},
		{`[\xE0-\xEF][\x80-\xBF]{2}\b(or|and)\b`, "宽字符SQL关键词", ThreatLevelHigh},
		{`[\xE0-\xEF][\x80-\xBF]{2}\bunion\b`, "宽字符UNION", ThreatLevelCritical},
		{`[\xE0-\xEF][\x80-\xBF]{2}\bselect\b`, "宽字符SELECT", ThreatLevelHigh},
		{`[\xE0-\xEF][\x80-\xBF]{2}\bdrop\b`, "宽字符DROP", ThreatLevelCritical},
		{`[\xE0-\xEF][\x80-\xBF]{2}\bexec\b`, "宽字符EXEC", ThreatLevelCritical},
		{`[\x81-\xFE][\x40-\xFE]['\";=]`, "GBK SQL注入", ThreatLevelHigh},
	}

	for _, p := range wideCharSQL {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "宽字符SQL注入: " + p.description,
				Recommendation: "使用参数化查询",
			})
		}
	}

	wideCharXSS := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`[\xC0-\xDF][\x80-\xBF]<script`, "宽字符Script注入", ThreatLevelCritical},
		{`[\xE0-\xEF][\x80-\xBF]{2}<script`, "宽字符Script注入(3字节)", ThreatLevelCritical},
		{`[\xC0-\xDF][\x80-\xBF]javascript:`, "宽字符JavaScript协议", ThreatLevelCritical},
		{`[\xC0-\xDF][\x80-\xBF]on\w+=`, "宽字符事件处理器", ThreatLevelCritical},
		{`[\xE0-\xEF][\x80-\xBF]{2}[\x00-\x1F]*on\w+=`, "宽字符事件处理器变体", ThreatLevelCritical},
		{`&#[\xC0-\xDF][\x80-\xBF];`, "HTML实体宽字符", ThreatLevelHigh},
		{`&#x[0-9a-fA-F]{2,4};`, "HTML十六进制实体", ThreatLevelMedium},
	}

	for _, p := range wideCharXSS {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "宽字符XSS攻击: " + p.description,
				Recommendation: "正确编码宽字符输出",
			})
		}
	}
}

func (a *CharsetAnalyzer) analyzeCharsetConfusion(input *AnalysisInput, result *AnalysisResult) {
	data := input.Raw + " " + input.QueryString + " " + input.Body

	contentType := ""
	if input.Headers != nil {
		contentType = input.Headers["Content-Type"]
	}

	charsetMismatch := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)charset\s*=\s*utf-?8.*[\x80-\xFF]`, "声明UTF-8但包含高位字节", ThreatLevelMedium},
		{`(?i)charset\s*=\s*gbk.*[\xE0-\xEF][\x80-\xBF]{2}`, "声明GBK但包含UTF-8三字节序列", ThreatLevelMedium},
		{`(?i)charset\s*=\s*iso-8859-1.*[\xC0-\xFF]`, "声明ISO-8859-1但包含高位字节", ThreatLevelMedium},
		{`(?i)charset\s*=\s*utf-?8.*[\x00-\x1F]`, "UTF-8包含控制字符", ThreatLevelMedium},
	}

	for _, p := range charsetMismatch {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(contentType + " " + data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "字符集混淆攻击: " + p.description,
				Recommendation: "统一字符集编码",
			})
		}
	}

	multiByteConfusion := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`[\x00-\xFF]{10,}[\x80-\xFF]{5,}`, "多字节字符混淆", ThreatLevelMedium},
		{`[\xE0-\xEF][\x80-\xBF][\x00-\x1F][\x80-\xBF]`, "UTF-8控制字符注入", ThreatLevelHigh},
		{`[\xC0-\xDF][\x80-\xBF][\x00-\x1F]`, "两字节UTF-8控制字符", ThreatLevelMedium},
		{`[\x00-\x7F][\x80-\xBF]+`, "ASCII与UTF-8混合", ThreatLevelMedium},
	}

	for _, p := range multiByteConfusion {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "多字节字符混淆: " + p.description,
				Recommendation: "严格字符集验证",
			})
		}
	}

	homographAttack := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`[\xC0-\xD6][\x80-\xBF]`, "Latin-A到Latin-D范围(可能混淆)", ThreatLevelMedium},
		{`[\xE0-\xF6][\x80-\xBF]{2}`, "Latin扩展(可能混淆)", ThreatLevelMedium},
		{`[\x41][\xCC][\x80-\x82]`, "带重音符号的A(可能混淆)", ThreatLevelMedium},
		{`[\xC0-\xFF][\x80-\xBF]*[\x80-\xBF][\x80-\xBF]*`, "视觉欺骗字符", ThreatLevelMedium},
	}

	for _, p := range homographAttack {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        "homograph",
				Description:    "同形异义攻击: " + p.description,
				Recommendation: "使用IDN黑名单或白名单",
			})
		}
	}
}

func (a *CharsetAnalyzer) detectInvalidUTF8Sequences(data string) []string {
	invalids := make([]string, 0)
	for i := 0; i < len(data); {
		c := data[i]
		if c < 0x80 {
			i++
			continue
		}

		var expectedLen int
		if c&0xE0 == 0xC0 {
			expectedLen = 2
		} else if c&0xF0 == 0xE0 {
			expectedLen = 3
		} else if c&0xF8 == 0xF0 {
			expectedLen = 4
		} else if c&0xFC == 0xF8 {
			expectedLen = 5
		} else if c&0xFE == 0xFC {
			expectedLen = 6
		} else {
			invalids = append(invalids, string(c))
			i++
			continue
		}

		if i+expectedLen > len(data) {
			invalids = append(invalids, data[i:min(i+expectedLen, len(data))])
			break
		}

		valid := true
		for j := 1; j < expectedLen; j++ {
			if data[i+j]&0xC0 != 0x80 {
				valid = false
				break
			}
		}

		if !valid {
			invalids = append(invalids, data[i:min(i+expectedLen, len(data))])
		}

		i += expectedLen
	}
	return invalids
}

func NormalizeCharsetInput(data string, charset string) string {
	switch strings.ToLower(charset) {
	case "gbk", "gb2312", "gb18030":
		return normalizeGBKInput(data)
	case "utf-8", "utf8":
		return normalizeUTF8Input(data)
	case "iso-8859-1", "latin1":
		return normalizeISO88591Input(data)
	default:
		return data
	}
}

func normalizeGBKInput(data string) string {
	result := make([]byte, 0, len(data))
	for i := 0; i < len(data); i++ {
		c := data[i]
		if c < 0x80 {
			result = append(result, c)
		} else if i+1 < len(data) {
			result = append(result, c, data[i+1])
			i++
		}
	}
	return string(result)
}

func normalizeUTF8Input(data string) string {
	result := make([]rune, 0, len(data))
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRuneInString(data[i:])
		if r != utf8.RuneError || size == 1 {
			result = append(result, r)
		}
		i += size
	}
	return string(result)
}

func normalizeISO88591Input(data string) string {
	return data
}
