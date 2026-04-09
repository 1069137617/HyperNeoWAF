package analyzer

import (
	"encoding/json"
	"encoding/xml"
	"io"
	mimeMultipart "mime/multipart"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

type FormatParserAnalyzer struct {
	name         string
	version      string
	analyzerType string
	enabled      bool
	config       map[string]interface{}
	maxDepth     int
	mu           sync.RWMutex
}

func NewFormatParserAnalyzer() *FormatParserAnalyzer {
	return &FormatParserAnalyzer{
		name:         "format_parser_analyzer",
		version:      "1.0.0",
		analyzerType: "format_parser",
		enabled:      true,
		config:       make(map[string]interface{}),
		maxDepth:     10,
	}
}

func (a *FormatParserAnalyzer) Name() string {
	return a.name
}

func (a *FormatParserAnalyzer) Type() string {
	return a.analyzerType
}

func (a *FormatParserAnalyzer) Version() string {
	return a.version
}

func (a *FormatParserAnalyzer) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

func (a *FormatParserAnalyzer) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

func (a *FormatParserAnalyzer) Configure(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = config
	if depth, ok := config["maxDepth"].(int); ok && depth > 0 {
		a.maxDepth = depth
	}
	return nil
}

func (a *FormatParserAnalyzer) Analyze(input *AnalysisInput) *AnalysisResult {
	start := time.Now()
	result := NewAnalysisResult(a)

	if input == nil {
		result.ProcessingTime = time.Since(start)
		return result
	}

	a.analyzeFormData(input, result)
	a.analyzeJSONDeep(input, result)
	a.analyzeXMLDeep(input, result)
	a.analyzeMultipart(input, result)

	result.ProcessingTime = time.Since(start)

	if len(result.Matches) > 0 {
		result.ShouldBlock = result.ShouldBlockRequest(0.5)
		result.ShouldLog = true
		result.ShouldAllow = !result.ShouldBlock
	}

	return result
}

func (a *FormatParserAnalyzer) analyzeFormData(input *AnalysisInput, result *AnalysisResult) {
	ct := input.ContentType
	if ct == "" {
		ct = input.Headers["Content-Type"]
	}

	if !strings.Contains(strings.ToLower(ct), "application/x-www-form-urlencoded") {
		return
	}

	formData := input.Body
	if formData == "" {
		formData = input.QueryString
	}

	if formData == "" {
		return
	}

	parsed, err := url.ParseQuery(formData)
	if err != nil {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelMedium,
			Pattern:        "form_data_parse_error",
			Description:    "表单数据解析失败",
			Evidence:       formData[:min(len(formData), 100)],
			Recommendation: "检查表单数据格式是否正确",
			AnalyzerName:   a.name,
		})
		return
	}

	for key, values := range parsed {
		for _, value := range values {
			a.analyzeFormField(key, value, result)
		}
	}

	if len(parsed) > 100 {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelMedium,
			Pattern:        "form_field_count",
			Description:    "表单字段数量异常",
			Evidence:       "字段数量: " + itoa(int64(len(parsed))),
			Recommendation: "检查是否存在暴力填充攻击",
			AnalyzerName:   a.name,
		})
	}
}

func (a *FormatParserAnalyzer) analyzeFormField(key, value string, result *AnalysisResult) {
	if strings.Contains(value, "\r") || strings.Contains(value, "\n") {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelHigh,
			Pattern:        "form_newline_injection",
			Description:    "表单字段包含换行符: " + key,
			Recommendation: "拒绝包含换行符的表单数据",
			AnalyzerName:   a.name,
		})
	}

	dangerousPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`<script`, "XSS脚本标签", ThreatLevelHigh},
		{`javascript:`, "JavaScript协议", ThreatLevelHigh},
		{`on\w+\s*=`, "事件处理器", ThreatLevelHigh},
		{`\beval\s*\(`, "eval调用", ThreatLevelCritical},
		{`\bexec\s*\(`, "exec调用", ThreatLevelCritical},
		{`\bunion\s+select\b`, "SQL注入UNION", ThreatLevelHigh},
		{`\bdrop\s+table\b`, "SQL DROP表", ThreatLevelCritical},
		{`\bexec\s+xp_`, "存储过程注入", ThreatLevelCritical},
	}

	for _, p := range dangerousPatterns {
		re := regexp.MustCompile(`(?i)` + p.pattern)
		if re.MatchString(value) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description + " 在字段: " + key,
				Evidence:       value[:min(len(value), 100)],
				Recommendation: "拒绝包含恶意特征的请求",
				AnalyzerName:   a.name,
			})
		}
	}
}

func (a *FormatParserAnalyzer) analyzeJSONDeep(input *AnalysisInput, result *AnalysisResult) {
	ct := input.ContentType
	if ct == "" {
		ct = input.Headers["Content-Type"]
	}

	if !strings.Contains(strings.ToLower(ct), "application/json") {
		if !a.looksLikeJSON(input.Body) {
			return
		}
	}

	jsonData := input.Body
	if jsonData == "" {
		return
	}

	var jsonBody interface{}
	if err := json.Unmarshal([]byte(jsonData), &jsonBody); err != nil {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelMedium,
			Pattern:        "json_parse_error",
			Description:    "JSON解析失败",
			Evidence:       jsonData[:min(len(jsonData), 100)],
			Recommendation: "检查JSON格式是否正确",
			AnalyzerName:   a.name,
		})
		return
	}

	a.analyzeJSONValue(jsonBody, "", 0, result)
}

func (a *FormatParserAnalyzer) looksLikeJSON(data string) bool {
	trimmed := strings.TrimSpace(data)
	return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}

func (a *FormatParserAnalyzer) analyzeJSONValue(value interface{}, path string, depth int, result *AnalysisResult) {
	if depth >= a.maxDepth {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelMedium,
			Pattern:        "json_max_depth",
			Description:    "JSON嵌套深度超限",
			Evidence:       "路径: " + path,
			Recommendation: "限制JSON解析深度",
			AnalyzerName:   a.name,
		})
		return
	}

	switch v := value.(type) {
	case map[string]interface{}:
		for key, val := range v {
			newPath := key
			if path != "" {
				newPath = path + "." + key
			}
			a.analyzeJSONValue(val, newPath, depth+1, result)
		}
	case []interface{}:
		for i, item := range v {
			newPath := path + "[" + itoa(int64(i)) + "]"
			a.analyzeJSONValue(item, newPath, depth+1, result)
		}
	case string:
		a.analyzeJSONString(v, path, result)
	}
}

func (a *FormatParserAnalyzer) analyzeJSONString(value, path string, result *AnalysisResult) {
	if strings.Contains(value, "\r") || strings.Contains(value, "\n") {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelHigh,
			Pattern:        "json_string_newline",
			Description:    "JSON字符串包含换行符",
			Evidence:       "路径: " + path,
			Recommendation: "拒绝包含非法字符的JSON",
			AnalyzerName:   a.name,
		})
	}

	dangerousPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`<script`, "XSS脚本标签", ThreatLevelHigh},
		{`javascript:`, "JavaScript协议", ThreatLevelHigh},
		{`on\w+\s*=`, "事件处理器", ThreatLevelHigh},
		{`\beval\s*\(`, "eval调用", ThreatLevelCritical},
		{`\bunion\s+select\b`, "SQL注入UNION", ThreatLevelHigh},
	}

	for _, p := range dangerousPatterns {
		re := regexp.MustCompile(`(?i)` + p.pattern)
		if re.MatchString(value) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description + " 在路径: " + path,
				Evidence:       value[:min(len(value), 100)],
				Recommendation: "拒绝包含恶意特征的JSON",
				AnalyzerName:   a.name,
			})
		}
	}
}

func (a *FormatParserAnalyzer) analyzeXMLDeep(input *AnalysisInput, result *AnalysisResult) {
	ct := input.ContentType
	if ct == "" {
		ct = input.Headers["Content-Type"]
	}

	if !strings.Contains(strings.ToLower(ct), "xml") && !strings.Contains(strings.ToLower(input.Body), "<?xml") {
		return
	}

	xmlData := input.Body
	if xmlData == "" {
		return
	}

	decoder := xml.NewDecoder(strings.NewReader(xmlData))
	_, err := tokenizeXML(decoder)
	if err != nil {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelMedium,
			Pattern:        "xml_parse_error",
			Description:    "XML解析失败",
			Evidence:       xmlData[:min(len(xmlData), 100)],
			Recommendation: "检查XML格式是否正确",
			AnalyzerName:   a.name,
		})
		return
	}

	a.analyzeXMLElements(xmlData, 0, result)
}

func tokenizeXML(decoder *xml.Decoder) ([]xml.Token, error) {
	var tokens []xml.Token
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return tokens, err
		}
		tokens = append(tokens, token)
	}
	return tokens, nil
}

func (a *FormatParserAnalyzer) analyzeXMLElements(data string, depth int, result *AnalysisResult) {
	if depth >= a.maxDepth {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelMedium,
			Pattern:        "xml_max_depth",
			Description:    "XML嵌套深度超限",
			Recommendation: "限制XML解析深度",
			AnalyzerName:   a.name,
		})
		return
	}

	dangerousPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`<script`, "XSS脚本标签", ThreatLevelHigh},
		{`javascript:`, "JavaScript协议", ThreatLevelHigh},
		{`on\w+\s*=`, "事件处理器", ThreatLevelHigh},
		{`<!\[CDATA\[`, "CDATA节", ThreatLevelMedium},
		{`<!DOCTYPE`, "DOCTYPE声明", ThreatLevelMedium},
		{`&#[0-9]+;`, "数值HTML实体", ThreatLevelMedium},
		{`&#x[0-9a-f]+;`, "十六进制HTML实体", ThreatLevelMedium},
		{`xmlns\s*=`, "XML命名空间", ThreatLevelLow},
		{`xsi\s*:`, "XSI命名空间", ThreatLevelLow},
	}

	for _, p := range dangerousPatterns {
		re := regexp.MustCompile(`(?i)` + p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "检查XML内容是否安全",
				AnalyzerName:   a.name,
			})
		}
	}
}

func (a *FormatParserAnalyzer) analyzeMultipart(input *AnalysisInput, result *AnalysisResult) {
	ct := input.ContentType
	if ct == "" {
		ct = input.Headers["Content-Type"]
	}

	if !strings.Contains(strings.ToLower(ct), "multipart/form-data") {
		return
	}

	body := input.Body
	if body == "" {
		return
	}

	boundary := extractMultipartBoundary(ct)
	if boundary == "" {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelMedium,
			Pattern:        "multipart_no_boundary",
			Description:    "multipart请求缺少boundary参数",
			Recommendation: "检查Content-Type头是否正确",
			AnalyzerName:   a.name,
		})
		return
	}

	reader := mimeMultipart.NewReader(strings.NewReader(body), boundary)
	partCount := 0
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelMedium,
				Pattern:        "multipart_parse_error",
				Description:    "multipart解析错误",
				Recommendation: "检查multipart格式是否正确",
				AnalyzerName:   a.name,
			})
			break
		}

		partCount++
		if partCount > 50 {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelMedium,
				Pattern:        "multipart_too_many_parts",
				Description:    "multipart部分数量过多",
				Recommendation: "检查是否存在暴力填充攻击",
				AnalyzerName:   a.name,
			})
			break
		}

		formName := part.FormName()
		fileName := part.FileName()

		if fileName != "" {
			a.analyzeMultipartFile(formName, fileName, result)
		}

		content, _ := io.ReadAll(part)
		if len(content) > 10*1024*1024 {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelMedium,
				Pattern:        "multipart_part_too_large",
				Description:    "multipart部分数据过大",
				Recommendation: "限制上传文件大小",
				AnalyzerName:   a.name,
			})
		}

		a.analyzeFormField(formName, string(content), result)
	}

	if partCount == 0 {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelLow,
			Pattern:        "multipart_empty",
			Description:    "multipart请求没有部分",
			Recommendation: "检查请求是否正确",
			AnalyzerName:   a.name,
		})
	}
}

func extractMultipartBoundary(ct string) string {
	parts := strings.Split(ct, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "boundary=") {
			boundary := strings.TrimPrefix(part, "boundary=")
			boundary = strings.Trim(boundary, "\"")
			return boundary
		}
	}
	return ""
}

func (a *FormatParserAnalyzer) analyzeMultipartFile(formName, fileName string, result *AnalysisResult) {
	dangerousExtensions := []string{
		".php", ".phtml", ".php3", ".php4", ".php5", ".phar",
		".asp", ".aspx", ".ascx", ".ashx", ".asmx",
		".jsp", ".jspx", ".jsf",
		".cgi", ".pl", ".py",
		".exe", ".dll", ".com", ".bat", ".sh", ".ps1",
		".htaccess", ".htpasswd",
	}

	lowerFileName := strings.ToLower(fileName)
	for _, ext := range dangerousExtensions {
		if strings.HasSuffix(lowerFileName, ext) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelHigh,
				Pattern:        "multipart_dangerous_file",
				Description:    "危险文件上传: " + fileName,
				Evidence:       "表单字段: " + formName,
				Recommendation: "禁止上传危险类型的文件",
				AnalyzerName:   a.name,
			})
			return
		}
	}

	if strings.Contains(fileName, "..") {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelHigh,
			Pattern:        "multipart_path_traversal",
			Description:    "文件路径包含目录遍历: " + fileName,
			Recommendation: "拒绝包含路径遍历字符的文件名",
			AnalyzerName:   a.name,
		})
	}

	if strings.HasPrefix(fileName, ".") {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelMedium,
			Pattern:        "multipart_hidden_file",
			Description:    "隐藏文件上传: " + fileName,
			Recommendation: "检查文件是否为隐藏文件",
			AnalyzerName:   a.name,
		})
	}

	doubleExtPattern := regexp.MustCompile(`\.[a-zA-Z0-9]+\.[a-zA-Z0-9]+$`)
	if doubleExtPattern.MatchString(fileName) {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelMedium,
			Pattern:        "multipart_double_extension",
			Description:    "双扩展名文件: " + fileName,
			Recommendation: "检查文件是否为绕过类型检测",
			AnalyzerName:   a.name,
		})
	}
}
