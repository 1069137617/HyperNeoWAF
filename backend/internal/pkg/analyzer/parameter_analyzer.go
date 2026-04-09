package analyzer

import (
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

type ParameterAnalyzer struct {
	name         string
	version      string
	analyzerType string
	enabled      bool
	config       map[string]interface{}
	mu           sync.RWMutex
}

func NewParameterAnalyzer() *ParameterAnalyzer {
	return &ParameterAnalyzer{
		name:         "parameter_analyzer",
		version:      "1.0.0",
		analyzerType: "parameter",
		enabled:      true,
		config:       make(map[string]interface{}),
	}
}

func (a *ParameterAnalyzer) Name() string {
	return a.name
}

func (a *ParameterAnalyzer) Type() string {
	return a.analyzerType
}

func (a *ParameterAnalyzer) Version() string {
	return a.version
}

func (a *ParameterAnalyzer) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

func (a *ParameterAnalyzer) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

func (a *ParameterAnalyzer) Configure(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = config
	return nil
}

func (a *ParameterAnalyzer) Analyze(input *AnalysisInput) *AnalysisResult {
	start := time.Now()
	result := NewAnalysisResult(a)

	if input == nil {
		return result
	}

	parameters := a.parseParameters(input)
	a.analyzeParameterRelationships(parameters, result)
	a.analyzeConcatenationInjection(parameters, input, result)
	a.analyzeParameterPollution(parameters, input, result)
	a.analyzeParameterTampering(parameters, input, result)
	a.analyzeContextReassembly(parameters, input, result)

	result.ProcessingTime = time.Since(start)
	result.ShouldBlock = result.ShouldBlockRequest(0.6)
	if len(result.Matches) > 0 {
		result.ShouldLog = true
		result.ShouldAllow = !result.ShouldBlock
	}

	return result
}

type Parameter struct {
	Name  string
	Value string
	Type  string
}

func (a *ParameterAnalyzer) parseParameters(input *AnalysisInput) []Parameter {
	params := make([]Parameter, 0)

	if input.QueryString != "" {
		queryParams := a.parseQueryString(input.QueryString)
		params = append(params, queryParams...)
	}

	if input.Body != "" {
		bodyParams := a.parseBodyParameters(input.Body, input.ContentType)
		params = append(params, bodyParams...)
	}

	if input.Headers != nil {
		headerParams := a.parseHeaderParameters(input.Headers)
		params = append(params, headerParams...)
	}

	return params
}

func (a *ParameterAnalyzer) parseQueryString(query string) []Parameter {
	params := make([]Parameter, 0)

	values, err := url.ParseQuery(query)
	if err != nil {
		return params
	}

	for name, valueList := range values {
		for _, value := range valueList {
			params = append(params, Parameter{
				Name:  name,
				Value: value,
				Type:  "query",
			})
		}
	}

	return params
}

func (a *ParameterAnalyzer) parseBodyParameters(body string, contentType string) []Parameter {
	params := make([]Parameter, 0)

	if strings.Contains(strings.ToLower(contentType), "application/x-www-form-urlencoded") {
		values, err := url.ParseQuery(body)
		if err != nil {
			return params
		}
		for name, valueList := range values {
			for _, value := range valueList {
				params = append(params, Parameter{
					Name:  name,
					Value: value,
					Type:  "body",
				})
			}
		}
	} else if strings.Contains(strings.ToLower(contentType), "multipart/form-data") {
		multipartParams := a.parseMultipartBody(body)
		params = append(params, multipartParams...)
	} else if strings.Contains(strings.ToLower(contentType), "application/json") {
		jsonParams := a.parseJsonBody(body)
		params = append(params, jsonParams...)
	}

	return params
}

func (a *ParameterAnalyzer) parseMultipartBody(body string) []Parameter {
	params := make([]Parameter, 0)

	boundaryPattern := regexp.MustCompile(`(?i)boundary=(.+)`)
	matches := boundaryPattern.FindStringSubmatch(body)
	if len(matches) > 1 {
		boundary := matches[1]
		parts := strings.Split(body, "--"+boundary)
		for _, part := range parts {
			if strings.Contains(part, "Content-Disposition") {
				namePattern := regexp.MustCompile(`(?i)name="([^"]+)"`)
				nameMatches := namePattern.FindStringSubmatch(part)
				if len(nameMatches) > 1 {
					value := a.extractMultipartValue(part)
					params = append(params, Parameter{
						Name:  nameMatches[1],
						Value: value,
						Type:  "multipart",
					})
				}
			}
		}
	}

	return params
}

func (a *ParameterAnalyzer) extractMultipartValue(part string) string {
	lines := strings.Split(part, "\r\n")
	valueStarted := false
	var value strings.Builder

	for _, line := range lines {
		if valueStarted {
			value.WriteString(line)
			break
		}
		if line == "" {
			valueStarted = true
		}
	}

	return strings.TrimSpace(value.String())
}

func (a *ParameterAnalyzer) parseJsonBody(body string) []Parameter {
	params := make([]Parameter, 0)

	jsonPatterns := []struct {
		pattern     string
		description string
	}{
		{`"([^"]+)"\s*:\s*"([^"]*)"`, "string field"},
		{`"([^"]+)"\s*:\s*(\d+)`, "number field"},
		{`"([^"]+)"\s*:\s*\[`, "array field"},
		{`"([^"]+)"\s*:\s*\{`, "object field"},
	}

	for _, p := range jsonPatterns {
		re := regexp.MustCompile(p.pattern)
		matches := re.FindAllStringSubmatch(body, -1)
		for _, match := range matches {
			if len(match) > 2 {
				params = append(params, Parameter{
					Name:  match[1],
					Value: match[2],
					Type:  "json",
				})
			}
		}
	}

	return params
}

func (a *ParameterAnalyzer) parseHeaderParameters(headers map[string]string) []Parameter {
	params := make([]Parameter, 0)

	interestingHeaders := []string{
		"X-Forwarded-For", "X-Real-IP", "X-Requested-With",
		"Authorization", "Cookie", "Referer", "Origin",
		"X-API-Key", "X-Auth-Token", "X-CSRF-Token",
		"User-Agent", "Accept", "Accept-Language",
	}

	for _, headerName := range interestingHeaders {
		if value, exists := headers[headerName]; exists {
			params = append(params, Parameter{
				Name:  headerName,
				Value: value,
				Type:  "header",
			})
		}
	}

	return params
}

func (a *ParameterAnalyzer) analyzeParameterRelationships(parameters []Parameter, result *AnalysisResult) {
	paramMap := make(map[string][]string)
	for _, p := range parameters {
		paramMap[p.Name] = append(paramMap[p.Name], p.Value)
	}

	for name, values := range paramMap {
		if len(values) > 1 {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelMedium,
				Pattern:        "duplicate-param",
				Description:    "参数重复: " + name + " (出现" + string(rune(len(values))) + "次)",
				Recommendation: "验证参数重复处理逻辑",
			})
		}
	}

	sqlRelatedParams := a.detectSQLRelatedParams(parameters)
	if len(sqlRelatedParams) > 1 {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelMedium,
			Pattern:        "sql-related-params",
			Description:    "检测到多个SQL相关参数: " + strings.Join(sqlRelatedParams, ", "),
			Recommendation: "检查参数拼接安全性",
		})
	}

	commandRelatedParams := a.detectCommandRelatedParams(parameters)
	if len(commandRelatedParams) > 1 {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelHigh,
			Pattern:        "command-related-params",
			Description:    "检测到多个命令相关参数: " + strings.Join(commandRelatedParams, ", "),
			Recommendation: "验证命令参数隔离",
		})
	}

	pathRelatedParams := a.detectPathRelatedParams(parameters)
	if len(pathRelatedParams) > 1 {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelMedium,
			Pattern:        "path-related-params",
			Description:    "检测到多个路径相关参数: " + strings.Join(pathRelatedParams, ", "),
			Recommendation: "验证路径拼接安全性",
		})
	}
}

func (a *ParameterAnalyzer) detectSQLRelatedParams(params []Parameter) []string {
	sqlKeywords := []string{
		"select", "from", "where", "insert", "update", "delete",
		"drop", "create", "alter", "union", "join", "table",
		"column", "database", "schema", "exec", "execute",
	}

	related := make([]string, 0)
	for _, p := range params {
		lowerValue := strings.ToLower(p.Value)
		for _, kw := range sqlKeywords {
			if strings.Contains(lowerValue, kw) {
				related = append(related, p.Name)
				break
			}
		}
	}
	return related
}

func (a *ParameterAnalyzer) detectCommandRelatedParams(params []Parameter) []string {
	commandKeywords := []string{
		"cat", "ls", "dir", "echo", "cd", "pwd", "rm", "mv",
		"cp", "chmod", "chown", "wget", "curl", "nc", "telnet",
		"ssh", "cmd", "bash", "sh", "powershell", "python",
		"perl", "ruby", "php", "exec", "system", "passthru",
	}

	related := make([]string, 0)
	for _, p := range params {
		lowerValue := strings.ToLower(p.Value)
		for _, kw := range commandKeywords {
			if strings.Contains(lowerValue, kw) {
				related = append(related, p.Name)
				break
			}
		}
	}
	return related
}

func (a *ParameterAnalyzer) detectPathRelatedParams(params []Parameter) []string {
	pathKeywords := []string{
		"path", "file", "dir", "folder", "filename", "filepath",
		"include", "require", "load", "open", "read", "write",
		"/etc", "/var", "/home", "/usr", "c:\\", "d:\\",
		"../", "..\\", ".\\", "./",
	}

	related := make([]string, 0)
	for _, p := range params {
		lowerValue := strings.ToLower(p.Value)
		for _, kw := range pathKeywords {
			if strings.Contains(lowerValue, kw) {
				related = append(related, p.Name)
				break
			}
		}
	}
	return related
}

func (a *ParameterAnalyzer) analyzeConcatenationInjection(parameters []Parameter, input *AnalysisInput, result *AnalysisResult) {
	sqlConcatPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\bselect\b.*\bfrom\b.*\+.*(?:\bwhere\b|\border\b)`, "SELECT拼接WHERE/ORDER", ThreatLevelHigh},
		{`(?i)\bwhere\b.*=.+?\+.+?`, "WHERE条件拼接", ThreatLevelHigh},
		{`(?i)\border\b.*by\b.*\+`, "ORDER BY拼接", ThreatLevelHigh},
		{`(?i)\band\b.*\d+\s*=\s*\d+\s*\+`, "AND条件拼接数字", ThreatLevelMedium},
		{`(?i)\bor\b.*['"].*['"].*\+`, "OR条件拼接字符串", ThreatLevelHigh},
		{`(?i)union\s+select\s+\+.+?`, "UNION SELECT拼接", ThreatLevelCritical},
		{`(?i)insert\s+into\b.*\+.+?`, "INSERT拼接", ThreatLevelHigh},
		{`(?i)update\b.*\+.+?set\b`, "UPDATE拼接", ThreatLevelHigh},
	}

	combinedParams := a.combineParameterValues(parameters)
	for _, p := range sqlConcatPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(combinedParams) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "SQL拼接注入: " + p.description,
				Recommendation: "使用参数化查询",
			})
		}
	}

	multiParamSQL := a.detectMultiParamSQLInjection(parameters)
	for _, m := range multiParamSQL {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelHigh,
			Pattern:        "multi-param-sql",
			Description:    "多参数SQL注入: " + m,
			Recommendation: "分别验证每个参数",
		})
	}
}

func (a *ParameterAnalyzer) combineParameterValues(params []Parameter) string {
	var combined strings.Builder
	for _, p := range params {
		combined.WriteString(p.Value)
		combined.WriteString(" ")
	}
	return combined.String()
}

func (a *ParameterAnalyzer) detectMultiParamSQLInjection(params []Parameter) []string {
	injectionPatterns := make([]string, 0)

	for i := 0; i < len(params); i++ {
		for j := i + 1; j < len(params); j++ {
			combined := params[i].Value + " " + params[j].Value

			sqlPatterns := []struct {
				pattern     string
				description string
			}{
				{`(?i)union\s+select`, "UNION SELECT"},
				{`(?i)or\s+['"].*=['"]`, "OR 1=1类型"},
				{`(?i)and\s+['"].*=['"]`, "AND 1=1类型"},
				{`(?i);\s*drop\b`, "DROP语句"},
				{`(?i);\s*delete\b`, "DELETE语句"},
				{`(?i);\s*insert\b`, "INSERT语句"},
			}

			for _, p := range sqlPatterns {
				re := regexp.MustCompile(p.pattern)
				if re.MatchString(combined) {
					injectionPatterns = append(injectionPatterns,
						params[i].Name+" + "+params[j].Name+": "+p.description)
				}
			}
		}
	}

	return injectionPatterns
}

func (a *ParameterAnalyzer) analyzeParameterPollution(parameters []Parameter, input *AnalysisInput, result *AnalysisResult) {
	paramCounts := make(map[string]int)
	for _, p := range parameters {
		paramCounts[p.Name]++
	}

	for name, count := range paramCounts {
		if count > 5 {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelMedium,
				Pattern:        "param-pollution",
				Description:    "参数污染: " + name + " 重复" + string(rune(count)) + "次",
				Recommendation: "验证参数污染处理逻辑",
			})
		}

		if count > 1 {
			a.analyzeDuplicateParamAttack(name, count, result)
		}
	}

	a.analyzeHTTPParameterPollution(input, result)
}

func (a *ParameterAnalyzer) analyzeDuplicateParamAttack(name string, count int, result *AnalysisResult) {
	dangerousParams := []string{
		"id", "page", "sort", "order", "limit", "offset",
		"filter", "search", "query", "q", "callback",
		"redirect", "url", "uri", "path", "file",
		"username", "password", "email", "token",
		"admin", "role", "privilege", "auth",
	}

	for _, dp := range dangerousParams {
		if strings.ToLower(name) == dp {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelHigh,
				Pattern:        "dangerous-pollution",
				Description:    "危险参数污染: " + name + " 重复" + string(rune(count)) + "次",
				Recommendation: "验证危险参数重复处理",
			})
			break
		}
	}
}

func (a *ParameterAnalyzer) analyzeHTTPParameterPollution(input *AnalysisInput, result *AnalysisResult) {
	if input.QueryString != "" && input.Body != "" {
		queryParams := a.parseQueryString(input.QueryString)
		bodyParams := a.parseBodyParameters(input.Body, input.ContentType)

		queryParamNames := make(map[string]bool)
		for _, p := range queryParams {
			queryParamNames[p.Name] = true
		}

		for _, p := range bodyParams {
			if queryParamNames[p.Name] {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    ThreatLevelMedium,
					Pattern:        "hpp-duplicate",
					Description:    "HTTP参数污染: " + p.Name + " 同时出现在Query和Body中",
					Recommendation: "验证参数优先级和处理逻辑",
				})
			}
		}
	}
}

func (a *ParameterAnalyzer) analyzeParameterTampering(parameters []Parameter, input *AnalysisInput, result *AnalysisResult) {
	a.analyzeTypeTampering(parameters, result)
	a.analyzeIntegerOverflow(parameters, result)
	a.analyzeNullByteInjection(parameters, result)
	a.analyzeWhitespaceManipulation(parameters, result)
}

func (a *ParameterAnalyzer) analyzeTypeTampering(params []Parameter, result *AnalysisResult) {
	for _, p := range params {
		if a.isNumericParam(p.Name) {
			if a.containsNonNumeric(p.Value) {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    ThreatLevelMedium,
					Pattern:        "type-tampering",
					Description:    "类型篡改: " + p.Name + " 应为数字但包含非数字字符",
					Recommendation: "验证参数类型",
				})
			}
		}
	}
}

func (a *ParameterAnalyzer) isNumericParam(name string) bool {
	numericParams := []string{
		"id", "page", "limit", "offset", "count", "size",
		"length", "width", "height", "price", "quantity",
		"age", "year", "month", "day", "hour", "minute",
		"num", "number", "index", "position", "sort",
	}

	nameLower := strings.ToLower(name)
	for _, np := range numericParams {
		if nameLower == np || strings.HasSuffix(nameLower, "_"+np) {
			return true
		}
	}
	return false
}

func (a *ParameterAnalyzer) containsNonNumeric(value string) bool {
	for _, c := range value {
		if c < '0' || c > '9' {
			if c != '.' && c != '-' && c != '+' && c != 'e' && c != 'E' {
				return true
			}
		}
	}
	return false
}

func (a *ParameterAnalyzer) analyzeIntegerOverflow(params []Parameter, result *AnalysisResult) {
	overflowPatterns := []string{
		"9999999999",
		"2147483647",
		"2147483648",
		"-2147483648",
		"4294967295",
		"9223372036854775807",
		"-9223372036854775808",
		"9999999999999999999",
	}

	for _, p := range params {
		for _, op := range overflowPatterns {
			if p.Value == op {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    ThreatLevelMedium,
					Pattern:        "integer-overflow",
					Description:    "整数溢出值: " + p.Name + "=" + op,
					Recommendation: "验证数值范围",
				})
			}
		}

		if len(p.Value) > 15 {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelMedium,
				Pattern:        "large-integer",
				Description:    "超大整数值: " + p.Name + " (长度" + string(rune(len(p.Value))) + ")",
				Recommendation: "限制数值大小",
			})
		}
	}
}

func (a *ParameterAnalyzer) analyzeNullByteInjection(params []Parameter, result *AnalysisResult) {
	nullBytePatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`[\x00]`, "空字节(%00)", ThreatLevelHigh},
		{`%00[\x00]`, "URL编码空字节", ThreatLevelHigh},
		{`\u0000`, "Unicode空字节", ThreatLevelHigh},
		{`[\x00].*[\x00]`, "多个空字节", ThreatLevelMedium},
	}

	for _, p := range params {
		for _, nbp := range nullBytePatterns {
			re := regexp.MustCompile(nbp.pattern)
			if re.MatchString(p.Value) {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    nbp.threatLevel,
					Pattern:        "null-byte",
					Description:    "空字节注入: " + p.Name + " " + nbp.description,
					Recommendation: "过滤空字节",
				})
			}
		}
	}
}

func (a *ParameterAnalyzer) analyzeWhitespaceManipulation(params []Parameter, result *AnalysisResult) {
	whitespacePatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\s{5,}`, "多个连续空白字符", ThreatLevelMedium},
		{`[\t\n\r\x0B\x0C]{3,}`, "多个控制字符", ThreatLevelMedium},
		{`%20%20%20+`, "多个URL编码空格", ThreatLevelMedium},
		{`\+\+\+`, "多个加号", ThreatLevelMedium},
		{`----`, "多个短横线(注释)", ThreatLevelMedium},
		{`;;`, "双分号", ThreatLevelMedium},
		{`/\*.*\*/`, "块注释", ThreatLevelMedium},
	}

	for _, p := range params {
		for _, wp := range whitespacePatterns {
			re := regexp.MustCompile(wp.pattern)
			if re.MatchString(p.Value) {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    wp.threatLevel,
					Pattern:        "whitespace-manip",
					Description:    "空白字符操控: " + p.Name + " " + wp.description,
					Recommendation: "规范化空白字符",
				})
			}
		}
	}
}

func (a *ParameterAnalyzer) analyzeContextReassembly(params []Parameter, input *AnalysisInput, result *AnalysisResult) {
	a.analyzeSQLReassembly(params, result)
	a.analyzeCommandReassembly(params, result)
	a.analyzeTemplateReassembly(params, result)
	a.analyzeJSONReassembly(params, result)
}

func (a *ParameterAnalyzer) analyzeSQLReassembly(params []Parameter, result *AnalysisResult) {
	combined := a.combineParameterValues(params)

	sqlReassembly := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)sel\x20+ect`, "SQL关键字拆分(space)", ThreatLevelHigh},
		{`(?i)sel%00ect`, "SQL关键字拆分(null)", ThreatLevelHigh},
		{`(?i)sel%0aect`, "SQL关键字拆分(newline)", ThreatLevelHigh},
		{`(?i)un\x20ion`, "UNION拆分", ThreatLevelHigh},
		{`(?i)un%00ion`, "UNION拆分(null)", ThreatLevelHigh},
		{`(?i)sel\x65ct`, "SQL关键字十六进制", ThreatLevelHigh},
		{`(?i)0x73656c656374`, "SELECT十六进制编码", ThreatLevelHigh},
		{`(?i)char\s*\(\s*\d+\s*\)`, "CHAR()函数注入", ThreatLevelMedium},
		{`(?i)concat\s*\(`, "CONCAT()函数注入", ThreatLevelMedium},
		{`(?i)concat_ws\s*\(`, "CONCAT_WS()函数注入", ThreatLevelMedium},
	}

	for _, p := range sqlReassembly {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(combined) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        "sql-reassembly",
				Description:    "SQL重组攻击: " + p.description,
				Recommendation: "使用参数化查询",
			})
		}
	}
}

func (a *ParameterAnalyzer) analyzeCommandReassembly(params []Parameter, result *AnalysisResult) {
	combined := a.combineParameterValues(params)

	commandReassembly := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`c\x61t`, "cat命令拆分", ThreatLevelHigh},
		{`c%61t`, "cat命令URL编码", ThreatLevelHigh},
		{`l\x73`, "ls命令拆分", ThreatLevelHigh},
		{`l%73`, "ls命令URL编码", ThreatLevelHigh},
		{`wh\x6fami`, "whoami命令拆分", ThreatLevelHigh},
		{`wh%6fami`, "whoami命令URL编码", ThreatLevelHigh},
		{`\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64`, "/etc/passwd十六进制", ThreatLevelCritical},
		{`\x2e\x2e\x2f`, "../十六进制", ThreatLevelHigh},
		{`\.\.%2f`, "../URL编码", ThreatLevelHigh},
	}

	for _, p := range commandReassembly {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(combined) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        "command-reassembly",
				Description:    "命令重组攻击: " + p.description,
				Recommendation: "避免直接执行用户输入",
			})
		}
	}
}

func (a *ParameterAnalyzer) analyzeTemplateReassembly(params []Parameter, result *AnalysisResult) {
	combined := a.combineParameterValues(params)

	templateReassembly := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\{\{\{`, "模板变量三重括号", ThreatLevelHigh},
		{`\}\}\}`, "模板变量三重闭合", ThreatLevelHigh},
		{`\{\{.*?\}\}`, "模板变量双括号", ThreatLevelMedium},
		{`\$\{.*?\}`, "EL表达式", ThreatLevelHigh},
		{`<\%.*?\%>`, "ERB/JSP模板", ThreatLevelHigh},
		{`\{\%.*?\%\}`, "Jinja2模板", ThreatLevelMedium},
		{`\#\{.*?\}`, "Ruby模板", ThreatLevelMedium},
		{`\{\{.*?\x7b.*?\}\}`, "嵌套模板表达式", ThreatLevelMedium},
	}

	for _, p := range templateReassembly {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(combined) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        "template-reassembly",
				Description:    "模板重组攻击: " + p.description,
				Recommendation: "正确转义模板输出",
			})
		}
	}
}

func (a *ParameterAnalyzer) analyzeJSONReassembly(params []Parameter, result *AnalysisResult) {
	combined := a.combineParameterValues(params)

	jsonReassembly := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`"\x22`, "JSON引号十六进制", ThreatLevelHigh},
		{`"\u0022`, "JSON引号Unicode", ThreatLevelHigh},
		{`\x3c\x73\x63\x72\x69\x70\x74`, "script标签十六进制", ThreatLevelCritical},
		{`\x3c\x69\x6d\x67`, "img标签十六进制", ThreatLevelHigh},
		{`\x6a\x61\x76\x61\x73\x63\x72\x69\x70\x74\x3a`, "javascript协议十六进制", ThreatLevelCritical},
		{`\\\x22`, "转义引号注入", ThreatLevelMedium},
		{`\\\u`, "转义Unicode注入", ThreatLevelMedium},
	}

	for _, p := range jsonReassembly {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(combined) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        "json-reassembly",
				Description:    "JSON重组攻击: " + p.description,
				Recommendation: "正确转义JSON输出",
			})
		}
	}
}
