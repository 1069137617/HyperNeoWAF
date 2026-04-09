package analyzer

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

type XSSContextType int

const (
	ContextUnknown XSSContextType = iota
	ContextHTMLOutside
	ContextHTMLTag
	ContextHTMLAttribute
	ContextHTMLAttributeDoubleQuote
	ContextHTMLAttributeSingleQuote
	ContextHTMLAttributeNoQuote
	ContextJavaScript
	ContextJavaScriptBlock
	ContextJavaScriptEventHandler
	ContextJavaScriptURL
	ContextCSS
	ContextURL
	ContextJSON
	ContextTextarea
	ContextTitle
	ContextNoscript
	ContextStyle
	ContextXMP
	ContextListing
	ContextTemplate
)

func (c XSSContextType) String() string {
	switch c {
	case ContextUnknown:
		return "unknown"
	case ContextHTMLOutside:
		return "html_outside"
	case ContextHTMLTag:
		return "html_tag"
	case ContextHTMLAttribute:
		return "html_attribute"
	case ContextHTMLAttributeDoubleQuote:
		return "html_attribute_double_quote"
	case ContextHTMLAttributeSingleQuote:
		return "html_attribute_single_quote"
	case ContextHTMLAttributeNoQuote:
		return "html_attribute_no_quote"
	case ContextJavaScript:
		return "javascript"
	case ContextJavaScriptBlock:
		return "javascript_block"
	case ContextJavaScriptEventHandler:
		return "javascript_event_handler"
	case ContextJavaScriptURL:
		return "javascript_url"
	case ContextCSS:
		return "css"
	case ContextURL:
		return "url"
	case ContextJSON:
		return "json"
	case ContextTextarea:
		return "textarea"
	case ContextTitle:
		return "title"
	case ContextNoscript:
		return "noscript"
	case ContextStyle:
		return "style"
	case ContextXMP:
		return "xmp"
	case ContextListing:
		return "listing"
	case ContextTemplate:
		return "template"
	default:
		return "unknown"
	}
}

type XSSContext struct {
	ContextType     XSSContextType
	TagName         string
	AttributeName   string
	ParentTags      []string
	IsScriptContext bool
	IsStyleContext  bool
	Depth           int
}

type XSSContextAnalyzer struct {
	name         string
	version      string
	analyzerType string
	enabled      bool
	config       map[string]interface{}
	mu           sync.RWMutex

	scriptTags         []string
	eventHandlerAttrs []string
	urlAttrs           []string
	dangerousTags      []string
	executionFuncs     []string

	scriptTagRE       *regexp.Regexp
	eventHandlerRE    *regexp.Regexp
	urlAttrRE         *regexp.Regexp
	jsProtocolRE      *regexp.Regexp
	dataProtocolRE    *regexp.Regexp
	quotedStringRE    *regexp.Regexp
	htmlTagRE         *regexp.Regexp
	htmlCommentRE     *regexp.Regexp
	styleContentRE    *regexp.Regexp
	scriptContentRE   *regexp.Regexp
	jsonContentRE     *regexp.Regexp
}

func NewXSSContextAnalyzer() *XSSContextAnalyzer {
	a := &XSSContextAnalyzer{
		name:         "xss_context_analyzer",
		version:      "1.0.0",
		analyzerType: "xss_context",
		enabled:      true,
		config:       make(map[string]interface{}),

		scriptTags: []string{
			"script", "body", "head", "html", "div", "span", "p", "a",
			"form", "input", "textarea", "select", "option", "button",
			"img", "svg", "path", "rect", "circle", "ellipse", "line",
			"polyline", "polygon", "iframe", "object", "embed", "applet",
			"video", "audio", "source", "track", "canvas", "map", "area",
			"table", "tr", "td", "th", "tbody", "thead", "tfoot", "colgroup",
			"col", "caption", "ul", "ol", "li", "dl", "dt", "dd", "menu",
			"template", "math", "portal", "noscript", "style", "link",
			"meta", "title", "base", "b", "i", "u", "s", "strong", "em",
			"small", "sub", "sup", "code", "pre", "kbd", "samp", "var",
		},

		eventHandlerAttrs: []string{
			"onload", "onerror", "onclick", "onmouseover", "onmouseout",
			"onmousedown", "onmouseup", "onfocus", "onblur", "onchange",
			"onsubmit", "onreset", "onselect", "onkeydown", "onkeyup",
			"onkeypress", "ondblclick", "oncontextmenu", "onabort",
			"onbeforeunload", "ondrag", "ondragend", "ondragenter",
			"ondragleave", "ondragover", "ondragstart", "ondrop",
			"oninput", "oninvalid", "onsearch", "onpaste", "oncopy",
			"oncuts", "oncanplay", "oncanplaythrough", "oncuechange",
			"ondurationchange", "onemptied", "onended", "onloadeddata",
			"onloadedmetadata", "onloadstart", "onpause", "onplay",
			"onplaying", "onprogress", "onratechange", "onseeked",
			"onseeking", "onstalled", "onsuspend", "ontimeupdate",
			"onvolumechange", "onwaiting", "onwheel", "onscroll",
			"ontoggle", "onbeforeprint", "onafterprint",
		},

		urlAttrs: []string{
			"href", "src", "action", "data", "poster", "xlink:href",
			"formaction", "background", "dynsrc", "lowsrc", "ping",
			"cite", "classid", "codebase", "archive", "code", "manifest",
		},

		dangerousTags: []string{
			"script", "iframe", "object", "embed", "applet", "form",
			"input", "button", "select", "textarea", "svg", "math", "portal",
		},

		executionFuncs: []string{
			"eval", "Function", "setTimeout", "setInterval", "execScript",
			"createContextualFragment", "runat", "exec", "test",
		},
	}

	a.initPatterns()
	return a
}

func (a *XSSContextAnalyzer) initPatterns() {
	a.scriptTagRE = regexp.MustCompile(`(?i)<script[^>]*>`)
	a.eventHandlerRE = regexp.MustCompile(`(?i)\s+on\w+\s*=\s*`)
	a.urlAttrRE = regexp.MustCompile(`(?i)\s+(href|src|action|data|poster|xlink:href|formaction|background|dynsrc|lowsrc|ping)\s*=\s*`)
	a.jsProtocolRE = regexp.MustCompile(`(?i)javascript\s*:`)
	a.dataProtocolRE = regexp.MustCompile(`(?i)data\s*:\s*text/(html|javascript|xml)`)
	a.quotedStringRE = regexp.MustCompile(`(["'])(?:(?=(\\?))\2.)*?\1`)
	a.htmlTagRE = regexp.MustCompile(`(?i)<([a-z][a-z0-9]*)\s*[^>]*>`)
	a.htmlCommentRE = regexp.MustCompile(`(?i)<!--[\s\S]*?-->`)
	a.styleContentRE = regexp.MustCompile(`(?i)<style[^>]*>[\s\S]*?</style[^>]*>`)
	a.scriptContentRE = regexp.MustCompile(`(?i)<script[^>]*>[\s\S]*?</script[^>]*>`)
	a.jsonContentRE = regexp.MustCompile(`(?i)<script[^>]*type\s*=\s*["']?application/json["']?[^>]*>[\s\S]*?</script[^>]*>`)
}

func (a *XSSContextAnalyzer) Name() string {
	return a.name
}

func (a *XSSContextAnalyzer) Type() string {
	return a.analyzerType
}

func (a *XSSContextAnalyzer) Version() string {
	return a.version
}

func (a *XSSContextAnalyzer) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

func (a *XSSContextAnalyzer) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

func (a *XSSContextAnalyzer) Configure(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = config
	return nil
}

func (a *XSSContextAnalyzer) Analyze(input *AnalysisInput) *AnalysisResult {
	start := time.Now()
	result := NewAnalysisResult(a)

	if input == nil || input.Raw == "" {
		result.ProcessingTime = time.Since(start)
		return result
	}

	contexts := a.DetectContexts(input.Raw)

	a.analyzeByContext(input.Raw, contexts, result)
	a.analyzeContextAwareXSS(input.Raw, contexts, result)
	a.analyzeFalsePositiveMitigation(input.Raw, contexts, result)

	result.ProcessingTime = time.Since(start)
	result.ShouldBlock = result.ShouldBlockRequest(0.6)
	if len(result.Matches) > 0 {
		result.ShouldLog = true
		result.ShouldAllow = !result.ShouldBlock
	}

	return result
}

func (a *XSSContextAnalyzer) DetectContexts(data string) []XSSContext {
	contexts := make([]XSSContext, 0)

	if strings.Contains(data, "<script") || strings.Contains(data, "</script") {
		contexts = append(contexts, XSSContext{
			ContextType:     ContextJavaScriptBlock,
			IsScriptContext: true,
		})
	}

	scriptMatches := a.scriptContentRE.FindAllStringIndex(data, -1)
	for _, match := range scriptMatches {
		contexts = append(contexts, XSSContext{
			ContextType:     ContextJavaScriptBlock,
			IsScriptContext: true,
			Depth:           1,
		})
	}

	if strings.Contains(data, "<style") || strings.Contains(data, "</style") {
		contexts = append(contexts, XSSContext{
			ContextType:    ContextStyle,
			IsStyleContext: true,
		})
	}

	styleMatches := a.styleContentRE.FindAllStringIndex(data, -1)
	for _, match := range styleMatches {
		contexts = append(contexts, XSSContext{
			ContextType:    ContextStyle,
			IsStyleContext: true,
		})
	}

	eventHandlerMatches := a.eventHandlerRE.FindAllStringIndex(data, -1)
	for _, match := range eventHandlerMatches {
		contexts = append(contexts, XSSContext{
			ContextType: ContextJavaScriptEventHandler,
		})
	}

	urlAttrMatches := a.urlAttrRE.FindAllStringIndex(data, -1)
	for _, match := range urlAttrMatches {
		contexts = append(contexts, XSSContext{
			ContextType: ContextURL,
		})
	}

	jsProtocolMatches := a.jsProtocolRE.FindAllStringIndex(data, -1)
	for _, match := range jsProtocolMatches {
		contexts = append(contexts, XSSContext{
			ContextType: ContextJavaScriptURL,
		})
	}

	dataProtocolMatches := a.dataProtocolRE.FindAllStringIndex(data, -1)
	for _, match := range dataProtocolMatches {
		contexts = append(contexts, XSSContext{
			ContextType: ContextJavaScriptURL,
		})
	}

	jsonMatches := a.jsonContentRE.FindAllStringIndex(data, -1)
	for _, match := range jsonMatches {
		contexts = append(contexts, XSSContext{
			ContextType: ContextJSON,
		})
	}

	textareaMatches := regexp.MustCompile(`(?i)<textarea[^>]*>[\s\S]*?</textarea[^>]*>`).FindAllStringIndex(data, -1)
	for _, match := range textareaMatches {
		contexts = append(contexts, XSSContext{
			ContextType: ContextTextarea,
		})
	}

	titleMatches := regexp.MustCompile(`(?i)<title[^>]*>[\s\S]*?</title[^>]*>`).FindAllStringIndex(data, -1)
	for _, match := range titleMatches {
		contexts = append(contexts, XSSContext{
			ContextType: ContextTitle,
		})
	}

	noscriptMatches := regexp.MustCompile(`(?i)<noscript[^>]*>[\s\S]*?</noscript[^>]*>`).FindAllStringIndex(data, -1)
	for _, match := range noscriptMatches {
		contexts = append(contexts, XSSContext{
			ContextType: ContextNoscript,
		})
	}

	xmpMatches := regexp.MustCompile(`(?i)<xmp[^>]*>[\s\S]*?</xmp[^>]*>`).FindAllStringIndex(data, -1)
	for _, match := range xmpMatches {
		contexts = append(contexts, XSSContext{
			ContextType: ContextXMP,
		})
	}

	listingMatches := regexp.MustCompile(`(?i)<listing[^>]*>[\s\S]*?</listing[^>]*>`).FindAllStringIndex(data, -1)
	for _, match := range listingMatches {
		contexts = append(contexts, XSSContext{
			ContextType: ContextListing,
		})
	}

	templateMatches := regexp.MustCompile(`(?i)<template[^>]*>[\s\S]*?</template[^>]*>`).FindAllStringIndex(data, -1)
	for _, match := range templateMatches {
		contexts = append(contexts, XSSContext{
			ContextType: ContextTemplate,
		})
	}

	a.detectHTMLTagContexts(data, &contexts)
	a.detectHTMLAttributeContexts(data, &contexts)

	if len(contexts) == 0 {
		contexts = append(contexts, XSSContext{
			ContextType: ContextHTMLOutside,
		})
	}

	return contexts
}

func (a *XSSContextAnalyzer) detectHTMLTagContexts(data string, contexts *[]XSSContext) {
	tagMatches := a.htmlTagRE.FindAllStringSubmatch(data, -1)
	for _, match := range tagMatches {
		if len(match) < 2 {
			continue
		}
		tagName := strings.ToLower(match[1])

		isScript := tagName == "script"
		isStyle := tagName == "style"
		isDangerous := false
		for _, dt := range a.dangerousTags {
			if tagName == dt {
				isDangerous = true
				break
			}
		}

		contextType := ContextHTMLTag
		if isScript {
			contextType = ContextJavaScriptBlock
		} else if isStyle {
			contextType = ContextStyle
		}

		*contexts = append(*contexts, XSSContext{
			ContextType:     contextType,
			TagName:         tagName,
			IsScriptContext: isScript,
			IsStyleContext:  isStyle,
		})

		if isDangerous {
			for _, eh := range a.eventHandlerAttrs {
				pattern := `(?i)` + tagName + `[^>]+` + eh + `\s*=`
				if regexp.MustCompile(pattern).MatchString(data) {
					*contexts = append(*contexts, XSSContext{
						ContextType:   ContextJavaScriptEventHandler,
						TagName:       tagName,
						AttributeName: eh,
					})
				}
			}
		}
	}
}

func (a *XSSContextAnalyzer) detectHTMLAttributeContexts(data string, contexts *[]XSSContext) {
	doubleQuoteAttrRE := regexp.MustCompile(`(?i)\s+([a-z][a-z0-9]*)\s*=\s*"([^"]*)"`)
	singleQuoteAttrRE := regexp.MustCompile(`(?i)\s+([a-z][a-z0-9]*)\s*=\s*'([^']*)'`)
	noQuoteAttrRE := regexp.MustCompile(`(?i)\s+([a-z][a-z0-9]*)\s*=\s*([^\s>"']+)`)

	doubleMatches := doubleQuoteAttrRE.FindAllStringSubmatch(data, -1)
	for _, match := range doubleMatches {
		if len(match) < 3 {
			continue
		}
		attrName := strings.ToLower(match[1])
		attrValue := match[2]

		contextType := ContextHTMLAttributeDoubleQuote
		if a.isURLAttribute(attrName) {
			contextType = ContextURL
		} else if a.isEventHandlerAttribute(attrName) {
			contextType = ContextJavaScriptEventHandler
		}

		*contexts = append(*contexts, XSSContext{
			ContextType:   contextType,
			AttributeName: attrName,
		})

		if a.containsExecutionPatterns(attrValue) {
			*contexts = append(*contexts, XSSContext{
				ContextType:     ContextJavaScriptEventHandler,
				AttributeName:  attrName,
				IsScriptContext: true,
			})
		}
	}

	singleMatches := singleQuoteAttrRE.FindAllStringSubmatch(data, -1)
	for _, match := range singleMatches {
		if len(match) < 3 {
			continue
		}
		attrName := strings.ToLower(match[1])
		attrValue := match[2]

		contextType := ContextHTMLAttributeSingleQuote
		if a.isURLAttribute(attrName) {
			contextType = ContextURL
		} else if a.isEventHandlerAttribute(attrName) {
			contextType = ContextJavaScriptEventHandler
		}

		*contexts = append(*contexts, XSSContext{
			ContextType:   contextType,
			AttributeName: attrName,
		})
	}

	noQuoteMatches := noQuoteAttrRE.FindAllStringSubmatch(data, -1)
	for _, match := range noQuoteMatches {
		if len(match) < 3 {
			continue
		}
		attrName := strings.ToLower(match[1])

		*contexts = append(*contexts, XSSContext{
			ContextType:   ContextHTMLAttributeNoQuote,
			AttributeName: attrName,
		})
	}
}

func (a *XSSContextAnalyzer) isURLAttribute(attrName string) bool {
	for _, urlAttr := range a.urlAttrs {
		if attrName == urlAttr {
			return true
		}
	}
	return false
}

func (a *XSSContextAnalyzer) isEventHandlerAttribute(attrName string) bool {
	for _, eh := range a.eventHandlerAttrs {
		if attrName == eh {
			return true
		}
	}
	return false
}

func (a *XSSContextAnalyzer) containsExecutionPatterns(value string) bool {
	execPatterns := []string{
		`(?i)javascript\s*:`,
		`(?i)vbscript\s*:`,
		`(?i)data\s*:`,
		`(?i)eval\s*\(`,
		`(?i)Function\s*\(`,
		`(?i)setTimeout\s*\(`,
		`(?i)setInterval\s*\(`,
	}

	for _, pattern := range execPatterns {
		if regexp.MustCompile(pattern).MatchString(value) {
			return true
		}
	}
	return false
}

func (a *XSSContextAnalyzer) analyzeByContext(data string, contexts []XSSContext, result *AnalysisResult) {
	contextThreatRules := map[XSSContextType][]struct {
		pattern     *regexp.Regexp
		description string
		threatLevel ThreatLevel
	}{
		ContextJavaScriptBlock: {
			{regexp.MustCompile(`(?i)</script`), "Script block closing", ThreatLevelHigh},
			{regexp.MustCompile(`(?i)<script\s+`), "Nested script opening", ThreatLevelCritical},
			{regexp.MustCompile(`(?i)javascript\s*:`), "JavaScript protocol in script", ThreatLevelCritical},
			{regexp.MustCompile(`(?i)<!--`), "HTML comment in script", ThreatLevelMedium},
		},
		ContextJavaScriptEventHandler: {
			{regexp.MustCompile(`(?i)javascript\s*:`), "JavaScript protocol in event handler", ThreatLevelCritical},
			{regexp.MustCompile(`(?i)vbscript\s*:`), "VBScript protocol in event handler", ThreatLevelCritical},
			{regexp.MustCompile(`(?i)data\s*:\s*text/html`), "Data URI with HTML in event handler", ThreatLevelCritical},
			{regexp.MustCompile(`(?i)eval\s*\(`), "eval() in event handler", ThreatLevelCritical},
			{regexp.MustCompile(`(?i)Function\s*\(`), "Function() in event handler", ThreatLevelCritical},
		},
		ContextJavaScriptURL: {
			{regexp.MustCompile(`(?i)javascript\s*:\s*void`), "JavaScript void in URL", ThreatLevelHigh},
			{regexp.MustCompile(`(?i)javascript\s*:\s*eval`), "JavaScript eval in URL", ThreatLevelCritical},
			{regexp.MustCompile(`(?i)javascript\s*:\s*alert`), "JavaScript alert in URL", ThreatLevelHigh},
			{regexp.MustCompile(`(?i)javascript\s*:\s*document\.`), "Document access in URL", ThreatLevelCritical},
		},
		ContextURL: {
			{regexp.MustCompile(`(?i)javascript\s*:`), "JavaScript protocol in URL attribute", ThreatLevelCritical},
			{regexp.MustCompile(`(?i)vbscript\s*:`), "VBScript protocol in URL attribute", ThreatLevelHigh},
			{regexp.MustCompile(`(?i)data\s*:\s*text/html`), "Data URI with HTML in URL", ThreatLevelCritical},
			{regexp.MustCompile(`(?i)data\s*:\s*text/javascript`), "Data URI with JS in URL", ThreatLevelCritical},
		},
		ContextStyle: {
			{regexp.MustCompile(`(?i)expression\s*\(`), "CSS expression (IE)", ThreatLevelCritical},
			{regexp.MustCompile(`(?i)javascript\s*:`), "JavaScript protocol in style", ThreatLevelCritical},
			{regexp.MustCompile(`(?i)url\s*\(\s*["']?\s*javascript:`), "JavaScript URL in CSS", ThreatLevelCritical},
			{regexp.MustCompile(`(?i)behavior\s*:`), "CSS behavior (IE)", ThreatLevelHigh},
			{regexp.MustCompile(`(?i)-moz-binding`), "Moz-binding (legacy Firefox)", ThreatLevelHigh},
		},
		ContextHTMLAttributeDoubleQuote: {
			{regexp.MustCompile(`(?i)"\s*>`), "Quote closed in attribute", ThreatLevelHigh},
			{regexp.MustCompile(`(?i)"\s*\x00`), "Null byte in attribute", ThreatLevelMedium},
			{regexp.MustCompile(`(?i)"\s*on\w+\s*=`), "Event handler after quote", ThreatLevelCritical},
		},
		ContextHTMLAttributeSingleQuote: {
			{regexp.MustCompile(`(?i)'\s*>`), "Quote closed in single-quoted attribute", ThreatLevelHigh},
			{regexp.MustCompile(`(?i)'\s*on\w+\s*=`), "Event handler after single quote", ThreatLevelCritical},
		},
		ContextHTMLAttributeNoQuote: {
			{regexp.MustCompile(`(?i)>\s*<`), "Tag traversal without quote", ThreatLevelHigh},
			{regexp.MustCompile(`(?i)\s+on\w+\s*=`), "Event handler without quote", ThreatLevelCritical},
		},
		ContextJSON: {
			{regexp.MustCompile(`(?i)</script`), "Script closing in JSON", ThreatLevelHigh},
			{regexp.MustCompile(`(?i)<!--`), "HTML comment in JSON", ThreatLevelMedium},
			{regexp.MustCompile(`\x3c`), "Less-than in JSON (potential HTML context)", ThreatLevelMedium},
		},
	}

	for _, ctx := range contexts {
		rules, exists := contextThreatRules[ctx.ContextType]
		if !exists {
			continue
		}

		for _, rule := range rules {
			if rule.pattern.MatchString(data) {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    rule.threatLevel,
					Pattern:        rule.pattern.String(),
					Description:    rule.description + " (上下文: " + ctx.ContextType.String() + ")",
					Recommendation: "上下文感知建议：根据当前上下文进行适当编码",
				})
			}
		}
	}
}

func (a *XSSContextAnalyzer) analyzeContextAwareXSS(data string, contexts []XSSContext, result *AnalysisResult) {
	for _, ctx := range contexts {
		switch ctx.ContextType {
		case ContextJavaScriptBlock, ContextJavaScriptEventHandler:
			a.analyzeJSInScriptContext(data, ctx, result)

		case ContextURL:
			a.analyzeXSSInURLContext(data, ctx, result)

		case ContextStyle:
			a.analyzeXSSInStyleContext(data, ctx, result)

		case ContextHTMLOutside:
			a.analyzeXSSInHTMLOutsideContext(data, ctx, result)

		case ContextHTMLTag:
			a.analyzeXSSInTagContext(data, ctx, result)

		case ContextHTMLAttributeDoubleQuote, ContextHTMLAttributeSingleQuote, ContextHTMLAttributeNoQuote:
			a.analyzeXSSInAttributeContext(data, ctx, result)
		}
	}
}

func (a *XSSContextAnalyzer) analyzeJSInScriptContext(data string, ctx XSSContext, result *AnalysisResult) {
	jsSinkPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)innerHTML\s*=`, "innerHTML赋值 (DOM XSS sink)", ThreatLevelCritical},
		{`(?i)outerHTML\s*=`, "outerHTML赋值", ThreatLevelCritical},
		{`(?i)insertAdjacentHTML`, "insertAdjacentHTML (DOM XSS sink)", ThreatLevelCritical},
		{`(?i)document\.write\s*\(`, "document.write (DOM XSS sink)", ThreatLevelCritical},
		{`(?i)document\.writeln\s*\(`, "document.writeln (DOM XSS sink)", ThreatLevelCritical},
		{`(?i)eval\s*\(`, "eval()执行 (关键XSS sink)", ThreatLevelCritical},
		{`(?i)Function\s*\(`, "Function构造器 (间接eval)", ThreatLevelCritical},
		{`(?i)setTimeout\s*\(\s*["']?\s*[^"']+\s*["']?`, "setTimeout字符串 (间接eval)", ThreatLevelHigh},
		{`(?i)setInterval\s*\(\s*["']?\s*[^"']+\s*["']?`, "setInterval字符串 (间接eval)", ThreatLevelHigh},
		{`(?i)execScript\s*\(`, "execScript (IE间接eval)", ThreatLevelHigh},
	}

	for _, p := range jsSinkPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description + " (JavaScript上下文)",
				Recommendation: "避免使用innerHTML; 使用textContent; 实施CSP",
			})
		}
	}
}

func (a *XSSContextAnalyzer) analyzeXSSInURLContext(data string, ctx XSSContext, result *AnalysisResult) {
	urlXssPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)javascript\s*:`, "JavaScript伪协议", ThreatLevelCritical},
		{`(?i)vbscript\s*:`, "VBScript伪协议", ThreatLevelCritical},
		{`(?i)vbs:`, "VBScript短协议", ThreatLevelCritical},
		{`(?i)data\s*:\s*text/html`, "Data URI带HTML内容", ThreatLevelCritical},
		{`(?i)data\s*:\s*text/javascript`, "Data URI带JavaScript", ThreatLevelCritical},
		{`(?i)data\s*:\s*application/javascript`, "Data URI带JS应用类型", ThreatLevelHigh},
	}

	for _, p := range urlXssPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description + " (URL上下文)",
				Recommendation: "验证URL协议; 使用URL白名单; 实施CSP",
			})
		}
	}
}

func (a *XSSContextAnalyzer) analyzeXSSInStyleContext(data string, ctx XSSContext, result *AnalysisResult) {
	styleXssPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)expression\s*\(`, "CSS expression (IE mXSS)", ThreatLevelCritical},
		{`(?i)javascript\s*:`, "JavaScript伪协议在CSS中", ThreatLevelCritical},
		{`(?i)url\s*\(\s*["']?\s*javascript:`, "JavaScript URL在CSS中", ThreatLevelCritical},
		{`(?i)url\s*\(\s*["']?\s*vbscript:`, "VBScript URL在CSS中", ThreatLevelCritical},
		{`(?i)behavior\s*:`, "CSS behavior属性 (IE)", ThreatLevelHigh},
		{`(?i)-moz-binding`, "Moz-binding (旧版Firefox)", ThreatLevelHigh},
		{`(?i)import\s*`, "CSS @import", ThreatLevelMedium},
	}

	for _, p := range styleXssPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description + " (CSS上下文)",
				Recommendation: "避免在style中使用用户输入; 使用CSS安全编码",
			})
		}
	}
}

func (a *XSSContextAnalyzer) analyzeXSSInHTMLOutsideContext(data string, ctx XSSContext, result *AnalysisResult) {
	htmlOutsidePatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)<script[^>]*>`, "Script标签开始", ThreatLevelCritical},
		{`(?i)</script>`, "Script标签结束", ThreatLevelCritical},
		{`(?i)<iframe[^>]*>`, "Iframe标签", ThreatLevelHigh},
		{`(?i)<object[^>]*>`, "Object标签", ThreatLevelHigh},
		{`(?i)<embed[^>]*>`, "Embed标签", ThreatLevelHigh},
		{`(?i)<applet[^>]*>`, "Applet标签", ThreatLevelCritical},
		{`(?i)<form[^>]*>`, "Form标签", ThreatLevelMedium},
		{`(?i)<svg[^>]*>`, "SVG标签", ThreatLevelHigh},
		{`(?i)<math[^>]*>`, "Math标签 (mXSS)", ThreatLevelHigh},
	}

	for _, p := range htmlOutsidePatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description + " (HTML外部上下文)",
				Recommendation: "对所有HTML特殊字符进行编码",
			})
		}
	}
}

func (a *XSSContextAnalyzer) analyzeXSSInTagContext(data string, ctx XSSContext, result *AnalysisResult) {
	tagCtxPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)<\s*/?\s*\w+\s*on\w+\s*=`, "标签内事件处理器", ThreatLevelCritical},
		{`(?i)<\s*\w+\s+[^>]*\s+on\w+\s*=`, "标签属性中事件处理器", ThreatLevelCritical},
		{`(?i)<\s*script[^>]*src\s*=`, "外部脚本引用", ThreatLevelCritical},
		{`(?i)<\s*a[^>]*href\s*=\s*["']?\s*javascript:`, "A标签JavaScript href", ThreatLevelCritical},
		{`(?i)<\s*img[^>]*src\s*=\s*["']?\s*x`, "Img src xss向量", ThreatLevelCritical},
		{`(?i)<\s*img[^>]*onerror\s*=`, "Img onerror处理器", ThreatLevelCritical},
	}

	for _, p := range tagCtxPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description + " (标签上下文: " + ctx.TagName + ")",
				Recommendation: "对标签名和属性进行严格验证",
			})
		}
	}
}

func (a *XSSContextAnalyzer) analyzeXSSInAttributeContext(data string, ctx XSSContext, result *AnalysisResult) {
	quotedAttrPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)"[^"]*on\w+\s*="`, "双引号内事件处理器", ThreatLevelCritical},
		{`(?i)'[^']*on\w+\s*='`, "单引号内事件处理器", ThreatLevelCritical},
		{`[^"']*\s*on\w+\s*=`, "无引号事件处理器", ThreatLevelCritical},
		{`(?i)"[^"]*javascript\s*:`, "双引号内JavaScript协议", ThreatLevelCritical},
		{`(?i)'[^']*javascript\s*:`, "单引号内JavaScript协议", ThreatLevelHigh},
	}

	for _, p := range quotedAttrPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description + " (属性上下文: " + ctx.AttributeName + ")",
				Recommendation: "对属性值进行严格验证和编码",
			})
		}
	}
}

func (a *XSSContextAnalyzer) analyzeFalsePositiveMitigation(data string, contexts []XSSContext, result *AnalysisResult) {
	searchBoxPatterns := []string{
		`<script>`,
		`</script>`,
		`<script src=`,
		`onerror=`,
		`onload=`,
		`javascript:`,
		`vbscript:`,
	}

	for _, pattern := range searchBoxPatterns {
		if data == pattern || data == pattern+">" {
			isFalsePositive := false

			for _, ctx := range contexts {
				if ctx.ContextType == ContextHTMLOutside {
					hasContextualDanger := false
					for _, p2 := range searchBoxPatterns {
						if strings.Contains(data, p2) {
							checkRE := regexp.MustCompile(`(?i)` + p2)
							if checkRE.MatchString(data) && !strings.Contains(data, "=") {
								hasContextualDanger = true
								break
							}
						}
					}

					if !hasContextualDanger {
						isFalsePositive = true
						break
					}
				}
			}

			if isFalsePositive {
				result.ThreatLevel = ThreatLevelLow
				result.RiskScore *= 0.3
				result.Details["false_positive_mitigation"] = true
				result.Details["detected_pattern"] = pattern
				result.Recommendations = append(result.Recommendations, "检测到搜索框输入模式，可能为误报")
			}
		}
	}

	hasOpeningScript := regexp.MustCompile(`(?i)<script`).MatchString(data)
	hasClosingScript := regexp.MustCompile(`(?i)</script>`).MatchString(data)
	hasEventHandler := regexp.MustCompile(`(?i)\s+on\w+\s*=\s*`).MatchString(data)
	hasJSProtocol := regexp.MustCompile(`(?i)javascript\s*:`).MatchString(data)

	if hasOpeningScript && !hasClosingScript && hasJSProtocol {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelMedium,
			Pattern:        "unclosed_script_with_js",
			Description:    "未闭合的script标签伴随JavaScript协议",
			Recommendation: "建议验证script标签是否正确闭合",
		})
	}

	if hasOpeningScript && !hasClosingScript && !hasEventHandler && !hasJSProtocol {
		for _, ctx := range contexts {
			if ctx.ContextType == ContextHTMLOutside {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    ThreatLevelLow,
					Pattern:        "incomplete_script_tag",
					Description:    "检测到不完整的script标签，可能是用户输入",
					Recommendation: "建议进行HTML编码后存储",
				})
				break
			}
		}
	}
}

func (a *XSSContextAnalyzer) AnalyzeWithOutputContext(input *AnalysisInput, outputContext string) *AnalysisResult {
	start := time.Now()
	result := NewAnalysisResult(a)

	if input == nil || input.Raw == "" {
		result.ProcessingTime = time.Since(start)
		return result
	}

	contexts := a.ParseOutputContext(outputContext)
	a.analyzeByContext(input.Raw, contexts, result)
	a.analyzeContextAwareXSS(input.Raw, contexts, result)

	result.ProcessingTime = time.Since(start)
	result.ShouldBlock = result.ShouldBlockRequest(0.6)

	return result
}

func (a *XSSContextAnalyzer) ParseOutputContext(outputHTML string) []XSSContext {
	contexts := make([]XSSContext, 0)

	if outputHTML == "" {
		contexts = append(contexts, XSSContext{
			ContextType: ContextHTMLOutside,
		})
		return contexts
	}

	if strings.Contains(outputHTML, "<script") || strings.Contains(outputHTML, "</script") {
		contexts = append(contexts, XSSContext{
			ContextType:     ContextJavaScriptBlock,
			IsScriptContext: true,
		})
	}

	if strings.Contains(outputHTML, "<style") || strings.Contains(outputHTML, "</style") {
		contexts = append(contexts, XSSContext{
			ContextType:    ContextStyle,
			IsStyleContext: true,
		})
	}

	scriptContentMatches := a.scriptContentRE.FindAllStringSubmatchIndex(outputHTML, -1)
	for _, match := range scriptContentMatches {
		if len(match) >= 4 {
			scriptContent := outputHTML[match[0]:match[1]]
			if strings.Contains(strings.ToLower(scriptContent), "application/json") {
				contexts = append(contexts, XSSContext{
					ContextType: ContextJSON,
				})
			}
		}
	}

	eventHandlerMatches := a.eventHandlerRE.FindAllStringIndex(outputHTML, -1)
	for _, match := range eventHandlerMatches {
		contexts = append(contexts, XSSContext{
			ContextType: ContextJavaScriptEventHandler,
		})
	}

	urlAttrMatches := a.urlAttrRE.FindAllStringIndex(outputHTML, -1)
	for _, match := range urlAttrMatches {
		contexts = append(contexts, XSSContext{
			ContextType: ContextURL,
		})
	}

	if len(contexts) == 0 {
		contexts = append(contexts, XSSContext{
			ContextType: ContextHTMLOutside,
		})
	}

	return contexts
}

func (a *XSSContextAnalyzer) GetContextDescription(ctx XSSContext) string {
	switch ctx.ContextType {
	case ContextHTMLOutside:
		return "HTML外部上下文 - 最安全的上下文，用户输入将被视为纯文本"
	case ContextHTMLTag:
		return "HTML标签上下文 - 标签名和属性名区域"
	case ContextHTMLAttributeDoubleQuote:
		return "HTML属性上下文(双引号) - 属性值在双引号内"
	case ContextHTMLAttributeSingleQuote:
		return "HTML属性上下文(单引号) - 属性值在单引号内"
	case ContextHTMLAttributeNoQuote:
		return "HTML属性上下文(无引号) - 属性值无引号包裹，最危险"
	case ContextJavaScriptBlock:
		return "JavaScript块上下文 - <script>标签内的JavaScript代码"
	case ContextJavaScriptEventHandler:
		return "JavaScript事件处理器上下文 - 事件处理器属性值内"
	case ContextJavaScriptURL:
		return "JavaScript URL上下文 - javascript:协议URL"
	case ContextCSS:
		return "CSS上下文 - style属性或<style>标签内"
	case ContextURL:
		return "URL上下文 - href, src等URL属性内"
	case ContextJSON:
		return "JSON上下文 - <script type=\"application/json\">内"
	case ContextTextarea:
		return "Textarea上下文 - <textarea>标签内，内容不会被解析"
	case ContextTitle:
		return "Title上下文 - <title>标签内，内容作为页面标题"
	case ContextNoscript:
		return "Noscript上下文 - <noscript>标签内"
	case ContextStyle:
		return "Style上下文 - <style>标签内"
	case ContextXMP:
		return "XMP上下文 - <xmp>标签内，内容被视为原始文本"
	case ContextListing:
		return "Listing上下文 - <listing>标签内"
	case ContextTemplate:
		return "Template上下文 - <template>标签内"
	default:
		return "未知上下文"
	}
}
