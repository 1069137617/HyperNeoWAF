package analyzer

import (
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
)

type XSSAnalyzer struct {
	name         string
	version      string
	analyzerType string
	enabled      bool
	config       map[string]interface{}
	mu           sync.RWMutex
}

func NewXSSAnalyzer() *XSSAnalyzer {
	return &XSSAnalyzer{
		name:         "xss_analyzer",
		version:      "1.0.0",
		analyzerType: "xss",
		enabled:      true,
		config:       make(map[string]interface{}),
	}
}

func (a *XSSAnalyzer) Name() string {
	return a.name
}

func (a *XSSAnalyzer) Type() string {
	return a.analyzerType
}

func (a *XSSAnalyzer) Version() string {
	return a.version
}

func (a *XSSAnalyzer) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

func (a *XSSAnalyzer) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

func (a *XSSAnalyzer) Configure(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = config
	return nil
}

func (a *XSSAnalyzer) Analyze(input *AnalysisInput) *AnalysisResult {
	start := time.Now()
	result := NewAnalysisResult(a)

	if input == nil || input.Raw == "" {
		return result
	}

	dataToAnalyze := a.prepareData(input)

	a.analyzeScriptTags(dataToAnalyze, result)
	a.analyzeEventHandlers(dataToAnalyze, result)
	a.analyzeJavaScriptProtocol(dataToAnalyze, result)
	a.analyzeDOMManipulation(dataToAnalyze, result)
	a.analyzeDataTheft(dataToAnalyze, result)
	a.analyzeEncodedXSS(dataToAnalyze, result)
	a.analyzeStoredXSS(dataToAnalyze, result)
	a.analyzeReflectedXSS(dataToAnalyze, input, result)
	a.analyzeMutationXSS(dataToAnalyze, result)
	a.analyzeTemplateInjection(dataToAnalyze, result)

	result.ProcessingTime = time.Since(start)
	result.ShouldBlock = result.ShouldBlockRequest(0.6)
	if len(result.Matches) > 0 {
		result.ShouldLog = true
		result.ShouldAllow = !result.ShouldBlock
	}

	return result
}

func (a *XSSAnalyzer) prepareData(input *AnalysisInput) string {
	var sb strings.Builder
	sb.WriteString(input.Raw)
	sb.WriteString(" ")
	sb.WriteString(input.Path)
	sb.WriteString(" ")
	sb.WriteString(input.QueryString)
	sb.WriteString(" ")
	sb.WriteString(input.Body)
	if input.Headers != nil {
		for k, v := range input.Headers {
			sb.WriteString(" ")
			sb.WriteString(k)
			sb.WriteString(": ")
			sb.WriteString(v)
		}
	}
	return sb.String()
}

func (a *XSSAnalyzer) analyzeScriptTags(data string, result *AnalysisResult) {
	scriptPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)<script[^>]*>`, "Script tag opening", ThreatLevelCritical},
		{`(?i)</script>`, "Script tag closing", ThreatLevelCritical},
		{`(?i)<script[^>]*src\s*=`, "External script inclusion", ThreatLevelCritical},
		{`(?i)<script[^>]*src\s*=\s*["']?\s*https?://`, "External script from HTTP", ThreatLevelCritical},
		{`(?i)<script[^>]*src\s*=\s*["']?\s*javascript:`, "JavaScript protocol in script src", ThreatLevelCritical},
		{`(?i)<script[^>]*charset\s*=`, "Script with charset attribute", ThreatLevelHigh},
		{`(?i)<script[^>]*id\s*=`, "Script with ID attribute", ThreatLevelMedium},
		{`(?i)<script[^>]*type\s*=\s*["']?text/javascript`, "JavaScript MIME type", ThreatLevelMedium},
		{`(?i)<script[^>]*type\s*=\s*["']?application/javascript`, "JavaScript MIME type alt", ThreatLevelMedium},
		{`(?i)<script[^>]*type\s*=\s*["']?\s*>\s*[^<]+`, "Inline script block", ThreatLevelCritical},
		{`(?i)<\s*/\s*script`, "Script closing tag", ThreatLevelHigh},
		{`(?i)<script[^>]*>[\s\S]*?</script[^>]*>`, "Full script block", ThreatLevelCritical},
	}

	for _, p := range scriptPatterns {
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
				Evidence:       data[match[0]:min(match[1], match[0]+100)],
				Recommendation: "HTML-encode script tags and validate content context",
			})
		}
	}
}

func (a *XSSAnalyzer) analyzeEventHandlers(data string, result *AnalysisResult) {
	eventHandlers := []string{
		"onload", "onerror", "onclick", "onmouseover", "onmouseout",
		"onmousedown", "onmouseup", "onfocus", "onblur", "onchange",
		"onsubmit", "onreset", "onselect", "onkeydown", "onkeyup",
		"onkeypress", "ondblclick", "oncontextmenu", "onabort", "onbeforeunload",
		"ondrag", "ondragend", "ondragenter", "ondragleave", "ondragover",
		"ondragstart", "ondrop", "oninput", "oninvalid", "onsearch",
		"onpaste", "oncopy", "oncuts", "oncanplay", "oncanplaythrough",
		"oncuechange", "ondurationchange", "onemptied", "onended", "onloadeddata",
		"onloadedmetadata", "onloadstart", "onpause", "onplay", "onplaying",
		"onprogress", "onratechange", "onseeked", "onseeking", "onstalled",
		"onsuspend", "ontimeupdate", "onvolumechange", "onwaiting",
	}

	handlerPattern := regexp.MustCompile(`(?i)\s+on\w+\s*=\s*`)
	if handlerPattern.MatchString(data) {
		for _, handler := range eventHandlers {
			pattern := `(?i)` + handler + `\s*=\s*`
			re := regexp.MustCompile(pattern)
			if re.MatchString(data) {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    ThreatLevelCritical,
					Pattern:        handler,
					Description:    "XSS via event handler: " + handler,
					Recommendation: "HTML-encode event handlers; use Content Security Policy",
				})
			}
		}

		dangerousAttrs := []string{"style", "dynsrc", "lowsrc", "formaction", "data"}
		for _, attr := range dangerousAttrs {
			pattern := `(?i)\s+` + attr + `\s*=\s*[^>\s]+`
			re := regexp.MustCompile(pattern)
			if re.MatchString(data) {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    ThreatLevelHigh,
					Pattern:        attr,
					Description:    "Potentially dangerous attribute: " + attr,
					Recommendation: "Validate attribute values and use allowlist",
				})
			}
		}
	}
}

func (a *XSSAnalyzer) analyzeJavaScriptProtocol(data string, result *AnalysisResult) {
	jsProtocolPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)javascript\s*:`, "JavaScript protocol URI", ThreatLevelCritical},
		{`(?i)jscript\s*:`, "JScript protocol (IE)", ThreatLevelCritical},
		{`(?i)vbscript\s*:`, "VBScript protocol", ThreatLevelCritical},
		{`(?i)vbs:`, "VBScript short protocol", ThreatLevelCritical},
		{`(?i)livescript\s*:`, "Livescript protocol", ThreatLevelHigh},
		{`(?i)data\s*:\s*text/html`, "Data URI with HTML content", ThreatLevelCritical},
		{`(?i)data\s*:\s*text/javascript`, "Data URI with JavaScript", ThreatLevelCritical},
		{`(?i)data\s*:\s*application/javascript`, "Data URI with JS app type", ThreatLevelHigh},
		{`(?i)javascript\s*:\s*eval`, "JavaScript eval execution", ThreatLevelCritical},
		{`(?i)javascript\s*:\s*alert`, "JavaScript alert execution", ThreatLevelHigh},
		{`(?i)javascript\s*:\s*confirm`, "JavaScript confirm execution", ThreatLevelHigh},
		{`(?i)javascript\s*:\s*prompt`, "JavaScript prompt execution", ThreatLevelHigh},
		{`(?i)javascript\s*:\s*document\.`, "JavaScript document manipulation", ThreatLevelCritical},
		{`(?i)javascript\s*:\s*window\.`, "JavaScript window manipulation", ThreatLevelCritical},
		{`(?i)javascript\s*:\s*location\.`, "JavaScript location manipulation", ThreatLevelCritical},
		{`(?i)javascript\s*:\s*history\.`, "JavaScript history manipulation", ThreatLevelHigh},
		{`(?i)javascript\s*:\s*top\.`, "JavaScript top object access", ThreatLevelHigh},
		{`(?i)javascript\s*:\s*parent\.`, "JavaScript parent object access", ThreatLevelHigh},
		{`(?i)javascript\s*:\s*frames\.`, "JavaScript frames access", ThreatLevelHigh},
	}

	for _, p := range jsProtocolPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "Block javascript: URIs; use CSP to prevent inline scripts",
			})
		}
	}
}

func (a *XSSAnalyzer) analyzeDOMManipulation(data string, result *AnalysisResult) {
	domPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)innerHTML\s*=`, "innerHTML assignment (DOM XSS sink)", ThreatLevelCritical},
		{`(?i)outerHTML\s*=`, "outerHTML assignment", ThreatLevelCritical},
		{`(?i)insertAdjacentHTML`, "insertAdjacentHTML (DOM XSS sink)", ThreatLevelCritical},
		{`(?i)write\s*\(`, "document.write (DOM XSS sink)", ThreatLevelCritical},
		{`(?i)writeln\s*\(`, "document.writeln (DOM XSS sink)", ThreatLevelCritical},
		{`(?i)document\.cookie`, "Cookie access (data theft vector)", ThreatLevelCritical},
		{`(?i)document\.domain`, "Domain access", ThreatLevelMedium},
		{`(?i)document\.referrer`, "Referrer access", ThreatLevelMedium},
		{`(?i)document\.title`, "Title access/modification", ThreatLevelLow},
		{`(?i)document\.baseURI`, "Base URI access", ThreatLevelMedium},
		{`(?i)document\.URL`, "Document URL access", ThreatLevelMedium},
		{`(?i)window\.location`, "Window location (navigation + info)", ThreatLevelHigh},
		{`(?i)location\.href`, "Location href (navigation)", ThreatLevelHigh},
		{`(?i)location\.search`, "Location search (query info)", ThreatLevelMedium},
		{`(?i)location\.hash`, "Location hash (info exfil)", ThreatLevelMedium},
		{`(?i)history\.pushState`, "History pushState (URL spoofing)", ThreatLevelMedium},
		{`(?i)history\.replaceState`, "History replaceState (URL spoofing)", ThreatLevelMedium},
		{`(?i)eval\s*\(`, "eval() execution (critical XSS sink)", ThreatLevelCritical},
		{`(?i)Function\s*\(`, "Function constructor (indirect eval)", ThreatLevelCritical},
		{`(?i)setTimeout\s*\(\s*["']?\s*\w+\s*["']?`, "setTimeout with string (indirect eval)", ThreatLevelHigh},
		{`(?i)setInterval\s*\(\s*["']?\s*\w+\s*["']?`, "setInterval with string (indirect eval)", ThreatLevelHigh},
		{`(?i)execScript\s*\(`, "execScript (IE, indirect eval)", ThreatLevelHigh},
		{`(?i)createEvent\s*\(`, "Event creation", ThreatLevelMedium},
		{`(?i)cloneNode\s*\(`, "Node cloning (potential mXSS)", ThreatLevelMedium},
		{`(?i)importNode\s*\(`, "Node import (potential mXSS)", ThreatLevelMedium},
		{`(?i)XMLHttpRequest`, "AJAX/XMLHttpRequest (data exfil)", ThreatLevelMedium},
		{`(?i)fetch\s*\(`, "Fetch API (data exfil)", ThreatLevelMedium},
		{`(?i)WebSocket\s*\(`, "WebSocket (data exfil)", ThreatLevelMedium},
		{`(?i)atob\s*\(`, "Base64 decode (payload obfuscation)", ThreatLevelMedium},
		{`(?i)btoa\s*\(`, "Base64 encode (data exfil)", ThreatLevelMedium},
		{`(?i)crypto\.`, "Crypto API access", ThreatLevelMedium},
		{`(?i)open\s*\([^)]*["']?\s*GET`, "XHR open GET (CSRF vector)", ThreatLevelMedium},
	}

	for _, p := range domPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "Avoid innerHTML; use textContent where possible; implement CSP",
			})
		}
	}
}

func (a *XSSAnalyzer) analyzeDataTheft(data string, result *AnalysisResult) {
	theftPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)fetch\s*\(\s*["']https?://`, "Data exfiltration via fetch", ThreatLevelCritical},
		{`(?i)XMLHttpRequest.*open.*GET.*send`, "XHR data theft pattern", ThreatLevelCritical},
		{`(?i)\.getElementById\s*\(`, "DOM element access", ThreatLevelLow},
		{`(?i)\.getElementsByTagName\s*\(`, "DOM element collection access", ThreatLevelLow},
		{`(?i)\.querySelectorAll\s*\(`, "DOM querySelectorAll", ThreatLevelMedium},
		{`(?i)\.querySelector\s*\(`, "DOM querySelector", ThreatLevelMedium},
		{`(?i)localStorage\.`, "LocalStorage access (data theft)", ThreatLevelHigh},
		{`(?i)sessionStorage\.`, "SessionStorage access (data theft)", ThreatLevelHigh},
		{`(?i)indexedDB\.`, "IndexedDB access", ThreatLevelMedium},
		{`(?i)\.sendBeacon\s*\(`, "Navigator sendBeacon (stealth exfil)", ThreatLevelHigh},
		{`(?i)navigator\.clipboard`, "Clipboard API (data theft)", ThreatLevelMedium},
		{`(?i)navigator\.credentials`, "Credentials API access", ThreatLevelHigh},
		{`(?i)Performance\.`, "Performance API (timing attacks)", ThreatLevelLow},
		{`(?i)AnimationFrame`, "AnimationFrame (timing attacks)", ThreatLevelLow},
		{`(?i)console\.`, "Console API (devtools detection)", ThreatLevelLow},
		{`(?i)postMessage\s*\(`, "postMessage (cross-origin comm)", ThreatLevelMedium},
	}

	for _, p := range theftPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "Validate origin in postMessage; protect storage with encryption",
			})
		}
	}
}

func (a *XSSAnalyzer) analyzeEncodedXSS(data string, result *AnalysisResult) {
	encodedPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)%3Cscript`, "URL Encoded: <script", ThreatLevelCritical},
		{`(?i)%3C/script%3E`, "URL Encoded: </script>", ThreatLevelCritical},
		{`(?i)%3Cimg[^%]*src\s*=\s*['"]?\s*x`, "URL Encoded: img xss", ThreatLevelCritical},
		{`(?i)%3Ciframe`, "URL Encoded: <iframe", ThreatLevelCritical},
		{`(?i)%3Csvg[^%]*onload`, "URL Encoded: svg onload", ThreatLevelCritical},
		{`&#\d+;`, "Decimal HTML Entity", ThreatLevelHigh},
		{`&#x[0-9a-f]+;`, "Hexadecimal HTML Entity", ThreatLevelHigh},
		{`&#\d+`, "Bare Decimal Entity", ThreatLevelMedium},
		{`&#x[0-9a-f]+`, "Bare Hex Entity", ThreatLevelMedium},
		{`\\x[0-9a-f]{2}`, "Hex Escape Sequence", ThreatLevelHigh},
		{`\\u[0-9a-f]{4}`, "Unicode Escape Sequence", ThreatLevelHigh},
		{`\\0`, "Null Character Escape", ThreatLevelMedium},
		{`<[^\w\d]+[^\>]*>`, "Obfuscated HTML tag", ThreatLevelHigh},
		{`\x3cscript`, "Hex encoded <script", ThreatLevelCritical},
		{`\x3e`, "Hex encoded >", ThreatLevelMedium},
		{`[\x00-\x08\x0B\x0C\x0E-\x1F]`, "Control character injection", ThreatLevelMedium},
	}

	for _, p := range encodedPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.description,
				Description:    "Encoded XSS attempt: " + p.description,
				Recommendation: "Decode input before validation; apply proper encoding on output",
			})
		}
	}

	a.analyzeUnicodeBypass(data, result)
}

func (a *XSSAnalyzer) analyzeUnicodeBypass(data string, result *AnalysisResult) {
	unicodeBypass := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\u003c`, "Unicode < (LEFT ANGULAR BRACKET)", ThreatLevelHigh},
		{`\u003e`, "Unicode > (RIGHT ANGULAR BRACKET)", ThreatLevelHigh},
		{`\u0027`, "Unicode ' (APOSTROPHE)", ThreatLevelMedium},
		{`\u0022`, "Unicode \" (QUOTATION MARK)", ThreatLevelMedium},
		{`\u003d`, "Unicode = (EQUALS SIGN)", ThreatLevelMedium},
		{`\u002d`, "Unicode - (HYPHEN-MINUS)", ThreatLevelLow},
		{`\u006a`, "Unicode j (lowercase j in javascript:)", ThreatLevelMedium},
		{`\u0061`, "Unicode a (lowercase a)", ThreatLevelLow},
		{`\u0076`, "Unicode v (lowercase v)", ThreatLevelLow},
		{`\u0062`, "Unicode b (lowercase b)", ThreatLevelLow},
	}

	for _, p := range unicodeBypass {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.description,
				Description:    "Unicode encoding bypass: " + p.description,
				Recommendation: "Normalize Unicode before validation; use strict allowlist",
			})
		}
	}
}

func (a *XSSAnalyzer) analyzeStoredXSS(data string, result *AnalysisResult) {
	storedPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)<video[^>]*>`, "Video tag (stored XSS vector)", ThreatLevelHigh},
		{`(?i)<audio[^>]*>`, "Audio tag (stored XSS vector)", ThreatLevelHigh},
		{`(?i)<source[^>]*>`, "Media source tag", ThreatLevelMedium},
		{`(?i)<track[^>]*>`, "Track element", ThreatLevelMedium},
		{`(?i)<object[^>]*>`, "Object embed (legacy XSS)", ThreatLevelHigh},
		{`(?i)<embed[^>]*>`, "Embed element (plugin XSS)", ThreatLevelHigh},
		{`(?i)<applet[^>]*>`, "Applet (Java legacy)", ThreatLevelCritical},
		{`(?i)<marquee[^>]*>`, "Marquee tag (IE XSS)", ThreatLevelMedium},
		{`(?i)<keygen[^>]*>`, "Keygen (old browser XSS)", ThreatLevelMedium},
		{`(?i)<details[^>]*open[^>]*>`, "Details open attribute", ThreatLevelMedium},
		{`(?i)<portal[^>]*>`, "Portal element (mXSS)", ThreatLevelHigh},
		{`(?i)<math[^>]*>`, "Math element (mXSS vector)", ThreatLevelHigh},
		{`(?i)<noscript[^>]*>`, "Noscript manipulation", ThreatLevelMedium},
	}

	for _, p := range storedPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Stored XSS vector: " + p.description,
				Recommendation: "Strict HTML sanitization; context-aware output encoding",
			})
		}
	}
}

func (a *XSSAnalyzer) analyzeReflectedXSS(data string, input *AnalysisInput, result *AnalysisResult) {
	if input.QueryString == "" && input.Path == "" {
		return
	}

	suspiciousParams := []string{
		"q", "query", "search", "keyword", "page", "id", "name",
		"url", "callback", "jsonp", "fragment", "ref", "redir",
		"redirect", "next", "data", "input", "val", "v", "pid",
	}

	for _, param := range suspiciousParams {
		pattern := `(?i)(?:` + param + `)=([^&\s]+)`
		re := regexp.MustCompile(pattern)

		pathMatch := re.FindStringSubmatch(input.Path)
		if len(pathMatch) > 1 {
			value := pathMatch[1]
			if a.isSuspiciousReflectedValue(value) {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    ThreatLevelHigh,
					Pattern:        param + "=" + value,
					Description:    "Reflected XSS in URL path parameter: " + param,
					Evidence:       value,
					Recommendation: "URL-encode reflected values; apply context-aware encoding",
				})
			}
		}

		if input.QueryString != "" {
			queryMatch := re.FindStringSubmatch(input.QueryString)
			if len(queryMatch) > 1 {
				value := queryMatch[1]
				if a.isSuspiciousReflectedValue(value) {
					result.AddMatch(Match{
						Type:           MatchTypeSemantic,
						ThreatLevel:    ThreatLevelHigh,
						Pattern:        param + "=" + value,
						Description:    "Reflected XSS in query string parameter: " + param,
						Evidence:       value,
						Recommendation: "URL-encode reflected values; apply context-aware encoding",
					})
				}
			}
		}
	}
}

func (a *XSSAnalyzer) isSuspiciousReflectedValue(value string) bool {
	suspiciousPatterns := []string{
		`<script`, `</script`, `javascript:`, `onerror=`, `onload=`,
		`<img`, `<svg`, `<iframe`, `<embed`, `<object`,
		`"`, `'`, `><`, `>`, `\x`, `\u`, `&#`,
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(strings.ToLower(value), pattern) {
			return true
		}
	}
	return false
}

func (a *XSSAnalyzer) analyzeMutationXSS(data string, result *AnalysisResult) {
	mXSSPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)<noscript[^>]*>.*?</noscript[^>]*>`, "Noscript tag (mXSS)", ThreatLevelMedium},
		{`(?i)<style[^>]*>.*?</style[^>]*>`, "Style tag (mXSS)", ThreatLevelMedium},
		{`(?i)<title[^>]*>.*?</title[^>]*>`, "Title tag (mXSS)", ThreatLevelMedium},
		{`(?i)<textarea[^>]*>.*?</textarea[^>]*>`, "Textarea (mXSS)", ThreatLevelMedium},
		{`(?i)<xmp[^>]*>.*?</xmp[^>]*>`, "XMP tag (deprecated mXSS)", ThreatLevelMedium},
		{`(?i)<listing[^>]*>.*?</listing[^>]*>`, "Listing tag (mXSS)", ThreatLevelMedium},
		{`(?i)<template[^>]*>.*?</template[^>]*>`, "Template tag (mXSS)", ThreatLevelMedium},
		{`(?i)<noembed[^>]*>.*?</noembed[^>]*>`, "Noembed tag (mXSS)", ThreatLevelMedium},
	}

	for _, p := range mXSSPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.description,
				Description:    "Potential Mutation XSS (mXSS) vector: " + p.description,
				Recommendation: "Use DOMPurify or similar sanitizers; avoid raw HTML in SVG",
			})
		}
	}
}

func (a *XSSAnalyzer) analyzeTemplateInjection(data string, result *AnalysisResult) {
	templatePatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\{\{\{.*?\}\}\}`, "Triple brace template (unsafe interpolation)", ThreatLevelHigh},
		{`\{.*?\{\{.*?\}\}.*?\}`, "Nested template expression", ThreatLevelMedium},
		{`\$\{.*?\}`, "ES6 template literal with expression", ThreatLevelMedium},
		{`(?i)<%.*?%>`, "ERB/JSP-style template tag", ThreatLevelHigh},
		{`(?i)<!--.*?-->`, "HTML comment (potential comment injection)", ThreatLevelLow},
		{`(?i)<![.*?]>`, "Conditional comment", ThreatLevelMedium},
		{`(?i)\{\_%20.*?_\%\}`, "Jinja2 comment block", ThreatLevelLow},
		{`(?i)\{_\%.*?\%_\}`, "Jinja2 block", ThreatLevelMedium},
		{`(?i)@*.*?\*@`, "Freemarker interpolation", ThreatLevelMedium},
		{`(?i)\$\[.*?\]`, "Blade template expression", ThreatLevelMedium},
		{`(?i)\#\{.*?\}`, "Ruby interpolation", ThreatLevelMedium},
		{`(?i)<c:out.*?>`, "JSTL out tag", ThreatLevelMedium},
		{`(?i)\$\{.*?\}`, "Angular expression", ThreatLevelMedium},
		{`(?i)\(\(.*?\)\)`, "Angular template syntax", ThreatLevelMedium},
	}

	for _, p := range templatePatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Template injection pattern: " + p.description,
				Recommendation: "Validate template syntax; disable unsafe template features",
			})
		}
	}
}

func isAlphanumeric(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return len(s) > 0
}
