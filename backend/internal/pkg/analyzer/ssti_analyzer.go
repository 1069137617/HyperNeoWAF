package analyzer

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

type SSTIAnalyzer struct {
	name         string
	version      string
	analyzerType string
	enabled      bool
	config       map[string]interface{}
	mu           sync.RWMutex
}

func NewSSTIAnalyzer() *SSTIAnalyzer {
	return &SSTIAnalyzer{
		name:         "ssti_analyzer",
		version:      "1.0.0",
		analyzerType: "ssti",
		enabled:      true,
		config:       make(map[string]interface{}),
	}
}

func (a *SSTIAnalyzer) Name() string {
	return a.name
}

func (a *SSTIAnalyzer) Type() string {
	return a.analyzerType
}

func (a *SSTIAnalyzer) Version() string {
	return a.version
}

func (a *SSTIAnalyzer) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

func (a *SSTIAnalyzer) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

func (a *SSTIAnalyzer) Configure(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = config
	return nil
}

func (a *SSTIAnalyzer) Analyze(input *AnalysisInput) *AnalysisResult {
	start := time.Now()
	result := NewAnalysisResult(a)

	if input == nil || input.Raw == "" {
		return result
	}

	dataToAnalyze := a.prepareData(input)

	a.analyzeJinja2Templates(dataToAnalyze, result)
	a.analyzeTwigTemplates(dataToAnalyze, result)
	a.analyzeFreeMarkerTemplates(dataToAnalyze, result)
	a.analyzeOGNLTemplates(dataToAnalyze, result)
	a.analyzeTemplateSelfExploitation(dataToAnalyze, result)
	a.analyzeTemplateExecutionPatterns(dataToAnalyze, result)
	a.analyzeAngularExpressions(dataToAnalyze, result)
	a.analyzeVelocityTemplates(dataToAnalyze, result)
	a.analyzeSmartyTemplates(dataToAnalyze, result)
	a.analyzeHandlebarsTemplates(dataToAnalyze, result)

	result.ProcessingTime = time.Since(start)
	result.ShouldBlock = result.ShouldBlockRequest(0.6)
	if len(result.Matches) > 0 {
		result.ShouldLog = true
		result.ShouldAllow = !result.ShouldBlock
	}

	return result
}

func (a *SSTIAnalyzer) prepareData(input *AnalysisInput) string {
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

func (a *SSTIAnalyzer) analyzeJinja2Templates(data string, result *AnalysisResult) {
	jinja2Patterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\{\{\{.*?\}\}\}`, "Jinja2 triple brace unescaped output", ThreatLevelCritical},
		{`\{\{.*?\}\}`, "Jinja2 variable expression", ThreatLevelMedium},
		{`\{[%#].*?[%#]\}`, "Jinja2 comment or tag block", ThreatLevelMedium},
		{`\{%\s*extends.*?%\}`, "Jinja2 template inheritance (extends)", ThreatLevelMedium},
		{`\{%\s*include.*?%\}`, "Jinja2 template inclusion", ThreatLevelHigh},
		{`\{%\s*import.*?%\}`, "Jinja2 import statement", ThreatLevelMedium},
		{`\{%\s*from.*?import.*?%\}`, "Jinja2 from-import statement", ThreatLevelMedium},
		{`\{%\s*set.*?%\}`, "Jinja2 variable assignment", ThreatLevelLow},
		{`\{%\s*if.*?%\}`, "Jinja2 conditional", ThreatLevelLow},
		{`\{%\s*for.*?%\}`, "Jinja2 loop", ThreatLevelLow},
		{`\{%\s*block.*?%\}`, "Jinja2 block definition", ThreatLevelLow},
		{`\{#.*?#\}`, "Jinja2 comment", ThreatLevelLow},
		{`\{\|\s*.*?\s*\|\}`, "Jinja2 filter expression", ThreatLevelMedium},
		{`\{\{.*?\|.*?\}\}`, "Jinja2 filtered output", ThreatLevelMedium},
		{`__import__`, "Python __import__ in template", ThreatLevelCritical},
		{`\{\{.*?\}\}\}.*?\{\{`, "Multiple template expressions", ThreatLevelMedium},
	}

	for _, p := range jinja2Patterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Jinja2 SSTI: " + p.description,
				Recommendation: "Validate template syntax; disable unsafe features in template engine",
			})
		}
	}

	a.analyzeJinja2Exploitation(data, result)
}

func (a *SSTIAnalyzer) analyzeJinja2Exploitation(data string, result *AnalysisResult) {
	exploitPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\{\{.*?__class__.*?\}\}`, "Python class introspection in Jinja2", ThreatLevelCritical},
		{`\{\{.*?__mro__.*?\}\}`, "Python MRO access in Jinja2", ThreatLevelCritical},
		{`\{\{.*?__subclasses__.*?\}\}`, "Python subclasses access in Jinja2", ThreatLevelCritical},
		{`\{\{.*?__init__.*?\}\}`, "Python __init__ access in Jinja2", ThreatLevelCritical},
		{`\{\{.*?__globals__.*?\}\}`, "Python globals access in Jinja2", ThreatLevelCritical},
		{`\{\{.*?\._getiter.*?\}\}`, "Python iterator access in Jinja2", ThreatLevelCritical},
		{`\{\{.*?\}|\s*join.*?\}`, "Jinja2 join filter exploitation", ThreatLevelHigh},
		{`\{\{.*?\}|\s*select.*?\}`, "Jinja2 select filter exploitation", ThreatLevelHigh},
		{`\{\{.*?\}|\s*reject.*?\}`, "Jinja2 reject filter exploitation", ThreatLevelHigh},
		{`\{\{.*?\}|\s*map.*?\}`, "Jinja2 map filter exploitation", ThreatLevelHigh},
		{`\{\{.*?\}|\s*attr.*?\}`, "Jinja2 attr filter exploitation", ThreatLevelHigh},
		{`\{\{.*?\}|\s*batch.*?\}`, "Jinja2 batch filter exploitation", ThreatLevelHigh},
		{`\{\{.*?\}|\s*default.*?\}`, "Jinja2 default filter exploitation", ThreatLevelMedium},
		{`\{\{.*?\}.*?\|\s*safe.*?\}`, "Jinja2 safe filter (disables escaping)", ThreatLevelCritical},
		{`\{\{.*?\}|\s*safe.*?\}`, "Jinja2 safe filter usage", ThreatLevelCritical},
		{`\{\{.*?\}|\s*format.*?\}`, "Jinja2 format filter exploitation", ThreatLevelHigh},
		{`\{\{.*?\}|\s*truncate.*?\}`, "Jinja2 truncate filter exploitation", ThreatLevelMedium},
		{`\{\{.*?\}|\s*wordcount.*?\}`, "Jinja2 wordcount filter", ThreatLevelLow},
		{`\{\{.*?\}|\s*capitalize.*?\}`, "Jinja2 capitalize filter", ThreatLevelLow},
		{`\{\{.*?\}|\s*upper.*?\}`, "Jinja2 upper filter", ThreatLevelLow},
		{`\{\{.*?\}|\s*lower.*?\}`, "Jinja2 lower filter", ThreatLevelLow},
		{`\{\{.*?\}|\s*reverse.*?\}`, "Jinja2 reverse filter exploitation", ThreatLevelMedium},
		{`\{\{.*?\}|\s*sort.*?\}`, "Jinja2 sort filter exploitation", ThreatLevelMedium},
		{`\{\{.*?\}|\s*length.*?\}`, "Jinja2 length filter", ThreatLevelLow},
		{`\{\{.*?\}|\s*list.*?\}`, "Jinja2 list filter (string to list)", ThreatLevelMedium},
		{`\{\{.*?\}|\s*int.*?\}`, "Jinja2 int filter exploitation", ThreatLevelMedium},
		{`\{\{.*?\}|\s*string.*?\}`, "Jinja2 string filter exploitation", ThreatLevelMedium},
		{`\{\{.*?\}|\s*replace.*?\}`, "Jinja2 replace filter exploitation", ThreatLevelMedium},
		{`\{\{.*?\}|\s*urlize.*?\}`, "Jinja2 urlize filter exploitation", ThreatLevelMedium},
		{`\{\{.*?\}|\s*wordwrap.*?\}`, "Jinja2 wordwrap filter exploitation", ThreatLevelMedium},
		{`\{\{.*?\}|\s*indent.*?\}`, "Jinja2 indent filter exploitation", ThreatLevelMedium},
		{`\{\{.*?\}|\s*striptags.*?\}`, "Jinja2 striptags filter exploitation", ThreatLevelMedium},
		{`\{\{.*?\}|\s*tojson.*?\}`, "Jinja2 tojson filter exploitation", ThreatLevelHigh},
		{`\{\{.*?\}|\s*flatten.*?\}`, "Jinja2 flatten filter exploitation", ThreatLevelHigh},
		{`\{\{lipsum.*?\}\}`, "Jinja2 lipsum (Lorem Ipsum generation)", ThreatLevelMedium},
		{`\{\{cycler.*?\}\}`, "Jinja2 cycler exploitation", ThreatLevelMedium},
		{`\{\{joiner.*?\}\}`, "Jinja2 joiner exploitation", ThreatLevelMedium},
		{`\{\{namespace.*?\}\}`, "Jinja2 namespace exploitation", ThreatLevelMedium},
	}

	for _, p := range exploitPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Jinja2 SSTI exploitation: " + p.description,
				Recommendation: "Block request; template expressions should not allow Python object access",
			})
		}
	}
}

func (a *SSTIAnalyzer) analyzeTwigTemplates(data string, result *AnalysisResult) {
	twigPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\{\{.*?\}\}`, "Twig variable expression", ThreatLevelMedium},
		{`\{%.*?%\}`, "Twig tag block", ThreatLevelMedium},
		{`\{#.*?#\}`, "Twig comment", ThreatLevelLow},
		{`\{%\s*extends.*?%\}`, "Twig template inheritance", ThreatLevelMedium},
		{`\{%\s*include.*?%\}`, "Twig template inclusion", ThreatLevelHigh},
		{`\{%\s*use.*?%\}`, "Twig use statement", ThreatLevelMedium},
		{`\{%\s*embed.*?%\}`, "Twig embed statement", ThreatLevelHigh},
		{`\{%\s*import.*?%\}`, "Twig import statement", ThreatLevelMedium},
		{`\{%\s*from.*?import.*?%\}`, "Twig from-import", ThreatLevelMedium},
		{`\{%\s*set.*?%\}`, "Twig variable assignment", ThreatLevelLow},
		{`\{%\s*if.*?%\}`, "Twig conditional", ThreatLevelLow},
		{`\{%\s*for.*?%\}`, "Twig loop", ThreatLevelLow},
		{`\{%\s*block.*?%\}`, "Twig block definition", ThreatLevelLow},
		{`\{%\s*macro.*?%\}`, "Twig macro definition", ThreatLevelLow},
		{`\{%\s*import.*?as.*?%\}`, "Twig import with alias", ThreatLevelLow},
		{`\{\{.*?\|.*?\}\}`, "Twig filtered output", ThreatLevelMedium},
		{`\{\{.*?\|raw\}\}`, "Twig raw filter (disables escaping)", ThreatLevelCritical},
		{`\{\{.*?\|_escape\}\}`, "Twig escape filter", ThreatLevelLow},
		{`\{\{.*?\}\}.*?\{\{.*?\}\}`, "Multiple Twig expressions", ThreatLevelMedium},
	}

	for _, p := range twigPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Twig SSTI: " + p.description,
				Recommendation: "Validate template input; disable dangerous filters",
			})
		}
	}

	a.analyzeTwigExploitation(data, result)
}

func (a *SSTIAnalyzer) analyzeTwigExploitation(data string, result *AnalysisResult) {
	exploitPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\{\{.*?_self.*?\}\}`, "Twig _self reference exploitation", ThreatLevelCritical},
		{`\{\{.*?__toString.*?\}\}`, "PHP __toString in Twig", ThreatLevelCritical},
		{`\{\{.*?__construct.*?\}\}`, "PHP __construct in Twig", ThreatLevelCritical},
		{`\{\{.*?__destruct.*?\}\}`, "PHP __destruct in Twig", ThreatLevelCritical},
		{`\{\{.*?__get.*?\}\}`, "PHP __get magic method in Twig", ThreatLevelCritical},
		{`\{\{.*?__call.*?\}\}`, "PHP __call magic method in Twig", ThreatLevelCritical},
		{`\{\{.*?getenv.*?\}\}`, "PHP getenv in Twig", ThreatLevelCritical},
		{`\{\{.*?system.*?\}\}`, "PHP system() in Twig", ThreatLevelCritical},
		{`\{\{.*?exec.*?\}\}`, "PHP exec() in Twig", ThreatLevelCritical},
		{`\{\{.*?shell_exec.*?\}\}`, "PHP shell_exec() in Twig", ThreatLevelCritical},
		{`\{\{.*?passthru.*?\}\}`, "PHP passthru() in Twig", ThreatLevelCritical},
		{`\{\{.*?popen.*?\}\}`, "PHP popen() in Twig", ThreatLevelHigh},
		{`\{\{.*?proc_open.*?\}\}`, "PHP proc_open() in Twig", ThreatLevelHigh},
		{`\{\{.*?curl_exec.*?\}\}`, "PHP curl_exec() in Twig", ThreatLevelHigh},
		{`\{\{.*?file_get_contents.*?\}\}`, "PHP file_get_contents() in Twig", ThreatLevelCritical},
		{`\{\{.*?fopen.*?\}\}`, "PHP fopen() in Twig", ThreatLevelCritical},
		{`\{\{.*?fread.*?\}\}`, "PHP fread() in Twig", ThreatLevelCritical},
		{`\{\{.*?file.*?\}\}`, "PHP file() in Twig", ThreatLevelCritical},
		{`\{\{.*?include.*?\}\}`, "PHP include in Twig", ThreatLevelCritical},
		{`\{\{.*?require.*?\}\}`, "PHP require in Twig", ThreatLevelCritical},
		{`\{\{.*?eval.*?\}\}`, "PHP eval() in Twig", ThreatLevelCritical},
		{`\{\{.*?assert.*?\}\}`, "PHP assert() in Twig", ThreatLevelCritical},
		{`\{\{.*?serialize.*?\}\}`, "PHP serialize() exploitation", ThreatLevelHigh},
		{`\{\{.*?unserialize.*?\}\}`, "PHP unserialize() in Twig", ThreatLevelCritical},
		{`\{\{.*?var_dump.*?\}\}`, "PHP var_dump() information disclosure", ThreatLevelMedium},
		{`\{\{.*?print_r.*?\}\}`, "PHP print_r() information disclosure", ThreatLevelMedium},
		{`\{\{.*?var_export.*?\}\}`, "PHP var_export() information disclosure", ThreatLevelMedium},
		{`\{\{.*?debug.*?\}\}`, "Twig debug output", ThreatLevelMedium},
		{`\{\{dump.*?\}\}`, "Twig dump function", ThreatLevelMedium},
	}

	for _, p := range exploitPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Twig SSTI exploitation: " + p.description,
				Recommendation: "Block request; PHP functions should not be accessible in templates",
			})
		}
	}
}

func (a *SSTIAnalyzer) analyzeFreeMarkerTemplates(data string, result *AnalysisResult) {
	freemarkerPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\$\{.*?\}`, "FreeMarker variable expression", ThreatLevelMedium},
		{`<#.*?>`, "FreeMarker tag directive", ThreatLevelMedium},
		{`<#assign.*?>`, "FreeMarker variable assignment", ThreatLevelLow},
		{`<#if.*?>`, "FreeMarker conditional", ThreatLevelLow},
		{`<#else.*?>`, "FreeMarker else branch", ThreatLevelLow},
		{`<#elseif.*?>`, "FreeMarker elseif branch", ThreatLevelLow},
		{`<#/if>`, "FreeMarker if end", ThreatLevelLow},
		{`<#list.*?>`, "FreeMarker list loop", ThreatLevelLow},
		{`<#list.*?as.*?>`, "FreeMarker list iteration", ThreatLevelLow},
		{`<#/list>`, "FreeMarker list end", ThreatLevelLow},
		{`<#macro.*?>`, "FreeMarker macro definition", ThreatLevelLow},
		{`<#/macro>`, "FreeMarker macro end", ThreatLevelLow},
		{`<#function.*?>`, "FreeMarker function definition", ThreatLevelLow},
		{`<#/function>`, "FreeMarker function end", ThreatLevelLow},
		{`<#return.*?>`, "FreeMarker return statement", ThreatLevelLow},
		{`<#import.*?>`, "FreeMarker import", ThreatLevelMedium},
		{`<#include.*?>`, "FreeMarker include", ThreatLevelHigh},
		{`<#nested.*?>`, "FreeMarker nested content", ThreatLevelMedium},
		{`<#attempt.*?>`, "FreeMarker attempt block", ThreatLevelLow},
		{`<#recover.*?>`, "FreeMarker recover block", ThreatLevelLow},
		{`<#switch.*?>`, "FreeMarker switch", ThreatLevelLow},
		{`<#case.*?>`, "FreeMarker case", ThreatLevelLow},
		{`<#break>`, "FreeMarker break", ThreatLevelLow},
		{`<#default>`, "FreeMarker default", ThreatLevelLow},
		{`<#/switch>`, "FreeMarker switch end", ThreatLevelLow},
		{`\$\{.*?\}`, "FreeMarker dollar interpolation", ThreatLevelMedium},
		{`\#\{.*?\}`, "FreeMarker hash interpolation", ThreatLevelMedium},
		{`!.*?\}`, "FreeMarker default value operator", ThreatLevelLow},
		{`\?.*?\}`, "FreeMarker built-in operation", ThreatLevelMedium},
	}

	for _, p := range freemarkerPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "FreeMarker SSTI: " + p.description,
				Recommendation: "Validate FreeMarker templates; restrict built-in operations",
			})
		}
	}

	a.analyzeFreeMarkerExploitation(data, result)
}

func (a *SSTIAnalyzer) analyzeFreeMarkerExploitation(data string, result *AnalysisResult) {
	exploitPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\$\{.*?\.class.*?\}`, "Java class introspection in FreeMarker", ThreatLevelCritical},
		{`\$\{.*?\.getClass.*?\}`, "Java getClass() in FreeMarker", ThreatLevelCritical},
		{`\$\{.*?\.forName.*?\}`, "Java Class.forName() in FreeMarker", ThreatLevelCritical},
		{`\$\{.*?\.getResource.*?\}`, "Java getResource() in FreeMarker", ThreatLevelCritical},
		{`\$\{.*?\.getDeclaredConstructor.*?\}`, "Java constructor access in FreeMarker", ThreatLevelCritical},
		{`\$\{.*?\.newInstance.*?\}`, "Java newInstance() in FreeMarker", ThreatLevelCritical},
		{`\$\{.*?\.getMethod.*?\}`, "Java method access in FreeMarker", ThreatLevelCritical},
		{`\$\{.*?\.invoke.*?\}`, "Java reflection invoke() in FreeMarker", ThreatLevelCritical},
		{`\$\{.*?\.getField.*?\}`, "Java field access in FreeMarker", ThreatLevelCritical},
		{`\$\{.*?\.getDeclaredField.*?\}`, "Java declared field access in FreeMarker", ThreatLevelCritical},
		{`\$\{.*?\.setAccessible.*?\}`, "Java setAccessible() bypass in FreeMarker", ThreatLevelCritical},
		{`\$\{.*?Runtime.*?\}`, "Java Runtime in FreeMarker", ThreatLevelCritical},
		{`\$\{.*?ProcessBuilder.*?\}`, "Java ProcessBuilder in FreeMarker", ThreatLevelCritical},
		{`\$\{.*?\.exec.*?\}`, "Java exec() in FreeMarker", ThreatLevelCritical},
		{`\$\{.*?\.eval.*?\}`, "FreeMarker eval() exploitation", ThreatLevelCritical},
		{`\$\{.*?\.getModel.*?\}`, "FreeMarker model access", ThreatLevelHigh},
		{`\$\{.*?\.api.*?\}`, "FreeMarker TemplateModel API exploitation", ThreatLevelCritical},
		{`\$\{.*?\.macro.*?\}`, "FreeMarker macro invocation", ThreatLevelHigh},
		{`\$\{.*?\.namespace.*?\}`, "FreeMarker namespace access", ThreatLevelHigh},
		{`\$\{.*?Session.*?\}`, "Servlet Session access in FreeMarker", ThreatLevelHigh},
		{`\$\{.*?application.*?\}`, "Servlet application scope in FreeMarker", ThreatLevelHigh},
		{`\$\{.*?request.*?\}`, "Servlet request access in FreeMarker", ThreatLevelHigh},
		{`\$\{.*?response.*?\}`, "Servlet response access in FreeMarker", ThreatLevelHigh},
		{`\$\{.*?_assert.*?\}`, "FreeMarker assertion exploitation", ThreatLevelHigh},
		{`\$\{msg.*?\}`, "FreeMarker message access", ThreatLevelMedium},
		{`\$\{vars.*?\}`, "FreeMarker vars access", ThreatLevelHigh},
		{`\$\{globals.*?\}`, "FreeMarker globals access", ThreatLevelHigh},
		{`\$\{ locals.*?\}`, "FreeMarker locals access", ThreatLevelMedium},
		{`\$\{.*?\}?web.*?\}`, "FreeMarker web API exploitation", ThreatLevelHigh},
		{`\$\{.*?\.getOutputStream.*?\}`, "Servlet output stream access", ThreatLevelCritical},
		{`\$\{.*?\.getWriter.*?\}`, "Servlet writer access", ThreatLevelCritical},
	}

	for _, p := range exploitPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "FreeMarker SSTI exploitation: " + p.description,
				Recommendation: "Block request; Java reflection and system calls must be blocked in templates",
			})
		}
	}
}

func (a *SSTIAnalyzer) analyzeOGNLTemplates(data string, result *AnalysisResult) {
	ognlPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\$\{.*?\}`, "OGNL expression", ThreatLevelMedium},
		{`%\{.*?\}`, "OGNL percent-encoded expression", ThreatLevelMedium},
		{`%\{@.*?\}`, "OGNL static method call", ThreatLevelHigh},
		{`%\{@.*?@.*?\}`, "OGNL static class method call", ThreatLevelHigh},
		{`%\{.*?\.\.\}`, "OGNL parent navigation", ThreatLevelMedium},
		{`%\{.*?\#.*?\}`, "OGNL variable access", ThreatLevelMedium},
		{`\$\{.*?\}`, "Struts2 OGNL expression", ThreatLevelMedium},
		{`\%\{.*?\}`, "Struts2 percent expression", ThreatLevelMedium},
		{`\#.*?=.*?`, "OGNL variable assignment", ThreatLevelMedium},
		{`\#.*?`, "OGNL variable reference", ThreatLevelMedium},
		{`@.*?@.*?`, "OGNL static operation", ThreatLevelHigh},
		{`\+\+.*?\+\+`, "OGNL increment/decrement", ThreatLevelMedium},
		{`new\s+.*?\(`, "OGNL object instantiation", ThreatLevelHigh},
	}

	for _, p := range ognlPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "OGNL SSTI: " + p.description,
				Recommendation: "Validate OGNL expressions; disable dangerous operations",
			})
		}
	}

	a.analyzeOGNLExploitation(data, result)
	a.analyzeStruts2Vulnerabilities(data, result)
}

func (a *SSTIAnalyzer) analyzeOGNLExploitation(data string, result *AnalysisResult) {
	exploitPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\#_memberAccess.*?=`, "OGNL MemberAccess bypass", ThreatLevelCritical},
		{`\#context.*?=`, "OGNL context access", ThreatLevelCritical},
		{`\#root.*?=`, "OGNL root access", ThreatLevelCritical},
		{`\#this.*?=`, "OGNL this reference", ThreatLevelCritical},
		{`@.*?@getClass\(\)`, "OGNL getClass() exploitation", ThreatLevelCritical},
		{`@.*?@forName\(`, "OGNL Class.forName() exploitation", ThreatLevelCritical},
		{`@.*?@getResource\(`, "OGNL getResource() exploitation", ThreatLevelCritical},
		{`@.*?@getDeclaredConstructor\(`, "OGNL constructor exploitation", ThreatLevelCritical},
		{`@.*?@newInstance\(`, "OGNL newInstance() exploitation", ThreatLevelCritical},
		{`@.*?@getMethod\(`, "OGNL getMethod() exploitation", ThreatLevelCritical},
		{`@.*?@invoke\(`, "OGNL invoke() exploitation", ThreatLevelCritical},
		{`@.*?Runtime@getRuntime\(\)`, "OGNL Runtime.getRuntime() exploitation", ThreatLevelCritical},
		{`@.*?Runtime@exec\(`, "OGNL Runtime.exec() exploitation", ThreatLevelCritical},
		{`@.*?ProcessBuilder@new`, "OGNL ProcessBuilder exploitation", ThreatLevelCritical},
		{`#.*?\.exec\(`, "OGNL exec() call", ThreatLevelCritical},
		{`#.*?\.eval\(`, "OGNL eval() call", ThreatLevelCritical},
		{`#.*?\.execute\(`, "OGNL execute() call", ThreatLevelCritical},
		{`#.*?\.process\(`, "OGNL process() call", ThreatLevelCritical},
		{`#.*?\.start\(`, "OGNL start() call", ThreatLevelCritical},
		{`new\s+java\.lang\.ProcessBuilder`, "OGNL ProcessBuilder creation", ThreatLevelCritical},
		{`new\s+java\.lang\.Runtime`, "OGNL Runtime creation", ThreatLevelCritical},
		{`@java\.lang\.System@exit`, "OGNL System.exit() call", ThreatLevelCritical},
		{`@java\.lang\.Thread@sleep`, "OGNL Thread.sleep() DoS", ThreatLevelHigh},
		{`@java\.lang\.ClassLoader@`, "OGNL ClassLoader manipulation", ThreatLevelCritical},
		{`#_memberAccess\[.*?\]`, "OGNL MemberAccess index access", ThreatLevelCritical},
		{`#parameters.*?=`, "Struts2 parameters access", ThreatLevelHigh},
		{`#request.*?=`, "Struts2 request access", ThreatLevelHigh},
		{`#session.*?=`, "Struts2 session access", ThreatLevelHigh},
		{`#application.*?=`, "Struts2 application access", ThreatLevelHigh},
		{`#attr.*?=`, "Struts2 attr access", ThreatLevelHigh},
		{`\(\(#.*?\)\).*?\)`, "OGNL nested expression with variable", ThreatLevelCritical},
		{`#.*?\[.*?\]`, "OGNL index access", ThreatLevelMedium},
	}

	for _, p := range exploitPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "OGNL SSTI exploitation: " + p.description,
				Recommendation: "Block request; OGNL expressions allowing system access must be blocked",
			})
		}
	}
}

func (a *SSTIAnalyzer) analyzeStruts2Vulnerabilities(data string, result *AnalysisResult) {
	struts2Patterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\#_memberAccess\[.*?\'.*?\'.*?\]`, "Struts2 MemberAccess bypass (S2-001 style)", ThreatLevelCritical},
		{`\(\'\#.*?\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\.\#.*?#\}`, "Struts2 tag in expression", ThreatLevelMedium},
		{`\{\{.*?\}\}.*?\{\{`, "Multiple template expressions (possible chaining)", ThreatLevelMedium},
		{`\{\{.*?\}\}.*?\}\}`, "Mismatched template braces", ThreatLevelLow},
		{`\{#.*?\}\}`, "Comment in expression context", ThreatLevelLow},
		{`\$:.*?\}`, "Dollar sign followed by colon", ThreatLevelLow},
	}

	for _, p := range struts2Patterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Struts2 SSTI vulnerability: " + p.description,
				Recommendation: "Block request; known Struts2 exploitation pattern detected",
			})
		}
	}
}

func (a *SSTIAnalyzer) analyzeTemplateSelfExploitation(data string, result *AnalysisResult) {
	selfPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`_template_self_`, "Template self-reference exploitation", ThreatLevelCritical},
		{`_self_`, "Template self reference", ThreatLevelCritical},
		{`_template_`, "Template reference", ThreatLevelCritical},
		{`__init__`, "Python __init__ in template", ThreatLevelCritical},
		{`__main__`, "Python __main__ in template", ThreatLevelCritical},
		{`__globals__`, "Python globals in template", ThreatLevelCritical},
		{`__builtins__`, "Python builtins in template", ThreatLevelCritical},
		{`__class__`, "Python class introspection in template", ThreatLevelCritical},
		{`__mro__`, "Python MRO in template", ThreatLevelCritical},
		{`__subclasses__`, "Python subclasses in template", ThreatLevelCritical},
		{`__bases__`, "Python bases in template", ThreatLevelCritical},
		{`__name__`, "Python name in template", ThreatLevelCritical},
		{`__doc__`, "Python docstring in template", ThreatLevelMedium},
		{`__file__`, "Python file path in template", ThreatLevelHigh},
		{`__path__`, "Python path in template", ThreatLevelHigh},
		{`__package__`, "Python package in template", ThreatLevelMedium},
		{`__loader__`, "Python loader in template", ThreatLevelHigh},
		{`__spec__`, "Python spec in template", ThreatLevelHigh},
		{`__closure__`, "Python closure in template", ThreatLevelHigh},
		{`__code__`, "Python code object in template", ThreatLevelCritical},
		{`__defaults__`, "Python defaults in template", ThreatLevelMedium},
		{`__kwdefaults__`, "Python kwdefaults in template", ThreatLevelMedium},
		{`__globals__\[`, "Python globals index access", ThreatLevelCritical},
		{`__class__\.__mro__`, "Python class MRO chain", ThreatLevelCritical},
		{`__class__\.__bases__`, "Python class bases", ThreatLevelCritical},
		{`__class__\.__subclasses__`, "Python class subclasses", ThreatLevelCritical},
		{`\.__init__\.__globals__`, "Python init globals", ThreatLevelCritical},
		{`\.__init__\.__code__`, "Python init code", ThreatLevelCritical},
		{`request\.__class__`, "Request class access", ThreatLevelCritical},
		{`application\.__class__`, "Application class access", ThreatLevelCritical},
		{`session\.__class__`, "Session class access", ThreatLevelHigh},
		{`config\.__class__`, "Config class access", ThreatLevelHigh},
		{`class\.__subclasses__`, "Class subclasses exploitation", ThreatLevelCritical},
		{`class\.__bases__`, "Class bases exploitation", ThreatLevelCritical},
		{`class\.__mro__`, "Class MRO exploitation", ThreatLevelCritical},
		{`object\.__subclasses__`, "Object subclasses exploitation", ThreatLevelCritical},
		{`object\.__new__`, "Object new exploitation", ThreatLevelCritical},
		{`type\.__new__`, "Type new exploitation", ThreatLevelCritical},
		{`type\.__mro__`, "Type MRO exploitation", ThreatLevelCritical},
		{`getattr\(`, "Python getattr in template", ThreatLevelCritical},
		{`setattr\(`, "Python setattr in template", ThreatLevelCritical},
		{`delattr\(`, "Python delattr in template", ThreatLevelCritical},
		{`hasattr\(`, "Python hasattr in template", ThreatLevelMedium},
		{`vars\(`, "Python vars in template", ThreatLevelHigh},
		{`dir\(`, "Python dir in template", ThreatLevelMedium},
		{`help\(`, "Python help in template", ThreatLevelMedium},
		{`repr\(`, "Python repr in template", ThreatLevelLow},
		{`open\(`, "Python open() in template", ThreatLevelCritical},
		{`compile\(`, "Python compile() in template", ThreatLevelCritical},
		{`eval\(`, "Python eval() in template", ThreatLevelCritical},
		{`exec\(`, "Python exec() in template", ThreatLevelCritical},
		{`input\(`, "Python input() in template", ThreatLevelCritical},
		{`reload\(`, "Python reload() in template", ThreatLevelHigh},
		{`importlib\.`, "Python importlib in template", ThreatLevelCritical},
		{`__import__`, "Python __import__ in template", ThreatLevelCritical},
	}

	for _, p := range selfPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Template self/execution exploitation: " + p.description,
				Recommendation: "Block request; dangerous introspection patterns detected",
			})
		}
	}
}

func (a *SSTIAnalyzer) analyzeTemplateExecutionPatterns(data string, result *AnalysisResult) {
	executionPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\{\{.*?\}\}.*?exec.*?\(`, "Template with exec() call", ThreatLevelCritical},
		{`\{\{.*?\}\}.*?eval.*?\(`, "Template with eval() call", ThreatLevelCritical},
		{`\{\{.*?\}\}.*?system.*?\(`, "Template with system() call", ThreatLevelCritical},
		{`\{\{.*?\}\}.*?shell_exec.*?\(`, "Template with shell_exec() call", ThreatLevelCritical},
		{`\{\{.*?\}\}.*?passthru.*?\(`, "Template with passthru() call", ThreatLevelCritical},
		{`\{\{.*?\}\}.*?popen.*?\(`, "Template with popen() call", ThreatLevelHigh},
		{`\{\{.*?\}\}.*?proc_open.*?\(`, "Template with proc_open() call", ThreatLevelHigh},
		{`\{\{.*?\}\}.*?Runtime.*?\.exec`, "Template with Runtime.exec()", ThreatLevelCritical},
		{`\{\{.*?\}\}.*?ProcessBuilder.*?\(`, "Template with ProcessBuilder()", ThreatLevelCritical},
		{`\{\{.*?\}\}.*?Class\.forName`, "Template with Class.forName()", ThreatLevelCritical},
		{`\{\{.*?\}\}.*?ClassLoader\.loadClass`, "Template with ClassLoader.loadClass()", ThreatLevelCritical},
		{`\{\{.*?\}\}.*?Method\.invoke`, "Template with Method.invoke()", ThreatLevelCritical},
		{`\{\{.*?\}\}.*?Constructor\.newInstance`, "Template with Constructor.newInstance()", ThreatLevelCritical},
		{`\{\{.*?\}\}.*?AccessibleObject\.setAccessible`, "Template with setAccessible() bypass", ThreatLevelCritical},
		{`\{\{.*?\}\}.*?file_get_contents`, "Template with file_get_contents()", ThreatLevelHigh},
		{`\{\{.*?\}\}.*?fopen`, "Template with fopen()", ThreatLevelHigh},
		{`\{\{.*?\}\}.*?fread`, "Template with fread()", ThreatLevelHigh},
		{`\{\{.*?\}\}.*?file_put_contents`, "Template with file_put_contents()", ThreatLevelCritical},
		{`\{\{.*?\}\}.*?copy`, "Template with copy()", ThreatLevelHigh},
		{`\{\{.*?\}\}.*?unlink`, "Template with unlink()", ThreatLevelHigh},
		{`\{\{.*?\}\}.*?rmdir`, "Template with rmdir()", ThreatLevelHigh},
		{`\{\{.*?\}\}.*?mkdir`, "Template with mkdir()", ThreatLevelMedium},
		{`\{\{.*?\}\}.*?chmod`, "Template with chmod()", ThreatLevelHigh},
		{`\{\{.*?\}\}.*?chown`, "Template with chown()", ThreatLevelHigh},
		{`\{\{.*?\}\}.*?symlink`, "Template with symlink()", ThreatLevelHigh},
		{`\{\{.*?\}\}.*?readlink`, "Template with readlink()", ThreatLevelMedium},
		{`\{\{.*?\}\}.*?include.*?\)`, "Template with include()", ThreatLevelCritical},
		{`\{\{.*?\}\}.*?require.*?\)`, "Template with require()", ThreatLevelCritical},
		{`\{\{.*?\}\}.*?include_once.*?\)`, "Template with include_once()", ThreatLevelHigh},
		{`\{\{.*?\}\}.*?require_once.*?\)`, "Template with require_once()", ThreatLevelHigh},
		{`\{\{.*?\}\}.*?curl_exec`, "Template with curl_exec()", ThreatLevelHigh},
		{`\{\{.*?\}\}.*?curl_setopt`, "Template with curl_setopt()", ThreatLevelHigh},
		{`\{\{.*?\}\}.*?fsockopen`, "Template with fsockopen()", ThreatLevelHigh},
		{`\{\{.*?\}\}.*?stream_socket_client`, "Template with stream_socket_client()", ThreatLevelHigh},
		{`\{\{.*?\}\}.*?socket_connect`, "Template with socket_connect()", ThreatLevelHigh},
		{`\{\{.*?\}\}.*?header.*?\(`, "Template with header() manipulation", ThreatLevelHigh},
		{`\{\{.*?\}\}.*?setcookie.*?\(`, "Template with setcookie() manipulation", ThreatLevelMedium},
		{`\{\{.*?\}\}.*?session_.*?\(`, "Template with session manipulation", ThreatLevelMedium},
		{`\{\{.*?\}\}.*?ini_set.*?\(`, "Template with ini_set()", ThreatLevelCritical},
		{`\{\{.*?\}\}.*?ini_alter.*?\(`, "Template with ini_alter()", ThreatLevelCritical},
		{`\{\{.*?\}\}.*?putenv.*?\(`, "Template with putenv()", ThreatLevelHigh},
		{`\{\{.*?\}\}.*?mail.*?\(`, "Template with mail()", ThreatLevelHigh},
		{`\{\{.*?\}\}.*?header_remove.*?\(`, "Template with header_remove()", ThreatLevelMedium},
		{`\{\{.*?\}\}.*?ob_start.*?\(`, "Template with ob_start()", ThreatLevelMedium},
		{`\{\{.*?\}\}.*?assert.*?\(`, "Template with assert()", ThreatLevelCritical},
		{`\{\{.*?\}\}.*?preg_replace.*?\(.*?e`, "Template with preg_replace /e modifier", ThreatLevelCritical},
		{`\{\{.*?\}\}.*?create_function.*?\(`, "Template with create_function()", ThreatLevelCritical},
		{`\{\{.*?\}\}.*?call_user_func.*?\(`, "Template with call_user_func()", ThreatLevelHigh},
		{`\{\{.*?\}\}.*?call_user_func_array.*?\(`, "Template with call_user_func_array()", ThreatLevelHigh},
		{`\{\{.*?\}\}.*?array_map.*?\(`, "Template with array_map()", ThreatLevelHigh},
		{`\{\{.*?\}\}.*?array_filter.*?\(`, "Template with array_filter()", ThreatLevelMedium},
		{`\{\{.*?\}\}.*?array_reduce.*?\(`, "Template with array_reduce()", ThreatLevelMedium},
		{`\{\{.*?\}\}.*?usort.*?\(`, "Template with usort()", ThreatLevelHigh},
		{`\{\{.*?\}\}.*?uasort.*?\(`, "Template with uasort()", ThreatLevelHigh},
		{`\{\{.*?\}\}.*?uksort.*?\(`, "Template with uksort()", ThreatLevelHigh},
		{`\{\{.*?\}\}.*?spl_autoload.*?\(`, "Template with spl_autoload()", ThreatLevelMedium},
	}

	for _, p := range executionPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Template execution exploitation: " + p.description,
				Recommendation: "Block request; dangerous function calls in template context",
			})
		}
	}
}

func (a *SSTIAnalyzer) analyzeAngularExpressions(data string, result *AnalysisResult) {
	angularPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\{\{.*?\}\}`, "Angular expression", ThreatLevelMedium},
		{`\(\(.*?\)\)`, "Angular double curly braces alternative", ThreatLevelMedium},
		{`\{\{.*?\|.*?\}\}`, "Angular expression with filter", ThreatLevelMedium},
		{`\{\{.*?\}\}.*?\{\{.*?\}\}`, "Multiple Angular expressions", ThreatLevelMedium},
		{`ng-app`, "Angular ng-app directive", ThreatLevelMedium},
		{`ng-controller`, "Angular ng-controller directive", ThreatLevelMedium},
		{`ng-bind`, "Angular ng-bind directive", ThreatLevelMedium},
		{`ng-model`, "Angular ng-model directive", ThreatLevelMedium},
		{`ng-init`, "Angular ng-init directive", ThreatLevelHigh},
		{`ng-click`, "Angular ng-click event binding", ThreatLevelMedium},
		{`ng-change`, "Angular ng-change event binding", ThreatLevelMedium},
		{`ng-submit`, "Angular ng-submit event binding", ThreatLevelMedium},
		{`ng-repeat`, "Angular ng-repeat directive", ThreatLevelLow},
		{`ng-show`, "Angular ng-show directive", ThreatLevelLow},
		{`ng-hide`, "Angular ng-hide directive", ThreatLevelLow},
		{`ng-if`, "Angular ng-if directive", ThreatLevelLow},
		{`ng-switch`, "Angular ng-switch directive", ThreatLevelLow},
		{`ng-include`, "Angular ng-include directive", ThreatLevelHigh},
		{`ng-view`, "Angular ng-view directive", ThreatLevelMedium},
		{`ng-transclude`, "Angular ng-transclude directive", ThreatLevelMedium},
		{`ng-template`, "Angular ng-template directive", ThreatLevelMedium},
		{`ng-form`, "Angular ng-form directive", ThreatLevelLow},
		{`ng-class`, "Angular ng-class directive", ThreatLevelLow},
		{`ng-style`, "Angular ng-style directive", ThreatLevelLow},
		{`ng-disabled`, "Angular ng-disabled directive", ThreatLevelLow},
		{`ng-readonly`, "Angular ng-readonly directive", ThreatLevelLow},
		{`ng-selected`, "Angular ng-selected directive", ThreatLevelLow},
		{`ng-href`, "Angular ng-href directive", ThreatLevelLow},
		{`ng-src`, "Angular ng-src directive", ThreatLevelLow},
		{`ng-sref`, "Angular ng-sref directive", ThreatLevelLow},
		{`\$event`, "Angular $event object", ThreatLevelMedium},
		{`\$scope`, "Angular $scope object", ThreatLevelMedium},
		{`\$rootScope`, "Angular $rootScope object", ThreatLevelHigh},
		{`\$index`, "Angular $index in ng-repeat", ThreatLevelLow},
		{`\$value`, "Angular $value object", ThreatLevelMedium},
		{`\$ctrl`, "Angular $ctrl controller reference", ThreatLevelMedium},
		{`\$resolve`, "Angular $resolve object", ThreatLevelMedium},
		{`\$state`, "Angular UI-Router $state", ThreatLevelMedium},
		{`\$transition\$`, "Angular $transition$ service", ThreatLevelMedium},
		{`\$http`, "Angular $http service", ThreatLevelHigh},
		{`\$resource`, "Angular $resource service", ThreatLevelHigh},
		{`\$window`, "Angular $window object", ThreatLevelMedium},
		{`\$document`, "Angular $document object", ThreatLevelMedium},
		{`\$location`, "Angular $location service", ThreatLevelMedium},
		{`\$cookies`, "Angular $cookies service", ThreatLevelMedium},
		{`\$cookieStore`, "Angular $cookieStore service", ThreatLevelMedium},
		{`\$cacheFactory`, "Angular $cacheFactory service", ThreatLevelLow},
		{`\$interpolate`, "Angular $interpolate service", ThreatLevelHigh},
		{`\$parse`, "Angular $parse service", ThreatLevelHigh},
		{`\$compile`, "Angular $compile service", ThreatLevelCritical},
		{`\$eval`, "Angular $eval() method", ThreatLevelHigh},
		{`\$evalAsync`, "Angular $evalAsync() method", ThreatLevelHigh},
		{`\$watch`, "Angular $watch() method", ThreatLevelMedium},
		{`\$watchGroup`, "Angular $watchGroup() method", ThreatLevelMedium},
		{`\$watchCollection`, "Angular $watchCollection() method", ThreatLevelMedium},
		{`\$destroy`, "Angular $destroy event", ThreatLevelMedium},
		{`\$emit`, "Angular $emit event", ThreatLevelMedium},
		{`\$broadcast`, "Angular $broadcast event", ThreatLevelMedium},
		{`\$on`, "Angular $on event handler", ThreatLevelLow},
		{`\$apply`, "Angular $apply() method", ThreatLevelMedium},
		{`\$digest`, "Angular $digest() method", ThreatLevelMedium},
		{`toString\.call`, "JavaScript toString.call() exploitation", ThreatLevelCritical},
		{`constructor\.constructor`, "JavaScript constructor.constructor exploitation", ThreatLevelCritical},
		{`\[native code\]`, "JavaScript native code reference", ThreatLevelHigh},
		{`return.*?ifer.*?er`, "JavaScript return toString exploit", ThreatLevelHigh},
	}

	for _, p := range angularPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Angular/SPA SSTI: " + p.description,
				Recommendation: "Validate Angular expressions; avoid unsafe use of $compile or $interpolate",
			})
		}
	}
}

func (a *SSTIAnalyzer) analyzeVelocityTemplates(data string, result *AnalysisResult) {
	velocityPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\$\{.*?\}`, "Velocity variable expression", ThreatLevelMedium},
		{`\$!.*`, "Velocity silent reference", ThreatLevelMedium},
		{`#set\(.*?\)`, "Velocity #set directive", ThreatLevelLow},
		{`#if\(.*?\)`, "Velocity #if directive", ThreatLevelLow},
		{`#elseif\(.*?\)`, "Velocity #elseif directive", ThreatLevelLow},
		{`#else`, "Velocity #else directive", ThreatLevelLow},
		{`#end`, "Velocity #end directive", ThreatLevelLow},
		{`#foreach\(.*?in.*?\)`, "Velocity #foreach loop", ThreatLevelLow},
		{`#break`, "Velocity #break directive", ThreatLevelLow},
		{`#stop`, "Velocity #stop directive", ThreatLevelMedium},
		{`#include\(.*?\)`, "Velocity #include directive", ThreatLevelHigh},
		{`#parse\(.*?\)`, "Velocity #parse directive", ThreatLevelHigh},
		{`#macro\(.*?\)`, "Velocity #macro definition", ThreatLevelLow},
		{`#end`, "Velocity macro end", ThreatLevelLow},
		{`#define\(.*?\)`, "Velocity #define directive", ThreatLevelLow},
		{`#evaluate\(.*?\)`, "Velocity #evaluate (dynamic evaluation)", ThreatLevelCritical},
		{`#@.*`, "Velocity user directive", ThreatLevelMedium},
		{`\$velocityCount`, "Velocity count variable", ThreatLevelLow},
		{`\$velocityHasNext`, "Velocity hasNext variable", ThreatLevelLow},
		{`\$class`, "Velocity class reference", ThreatLevelCritical},
		{`\$system`, "Velocity system reference", ThreatLevelCritical},
		{`\$runtime`, "Velocity runtime reference", ThreatLevelCritical},
		{`\$doMethod`, "Velocity method reference", ThreatLevelHigh},
		{`\$lang`, "Velocity lang reference", ThreatLevelMedium},
	}

	for _, p := range velocityPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Velocity SSTI: " + p.description,
				Recommendation: "Validate Velocity templates; disable dangerous directives",
			})
		}
	}
}

func (a *SSTIAnalyzer) analyzeSmartyTemplates(data string, result *AnalysisResult) {
	smartyPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\{.*?\}`, "Smarty template expression", ThreatLevelMedium},
		{`\{literal\}`, "Smarty literal block", ThreatLevelMedium},
		{`\{/literal\}`, "Smarty literal end", ThreatLevelMedium},
		{`\{ldelim\}`, "Smarty left delimiter", ThreatLevelLow},
		{`\{rdelim\}`, "Smarty right delimiter", ThreatLevelLow},
		{`\{\$.*?\}`, "Smarty variable reference", ThreatLevelMedium},
		{`\{assign.*?\}`, "Smarty assign directive", ThreatLevelLow},
		{`\{append.*?\}`, "Smarty append directive", ThreatLevelLow},
		{`\{if.*?\}`, "Smarty if directive", ThreatLevelLow},
		{`\{elseif.*?\}`, "Smarty elseif directive", ThreatLevelLow},
		{`\{else\}`, "Smarty else directive", ThreatLevelLow},
		{`\{/if\}`, "Smarty if end", ThreatLevelLow},
		{`\{foreach.*?\}`, "Smarty foreach directive", ThreatLevelLow},
		{`\{/foreach\}`, "Smarty foreach end", ThreatLevelLow},
		{`\{section.*?\}`, "Smarty section directive", ThreatLevelLow},
		{`\{/section\}`, "Smarty section end", ThreatLevelLow},
		{`\{capture.*?\}`, "Smarty capture directive", ThreatLevelLow},
		{`\{/capture\}`, "Smarty capture end", ThreatLevelLow},
		{`\{include.*?\}`, "Smarty include directive", ThreatLevelHigh},
		{`\{insert.*?\}`, "Smarty insert directive", ThreatLevelHigh},
		{`\{block.*?\}`, "Smarty block directive", ThreatLevelLow},
		{`\{/block\}`, "Smarty block end", ThreatLevelLow},
		{`\{function.*?\}`, "Smarty function directive", ThreatLevelLow},
		{`\{/function\}`, "Smarty function end", ThreatLevelLow},
		{`\{call.*?\}`, "Smarty call directive", ThreatLevelMedium},
		{`\{config_load.*?\}`, "Smarty config_load directive", ThreatLevelMedium},
		{`\{fetch.*?\}`, "Smarty fetch directive", ThreatLevelHigh},
		{`\{textformat.*?\}`, "Smarty textformat filter", ThreatLevelLow},
		{`\{strip\}`, "Smarty strip tag", ThreatLevelLow},
		{`\{/strip\}`, "Smarty strip end", ThreatLevelLow},
		{`\{nocache\}`, "Smarty nocache tag", ThreatLevelLow},
		{`\{/nocache\}`, "Smarty nocache end", ThreatLevelLow},
		{`\{[*].*?[*]\}`, "Smarty comment", ThreatLevelLow},
		{`\{\$smarty[.]`, "Smarty special variable", ThreatLevelMedium},
		{`\{\$smarty[.]template\}`, "Smarty template name", ThreatLevelLow},
		{`\{\$smarty[.]version\}`, "Smarty version", ThreatLevelLow},
		{`\{\$smarty[.]now\}`, "Smarty timestamp", ThreatLevelLow},
		{`\{\$smarty[.]ldelim\}`, "Smarty left delimiter", ThreatLevelLow},
		{`\{\$smarty[.]rdelim\}`, "Smarty right delimiter", ThreatLevelLow},
		{`\{\$smarty[.]capture\}`, "Smarty capture variable", ThreatLevelLow},
		{`\{\$smarty[.]get\}`, "Smarty GET variable", ThreatLevelMedium},
		{`\{\$smarty[.]post\}`, "Smarty POST variable", ThreatLevelMedium},
		{`\{\$smarty[.]cookies\}`, "Smarty cookies variable", ThreatLevelMedium},
		{`\{\$smarty[.]server\}`, "Smarty server variable", ThreatLevelMedium},
		{`\{\$smarty[.]session\}`, "Smarty session variable", ThreatLevelMedium},
		{`\{\$smarty[.]request\}`, "Smarty request variable", ThreatLevelMedium},
		{`\{\$smarty[.]config\}`, "Smarty config variable", ThreatLevelLow},
		{`\{\$smarty[.]const\}`, "Smarty const variable", ThreatLevelLow},
		{`\{\$smarty[.]tpl_vars\}`, "Smarty template variables", ThreatLevelLow},
		{`\{html_options.*?\}`, "Smarty html_options function", ThreatLevelLow},
		{`\{html_select_date.*?\}`, "Smarty date selection", ThreatLevelLow},
		{`\{html_select_time.*?\}`, "Smarty time selection", ThreatLevelLow},
		{`\{html_checkboxes.*?\}`, "Smarty checkbox selection", ThreatLevelLow},
		{`\{html_radios.*?\}`, "Smarty radio selection", ThreatLevelLow},
		{`\{html_table.*?\}`, "Smarty table generation", ThreatLevelLow},
		{`\{cycle.*?\}`, "Smarty cycle function", ThreatLevelLow},
		{`\{mailto.*?\}`, "Smarty mailto function", ThreatLevelMedium},
		{`\{url_encode.*?\}`, "Smarty URL encode", ThreatLevelLow},
		{`\{literal\}`, "Smarty literal block", ThreatLevelMedium},
	}

	for _, p := range smartyPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Smarty SSTI: " + p.description,
				Recommendation: "Validate Smarty templates; disable dangerous functions",
			})
		}
	}
}

func (a *SSTIAnalyzer) analyzeHandlebarsTemplates(data string, result *AnalysisResult) {
	handlebarsPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\{.*?\}`, "Handlebars expression", ThreatLevelMedium},
		{`\{\{.*?\}\}`, "Handlebars double-brace expression", ThreatLevelMedium},
		{`\{\{#.*?\}\}`, "Handlebars block helper", ThreatLevelMedium},
		{`\{\{else\}\}`, "Handlebars else branch", ThreatLevelLow},
		{`\{\{\/.*?\}\}`, "Handlebars closing block", ThreatLevelLow},
		{`\{\{!.*?\}\}`, "Handlebars comment", ThreatLevelLow},
		{`\{\{\{.*?\}\}\}`, "Handlebars triple-brace (unescaped)", ThreatLevelHigh},
		{`\{\{>\s*.*?\}\}`, "Handlebars partial", ThreatLevelMedium},
		{`\{\{#each.*?\}\}`, "Handlebars each loop", ThreatLevelLow},
		{`\{\{#if.*?\}\}`, "Handlebars if conditional", ThreatLevelLow},
		{`\{\{#unless.*?\}\}`, "Handlebars unless conditional", ThreatLevelLow},
		{`\{\{#with.*?\}\}`, "Handlebars with context", ThreatLevelLow},
		{`\{\{#let.*?\}\}`, "Handlebars let (newer versions)", ThreatLevelLow},
		{`\{\{#for.*?\}\}`, "Handlebars for loop (newer versions)", ThreatLevelLow},
		{`\{\{#lookup.*?\}\}`, "Handlebars lookup helper", ThreatLevelMedium},
		{`\{\{#log.*?\}\}`, "Handlebars log helper", ThreatLevelMedium},
		{`\{\{#block.*?\}\}`, "Handlebars block", ThreatLevelLow},
		{`\{\{#partial.*?\}\}`, "Handlebars partial definition", ThreatLevelMedium},
		{`\{\{#embed.*?\}\}`, "Handlebars embed (partial with block)", ThreatLevelHigh},
		{`\{\{#data.*?\}\}`, "Handlebars data access", ThreatLevelLow},
		{`\{\{@index\}\}`, "Handlebars index in loop", ThreatLevelLow},
		{`\{\{@key\}\}`, "Handlebars key in object iteration", ThreatLevelLow},
		{`\{\{@first\}\}`, "Handlebars first item check", ThreatLevelLow},
		{`\{\{@last\}\}`, "Handlebars last item check", ThreatLevelLow},
		{`\{\{@root\}\}`, "Handlebars root context", ThreatLevelMedium},
		{`\{\{@partial-block\}\}`, "Handlebars partial block", ThreatLevelMedium},
		{`\{\{+\s*.*?\s*\}\}`, "Handlebars whitespace control", ThreatLevelLow},
		{`\{\{-\s*.*?\s*-\}\}`, "Handlebars standalone whitespace control", ThreatLevelLow},
		{`\{helperName\}`, "Handlebars helper invocation", ThreatLevelMedium},
		{`\{\{helperName.*?\}\}`, "Handlebars helper with args", ThreatLevelMedium},
		{`\{\{#if\}\}.*?\{\{else\}\}.*?\{\{\/if\}\}`, "Handlebars if-else block", ThreatLevelLow},
	}

	for _, p := range handlebarsPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Handlebars SSTI: " + p.description,
				Recommendation: "Validate Handlebars templates; avoid unsafe helpers",
			})
		}
	}
}
