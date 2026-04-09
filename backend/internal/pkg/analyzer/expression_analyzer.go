package analyzer

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

type ExpressionAnalyzer struct {
	name         string
	version      string
	analyzerType string
	enabled      bool
	config       map[string]interface{}
	mu           sync.RWMutex
}

func NewExpressionAnalyzer() *ExpressionAnalyzer {
	return &ExpressionAnalyzer{
		name:         "expression_analyzer",
		version:      "1.0.0",
		analyzerType: "expression_injection",
		enabled:      true,
		config:       make(map[string]interface{}),
	}
}

func (a *ExpressionAnalyzer) Name() string {
	return a.name
}

func (a *ExpressionAnalyzer) Type() string {
	return a.analyzerType
}

func (a *ExpressionAnalyzer) Version() string {
	return a.version
}

func (a *ExpressionAnalyzer) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

func (a *ExpressionAnalyzer) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

func (a *ExpressionAnalyzer) Configure(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = config
	return nil
}

func (a *ExpressionAnalyzer) Analyze(input *AnalysisInput) *AnalysisResult {
	start := time.Now()
	result := NewAnalysisResult(a)

	if input == nil || input.Raw == "" {
		return result
	}

	dataToAnalyze := a.prepareData(input)

	a.analyzeJNDInjection(dataToAnalyze, result)
	a.analyzeELExpressions(dataToAnalyze, result)
	a.analyzeSpELExpressions(dataToAnalyze, result)
	a.analyzeLog4jVulnerabilities(dataToAnalyze, result)
	a.analyzeSpringFrameworkVulnerabilities(dataToAnalyze, result)
	a.analyzeStruts2OGNL(dataToAnalyze, result)
	a.analyzeMVELExpressions(dataToAnalyze, result)
	a.analyzeJBossELExpressions(dataToAnalyze, result)
	a.analyzeExpressionLanguageInjection(dataToAnalyze, result)

	result.ProcessingTime = time.Since(start)
	result.ShouldBlock = result.ShouldBlockRequest(0.6)
	if len(result.Matches) > 0 {
		result.ShouldLog = true
		result.ShouldAllow = !result.ShouldBlock
	}

	return result
}

func (a *ExpressionAnalyzer) prepareData(input *AnalysisInput) string {
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

func (a *ExpressionAnalyzer) analyzeJNDInjection(data string, result *AnalysisResult) {
	jndiPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)jndi:`, "JNDI protocol reference", ThreatLevelCritical},
		{`(?i)jndi:/`, "JNDI protocol with path", ThreatLevelCritical},
		{`(?i)jndi:ldap:`, "JNDI LDAP reference", ThreatLevelCritical},
		{`(?i)jndi:rmi:`, "JNDI RMI reference", ThreatLevelCritical},
		{`(?i)jndi:dns:`, "JNDI DNS reference", ThreatLevelCritical},
		{`(?i)jndi:iiop:`, "JNDI IIOP reference", ThreatLevelCritical},
		{`(?i)jndi:corba:`, "JNDI CORBA reference", ThreatLevelCritical},
		{`(?i)ldap://`, "LDAP protocol reference", ThreatLevelHigh},
		{`(?i)ldaps://`, "LDAPS secure LDAP reference", ThreatLevelHigh},
		{`(?i)rmi://`, "RMI protocol reference", ThreatLevelCritical},
		{`(?i)rmi:/`, "RMI protocol alternative", ThreatLevelCritical},
		{`(?i)dns://`, "DNS protocol reference", ThreatLevelMedium},
		{`(?i)iiop://`, "IIOP protocol reference", ThreatLevelHigh},
		{`(?i)corba://`, "CORBA protocol reference", ThreatLevelHigh},
		{`(?i)\$\{jndi:`, "JNDI in property placeholder", ThreatLevelCritical},
		{`(?i)\$\{env:`, "Environment variable in property", ThreatLevelMedium},
		{`(?i)\$\{sys:`, "System property in placeholder", ThreatLevelMedium},
		{`(?i)\$\{ctx:`, "JNDI ctx lookup", ThreatLevelCritical},
		{`(?i)lookup\s*\(\s*["']`, "JNDI lookup call", ThreatLevelCritical},
		{`(?i)InitialContext`, "JNDI InitialContext", ThreatLevelHigh},
		{`(?i)new\s+InitialContext`, "JNDI InitialContext creation", ThreatLevelCritical},
		{`(?i)Context\.PROVIDER_URL`, "JNDI Provider URL", ThreatLevelHigh},
		{`(?i)Context\.SECURITY_AUTHENTICATION`, "JNDI Security Auth", ThreatLevelHigh},
		{`(?i)Context\.SECURITY_CREDENTIALS`, "JNDI Security Credentials", ThreatLevelHigh},
		{`(?i)Context\.SECURITY_PRINCIPAL`, "JNDI Security Principal", ThreatLevelHigh},
		{`(?i)InitialDirContext`, "JNDI InitialDirContext", ThreatLevelHigh},
		{`(?i)LdapCtx`, "JNDI LDAP Context", ThreatLevelHigh},
		{`(?i)RmiCtx`, "JNDI RMI Context", ThreatLevelHigh},
		{`(?i)Registry`, "Java Registry reference", ThreatLevelHigh},
		{`(?i)LocateRegistry`, "RMI Registry location", ThreatLevelHigh},
		{`(?i)getRegistry`, "RMI getRegistry call", ThreatLevelHigh},
	}

	for _, p := range jndiPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "JNDI Injection: " + p.description,
				Recommendation: "Block JNDI references in user input; validate protocol usage",
			})
		}
	}

	a.analyzeJNDIVulnerabilityExploitation(data, result)
}

func (a *ExpressionAnalyzer) analyzeJNDIVulnerabilityExploitation(data string, result *AnalysisResult) {
	exploitPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\$\{jndi:ldap://.*\}`, "JNDI LDAP injection via property", ThreatLevelCritical},
		{`\$\{jndi:rmi://.*\}`, "JNDI RMI injection via property", ThreatLevelCritical},
		{`\$\{jndi:dns://.*\}`, "JNDI DNS injection via property", ThreatLevelCritical},
		{`\$\{jndi:iiop://.*\}`, "JNDI IIOP injection via property", ThreatLevelCritical},
		{`\$\{lower:.*jndi:.*\}`, "JNDI injection with case manipulation", ThreatLevelCritical},
		{`\$\{upper:.*jndi:.*\}`, "JNDI injection with case manipulation", ThreatLevelCritical},
		{`\$\{::-jndi:.*\}`, "JNDI injection with empty prefix bypass", ThreatLevelCritical},
		{`\$\{::-ldap:.*\}`, "JNDI LDAP injection with bypass", ThreatLevelCritical},
		{`\$\{::-rmi:.*\}`, "JNDI RMI injection with bypass", ThreatLevelCritical},
		{`\$\{::-dns:.*\}`, "JNDI DNS injection with bypass", ThreatLevelCritical},
		{`\$\{${.*?}:.*?\}`, "Nested JNDI reference", ThreatLevelCritical},
		{`\$\{env:.*?\}`, "Environment variable reference", ThreatLevelHigh},
		{`\$\{sys:.*?\}`, "System property reference", ThreatLevelHigh},
		{`\$\{main:.*?\}`, "Main class reference", ThreatLevelCritical},
		{`\$\{loader:.*?\}`, "ClassLoader reference", ThreatLevelCritical},
		{`\$\{processinfo:.*?\}`, "Process info reference", ThreatLevelMedium},
		{`\$\{thread:.*?\}`, "Thread reference", ThreatLevelMedium},
		{`\$\{login:.*?\}`, "Login configuration", ThreatLevelHigh},
		{`\$\{security:.*?\}`, "Security manager reference", ThreatLevelCritical},
		{`\$\{date:.*?\}`, "Date format reference", ThreatLevelMedium},
		{`\$\{url:.*?\}`, "URL reference", ThreatLevelHigh},
		{`\$\{bundle:.*?\}`, "Resource bundle reference", ThreatLevelMedium},
		{`\$\{script:.*?\}`, "Script engine reference", ThreatLevelCritical},
		{`\$\{scripting:.*?\}`, "Scripting engine reference", ThreatLevelCritical},
		{`\$\{com\.sun\.jndi\.rmi\.object\.trustURLCodebase.*?\}`, "RMI object codebase trust", ThreatLevelCritical},
		{`\$\{com\.sun\.jndi\.ldap\.object\.trustURLCodebase.*?\}`, "LDAP object codebase trust", ThreatLevelCritical},
		{`\$\{javax\.management\.remote\.rmi\.v.*?\}`, "JMX RMI reference", ThreatLevelHigh},
		{`\$\{java\.class\.path\}`, "Java class path reference", ThreatLevelMedium},
		{`\$\{java\.class\.path\}`, "Java class path reference", ThreatLevelMedium},
		{`\$\{java\.home\}`, "Java home reference", ThreatLevelMedium},
		{`\$\{java\.vendor\}`, "Java vendor reference", ThreatLevelLow},
		{`\$\{java\.version\}`, "Java version reference", ThreatLevelLow},
		{`\$\{os\.name\}`, "OS name reference", ThreatLevelLow},
		{`\$\{os\.arch\}`, "OS architecture reference", ThreatLevelLow},
		{`\$\{os\.version\}`, "OS version reference", ThreatLevelLow},
		{`\$\{user\.name\}`, "User name reference", ThreatLevelMedium},
		{`\$\{user\.home\}`, "User home reference", ThreatLevelMedium},
		{`\$\{user\.dir\}`, "User directory reference", ThreatLevelMedium},
		{`\$\{catalina\.home\}`, "Tomcat catalina home", ThreatLevelMedium},
		{`\$\{catalina\.base\}`, "Tomcat catalina base", ThreatLevelMedium},
		{`\$\{jetty\.home\}`, "Jetty home reference", ThreatLevelMedium},
		{`log4j`, "Log4j reference in expression", ThreatLevelHigh},
		{`log4j.*appender`, "Log4j appender configuration", ThreatLevelMedium},
		{`socket`, "Socket class reference", ThreatLevelMedium},
		{`SocketFactory`, "Socket factory reference", ThreatLevelMedium},
	}

	for _, p := range exploitPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "JNDI exploitation: " + p.description,
				Recommendation: "Block request; known JNDI/RMI exploitation pattern detected",
			})
		}
	}
}

func (a *ExpressionAnalyzer) analyzeELExpressions(data string, result *AnalysisResult) {
	elPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\$\{.*?\}`, "EL expression with dollar", ThreatLevelMedium},
		{`\#\{.*?\}`, "EL expression with hash", ThreatLevelMedium},
		{`\$\{\+.*?\}`, "EL expression concatenation", ThreatLevelMedium},
		{`\$\{.*?\+.*?\}`, "EL expression with addition", ThreatLevelMedium},
		{`\$\{.*?\-\ .*?\}`, "EL expression with subtraction", ThreatLevelMedium},
		{`\$\{.*?\*.*?\}`, "EL expression with multiplication", ThreatLevelMedium},
		{`\$\{.*?\/.*?\}`, "EL expression with division", ThreatLevelMedium},
		{`\$\{.*?div.*?\}`, "EL expression with div operator", ThreatLevelMedium},
		{`\$\{.*?mod.*?\}`, "EL expression with mod operator", ThreatLevelMedium},
		{`\$\{.*?\..*?\}`, "EL expression property access", ThreatLevelMedium},
		{`\$\{.*?\[".*?"\]`, "EL expression bracket access", ThreatLevelMedium},
		{`\$\{.*?\(.*?\)\}`, "EL expression method call", ThreatLevelHigh},
		{`\#\{.*?\(.*?\)\}`, "EL expression method call hash style", ThreatLevelHigh},
		{`\$\{.*?\.param.*?\}`, "EL param attribute access", ThreatLevelMedium},
		{`\$\{.*?\.header.*?\}`, "EL header attribute access", ThreatLevelMedium},
		{`\$\{.*?\.cookie.*?\}`, "EL cookie access", ThreatLevelMedium},
		{`\$\{.*?\.initParam.*?\}`, "EL init param access", ThreatLevelMedium},
		{`\$\{.*?\.pageContext.*?\}`, "EL pageContext access", ThreatLevelHigh},
		{`\$\{.*?\.request.*?\}`, "EL request access", ThreatLevelHigh},
		{`\$\{.*?\.session.*?\}`, "EL session access", ThreatLevelHigh},
		{`\$\{.*?\.application.*?\}`, "EL application access", ThreatLevelHigh},
		{`\$\{.*?\.pageScope.*?\}`, "EL pageScope access", ThreatLevelMedium},
		{`\$\{.*?\.requestScope.*?\}`, "EL requestScope access", ThreatLevelMedium},
		{`\$\{.*?\.sessionScope.*?\}`, "EL sessionScope access", ThreatLevelHigh},
		{`\$\{.*?\.applicationScope.*?\}`, "EL applicationScope access", ThreatLevelHigh},
		{`\$\{empty.*?\}`, "EL empty operator", ThreatLevelLow},
		{`\$\{not.*?\}`, "EL not operator", ThreatLevelLow},
		{`\$\{.*?and.*?\}`, "EL and operator", ThreatLevelLow},
		{`\$\{.*?or.*?\}`, "EL or operator", ThreatLevelLow},
		{`\$\{.*?eq.*?\}`, "EL eq operator", ThreatLevelLow},
		{`\$\{.*?ne.*?\}`, "EL ne operator", ThreatLevelLow},
		{`\$\{.*?lt.*?\}`, "EL lt operator", ThreatLevelLow},
		{`\$\{.*?gt.*?\}`, "EL gt operator", ThreatLevelLow},
		{`\$\{.*?le.*?\}`, "EL le operator", ThreatLevelLow},
		{`\$\{.*?ge.*?\}`, "EL ge operator", ThreatLevelLow},
		{`\$\{.*?\[.*?\]\}`, "EL bracket notation", ThreatLevelMedium},
		{`\$\{["']`, "EL with quote start", ThreatLevelMedium},
		{`\#\{["']`, "EL hash with quote start", ThreatLevelMedium},
		{`\$\{.*?\:.*?\}`, "EL ternary-like expression", ThreatLevelMedium},
		{`\$\{pageContext.*?\}`, "EL pageContext expression", ThreatLevelHigh},
		{`\$\{application.*?\}`, "EL application expression", ThreatLevelHigh},
		{`\$\{sessionScope.*?\}`, "EL sessionScope expression", ThreatLevelHigh},
	}

	for _, p := range elPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "EL Expression: " + p.description,
				Recommendation: "Validate EL expressions; restrict access to sensitive objects",
			})
		}
	}

	a.analyzeELExploitation(data, result)
}

func (a *ExpressionAnalyzer) analyzeELExploitation(data string, result *AnalysisResult) {
	exploitPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\$\{pageContext\..*?\}`, "EL pageContext exploitation", ThreatLevelCritical},
		{`\$\{application.*?\}`, "EL application scope exploitation", ThreatLevelCritical},
		{`\$\{sessionScope.*?\}`, "EL sessionScope exploitation", ThreatLevelCritical},
		{`\#\{pageContext.*?\}`, "EL pageContext hash style", ThreatLevelCritical},
		{`\$\{request.*?\}`, "EL request exploitation", ThreatLevelHigh},
		{`\$\{session.*?\}`, "EL session exploitation", ThreatLevelHigh},
		{`\$\{pageContext\.request\.contextPath\}`, "EL request contextPath", ThreatLevelMedium},
		{`\$\{pageContext\.request\.queryString\}`, "EL request queryString", ThreatLevelMedium},
		{`\$\{pageContext\.request\.requestURI\}`, "EL request URI", ThreatLevelMedium},
		{`\$\{pageContext\.request\.remoteAddr\}`, "EL request remoteAddr", ThreatLevelMedium},
		{`\$\{pageContext\.servletContext\.serverInfo\}`, "EL serverInfo exploitation", ThreatLevelMedium},
		{`\$\{pageContext\.servletContext\.realPath\}`, "EL realPath exploitation", ThreatLevelMedium},
		{`\$\{pageContext\.session\.id\}`, "EL session ID exploitation", ThreatLevelMedium},
		{`\$\{pageContext\.response.*?\}`, "EL response exploitation", ThreatLevelHigh},
		{`\$\{pageContext\.out.*?\}`, "EL out object exploitation", ThreatLevelHigh},
		{`\$\{pageContext\.getClass\(\)\}`, "EL getClass() call", ThreatLevelCritical},
		{`\#\{pageContext\.getClass\(\)\}`, "EL getClass() hash style", ThreatLevelCritical},
		{`\$\{pageContext\.class.*?\}`, "EL class exploitation", ThreatLevelCritical},
		{`\$\{pageContext\.class\.classLoader.*?\}`, "EL ClassLoader exploitation", ThreatLevelCritical},
		{`\$\{session\.getAttribute.*?\}`, "EL session getAttribute", ThreatLevelHigh},
		{`\$\{application\.getAttribute.*?\}`, "EL application getAttribute", ThreatLevelHigh},
		{`\$\{request\.getParameter.*?\}`, "EL request getParameter", ThreatLevelHigh},
		{`\$\{request\.getHeader.*?\}`, "EL request getHeader", ThreatLevelMedium},
		{`\$\{param.*?\}`, "EL param access", ThreatLevelMedium},
		{`\$\{header.*?\}`, "EL header access", ThreatLevelMedium},
		{`\$\{cookie.*?\}`, "EL cookie access", ThreatLevelMedium},
		{`\$\{initParam.*?\}`, "EL initParam access", ThreatLevelMedium},
		{`\$\{pageScope.*?\}`, "EL pageScope access", ThreatLevelMedium},
		{`\$\{requestScope.*?\}`, "EL requestScope access", ThreatLevelMedium},
		{`\$\{sessionScope.*?\}`, "EL sessionScope access", ThreatLevelHigh},
		{`\$\{applicationScope.*?\}`, "EL applicationScope access", ThreatLevelHigh},
		{`\$\{flash.*?\}`, "EL flash scope access", ThreatLevelMedium},
		{`\$\{flowScope.*?\}`, "EL flowScope access (Spring Web Flow)", ThreatLevelHigh},
		{`\$\{viewScope.*?\}`, "EL viewScope access", ThreatLevelMedium},
		{`\$\{resource.*?\}`, "EL resource access", ThreatLevelMedium},
		{`\$ FacesContext`, "JSF FacesContext reference", ThreatLevelHigh},
		{`\#\{FacesContext.*?\}`, "JSF FacesContext hash style", ThreatLevelHigh},
		{`\$ externalContext`, "JSF externalContext reference", ThreatLevelHigh},
		{`\#\{externalContext.*?\}`, "JSF externalContext hash style", ThreatLevelHigh},
		{`\$ Application`, "JSF Application reference", ThreatLevelHigh},
		{`\$ session`, "JSF session reference", ThreatLevelHigh},
		{`\$ request`, "JSF request reference", ThreatLevelHigh},
		{`\$ view`, "JSF view reference", ThreatLevelHigh},
	}

	for _, p := range exploitPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "EL Expression exploitation: " + p.description,
				Recommendation: "Block request; EL expressions allowing sensitive object access",
			})
		}
	}
}

func (a *ExpressionAnalyzer) analyzeSpELExpressions(data string, result *AnalysisResult) {
	spelPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\#\{.*?\}`, "SpEL expression with hash", ThreatLevelMedium},
		{`\#\{["']`, "SpEL with string literal", ThreatLevelMedium},
		{`\#\{[A-Z].*?\}`, "SpEL with class reference", ThreatLevelHigh},
		{`\#\{@.*?\}`, "SpEL bean reference", ThreatLevelMedium},
		{`\#\{T\(.*?\)\}`, "SpEL type reference", ThreatLevelHigh},
		{`\#\{.*?\.getClass\(\)\}`, "SpEL getClass() call", ThreatLevelCritical},
		{`\#\{.*?\.class\}`, "SpEL class property", ThreatLevelHigh},
		{`\#\{.*?\.forName\(`, "SpEL Class.forName()", ThreatLevelCritical},
		{`\#\{.*?\.getDeclaredConstructor\(`, "SpEL getDeclaredConstructor()", ThreatLevelCritical},
		{`\#\{.*?\.getDeclaredField\(`, "SpEL getDeclaredField()", ThreatLevelCritical},
		{`\#\{.*?\.newInstance\(\)\}`, "SpEL newInstance() call", ThreatLevelCritical},
		{`\#\{.*?\.getMethod\(`, "SpEL getMethod() call", ThreatLevelCritical},
		{`\#\{.*?\.invoke\(`, "SpEL invoke() call", ThreatLevelCritical},
		{`\#\{.*?\}eq.*?\}`, "SpEL equality comparison", ThreatLevelLow},
		{`\#\{.*?\}ne.*?\}`, "SpEL not equal comparison", ThreatLevelLow},
		{`\#\{.*?\}lt.*?\}`, "SpEL less than comparison", ThreatLevelLow},
		{`\#\{.*?\}gt.*?\}`, "SpEL greater than comparison", ThreatLevelLow},
		{`\#\{.*?\}le.*?\}`, "SpEL less or equal comparison", ThreatLevelLow},
		{`\#\{.*?\}ge.*?\}`, "SpEL greater or equal comparison", ThreatLevelLow},
		{`\#\{.*?\(\)\}`, "SpEL method invocation", ThreatLevelHigh},
		{`\#\{.*?\(.*?,.*?\)\}`, "SpEL method with args", ThreatLevelHigh},
		{`\#\{new\s+.*?\(`, "SpEL object instantiation", ThreatLevelHigh},
		{`\#\{.*?\+.*?\}`, "SpEL concatenation", ThreatLevelLow},
		{`\#\{.*?\-\ .*?\}`, "SpEL subtraction", ThreatLevelLow},
		{`\#\{.*?\*.*?\}`, "SpEL multiplication", ThreatLevelLow},
		{`\#\{.*?\/.*?\}`, "SpEL division", ThreatLevelLow},
		{`\#\{.*?\%.*?\}`, "SpEL modulus", ThreatLevelLow},
		{`\#\{.*?\.toString\(\)\}`, "SpEL toString() call", ThreatLevelMedium},
		{`\#\{.*?\.toByteArray\(\)\}`, "SpEL toByteArray() call", ThreatLevelMedium},
		{`\#\{.*?\.valueOf\(\)\}`, "SpEL valueOf() call", ThreatLevelMedium},
		{`\#\{.*?\.substring\(`, "SpEL substring() call", ThreatLevelMedium},
		{`\#\{.*?\.split\(`, "SpEL split() call", ThreatLevelMedium},
		{`\#\{.*?\.replace\(`, "SpEL replace() call", ThreatLevelMedium},
		{`\#\{.*?\.trim\(\)\}`, "SpEL trim() call", ThreatLevelLow},
		{`\#\{.*?\.length\(\)\}`, "SpEL length() call", ThreatLevelLow},
		{`\#\{.*?\.isEmpty\(\)\}`, "SpEL isEmpty() call", ThreatLevelLow},
		{`\#\{.*?\.contains\(`, "SpEL contains() call", ThreatLevelMedium},
		{`\#\{.*?\.startsWith\(`, "SpEL startsWith() call", ThreatLevelLow},
		{`\#\{.*?\.endsWith\(`, "SpEL endsWith() call", ThreatLevelLow},
		{`\#\{.*?\.matches\(`, "SpEL matches() call", ThreatLevelMedium},
		{`\#\{.*?\.equals\(`, "SpEL equals() call", ThreatLevelLow},
		{`\#\{.*?\.hashCode\(\)\}`, "SpEL hashCode() call", ThreatLevelLow},
		{`\#\{.*?\.getBytes\(\)\}`, "SpEL getBytes() call", ThreatLevelMedium},
	}

	for _, p := range spelPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "SpEL Expression: " + p.description,
				Recommendation: "Validate SpEL expressions; restrict type access",
			})
		}
	}

	a.analyzeSpELExploitation(data, result)
}

func (a *ExpressionAnalyzer) analyzeSpELExploitation(data string, result *AnalysisResult) {
	exploitPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\#\{T\(java\.lang\.System\)`, "SpEL java.lang.System access", ThreatLevelCritical},
		{`\#\{T\(java\.lang\.Runtime\)`, "SpEL java.lang.Runtime access", ThreatLevelCritical},
		{`\#\{T\(java\.lang\.Class\)`, "SpEL java.lang.Class access", ThreatLevelCritical},
		{`\#\{T\(java\.lang\.ProcessBuilder\)`, "SpEL ProcessBuilder access", ThreatLevelCritical},
		{`\#\{T\(java\.lang\.ClassLoader\)`, "SpEL ClassLoader access", ThreatLevelCritical},
		{`\#\{T\(java\.lang\.reflect\.Method\)`, "SpEL Method access", ThreatLevelCritical},
		{`\#\{T\(java\.lang\.reflect\.Field\)`, "SpEL Field access", ThreatLevelCritical},
		{`\#\{T\(java\.lang\.reflect\.Constructor\)`, "SpEL Constructor access", ThreatLevelCritical},
		{`\#\{T\(java\.io\.File\)`, "SpEL File access", ThreatLevelCritical},
		{`\#\{T\(java\.io\.InputStream\)`, "SpEL InputStream access", ThreatLevelCritical},
		{`\#\{T\(java\.net\.URL\)`, "SpEL URL access", ThreatLevelHigh},
		{`\#\{T\(java\.net\.Socket\)`, "SpEL Socket access", ThreatLevelHigh},
		{`\#\{T\(java\.sql\.DriverManager\)`, "SpEL DriverManager access", ThreatLevelHigh},
		{`\#\{T\(javax\.sql\.DataSource\)`, "SpEL DataSource access", ThreatLevelHigh},
		{`\#\{T\(org\.springframework\.beans\.BeanUtils\)`, "SpEL Spring BeanUtils", ThreatLevelHigh},
		{`\#\{T\(org\.springframework\.util\.ReflectionUtils\)`, "SpEL Spring ReflectionUtils", ThreatLevelHigh},
		{`\#\{T\(com\.opensymphony\.xwork2\.ActionContext\)`, "Struts2 ActionContext", ThreatLevelCritical},
		{`\#\{@.*?\}`, "SpEL bean reference exploitation", ThreatLevelHigh},
		{`\#\{@org\.springframework.*?\}`, "SpEL Spring bean exploitation", ThreatLevelHigh},
		{`\#\{@.*?\.getClass\(\)\}`, "SpEL bean getClass()", ThreatLevelCritical},
		{`\#\{.*?@.*?\}`, "SpEL bean method chain", ThreatLevelHigh},
		{`\#\{new\s+java\.lang\.ProcessBuilder`, "SpEL ProcessBuilder creation", ThreatLevelCritical},
		{`\#\{new\s+java\.lang\.Runtime`, "SpEL Runtime creation", ThreatLevelCritical},
		{`\#\{T\(java\.lang\.System\)\.exit`, "SpEL System.exit()", ThreatLevelCritical},
		{`\#\{T\(java\.lang\.System\)\.gc`, "SpEL System.gc()", ThreatLevelHigh},
		{`\#\{T\(java\.lang\.Runtime\)\.getRuntime\(\)\.exec`, "SpEL Runtime.exec()", ThreatLevelCritical},
		{`\#\{T\(java\.lang\.Runtime\)\.getRuntime\(\)\.availableProcessors`, "SpEL availableProcessors", ThreatLevelLow},
		{`\#\{T\(java\.lang\.Runtime\)\.getRuntime\(\)\.freeMemory`, "SpEL freeMemory", ThreatLevelLow},
		{`\#\{T\(java\.lang\.Runtime\)\.getRuntime\(\)\.totalMemory`, "SpEL totalMemory", ThreatLevelLow},
		{`\#\{T\(java\.lang\.Boolean\)\.TYPE`, "SpEL Boolean.TYPE", ThreatLevelMedium},
		{`\#\{T\(java\.lang\.Byte\)\.TYPE`, "SpEL Byte.TYPE", ThreatLevelMedium},
		{`\#\{T\(java\.lang\.Character\)\.TYPE`, "SpEL Character.TYPE", ThreatLevelMedium},
		{`\#\{T\(java\.lang\.Integer\)\.TYPE`, "SpEL Integer.TYPE", ThreatLevelMedium},
		{`\#\{T\(java\.lang\.Long\)\.TYPE`, "SpEL Long.TYPE", ThreatLevelMedium},
		{`\#\{T\(java\.lang\.Double\)\.TYPE`, "SpEL Double.TYPE", ThreatLevelMedium},
		{`\#\{T\(java\.lang\.Float\)\.TYPE`, "SpEL Float.TYPE", ThreatLevelMedium},
		{`\#\{T\(java\.lang\.Short\)\.TYPE`, "SpEL Short.TYPE", ThreatLevelMedium},
		{`\#\{T\(java\.lang\.Object\)\.class`, "SpEL Object.class", ThreatLevelMedium},
		{`\#\{T\(java\.lang\.Class\)\.forName`, "SpEL Class.forName()", ThreatLevelCritical},
		{`\#\{T\(java\.security\.SecurityManager\)`, "SpEL SecurityManager access", ThreatLevelCritical},
		{`\#\{T\(java\.lang\.ref\.Reference\)`, "SpEL Reference access", ThreatLevelHigh},
		{`\#\{T\(java\.lang\.ref\.FinalReference\)`, "SpEL FinalReference access", ThreatLevelHigh},
		{`\#\{T\(java\.lang\.ref\.Finalizer\)`, "SpEL Finalizer access", ThreatLevelHigh},
		{`\#\{T\(java\.util\.Timer\)`, "SpEL Timer access", ThreatLevelHigh},
		{`\#\{T\(java\.util\.TimerTask\)`, "SpEL TimerTask access", ThreatLevelHigh},
		{`\#\{T\(sun\.misc\.Unsafe\)`, "SpEL sun.misc.Unsafe access", ThreatLevelCritical},
		{`\#\{T\(sun\.reflect\.ReflectionFactory\)`, "SpEL ReflectionFactory access", ThreatLevelCritical},
	}

	for _, p := range exploitPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "SpEL exploitation: " + p.description,
				Recommendation: "Block request; known SpEL exploitation pattern detected",
			})
		}
	}
}

func (a *ExpressionAnalyzer) analyzeLog4jVulnerabilities(data string, result *AnalysisResult) {
	log4jPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\$\{.*?::-.*?\}`, "Log4j bypass with empty prefix", ThreatLevelCritical},
		{`\$\{.*?:.*?-.*?\}`, "Log4j bypass with dash", ThreatLevelCritical},
		{`\$\{.*?:.*?:\-.*?\}`, "Log4j bypass pattern", ThreatLevelCritical},
		{`\$\{.*?:.*?\}`, "Log4j generic lookup", ThreatLevelHigh},
		{`\$\{jndi:.*?\}`, "Log4j JNDI lookup", ThreatLevelCritical},
		{`\$\{env:.*?\}`, "Log4j environment lookup", ThreatLevelHigh},
		{`\$\{sys:.*?\}`, "Log4j system property lookup", ThreatLevelHigh},
		{`\$\{ctx:.*?\}`, "Log4j context lookup", ThreatLevelCritical},
		{`\$\{bundle:.*?\}`, "Log4j bundle lookup", ThreatLevelMedium},
		{`\$\{date:.*?\}`, "Log4j date lookup", ThreatLevelMedium},
		{`\$\{login:.*?\}`, "Log4j login lookup", ThreatLevelHigh},
		{`\$\{main:.*?\}`, "Log4j main lookup", ThreatLevelHigh},
		{`\$\{map:.*?\}`, "Log4j map lookup", ThreatLevelMedium},
		{`\$\{mdc:.*?\}`, "Log4j MDC lookup", ThreatLevelMedium},
		{`\$\{ndc:.*?\}`, "Log4j NDC lookup", ThreatLevelMedium},
		{`\$\{thread:.*?\}`, "Log4j thread lookup", ThreatLevelMedium},
		{`\$\{hostname:.*?\}`, "Log4j hostname lookup", ThreatLevelMedium},
		{`\$\{lower:.*?\}`, "Log4j lower conversion", ThreatLevelMedium},
		{`\$\{upper:.*?\}`, "Log4j upper conversion", ThreatLevelMedium},
		{`\$\{strip:.*?\}`, "Log4j strip conversion", ThreatLevelMedium},
		{`\$\{trim:.*?\}`, "Log4j trim conversion", ThreatLevelMedium},
		{`\$\{marker:.*?\}`, "Log4j marker lookup", ThreatLevelLow},
		{`\$\{ctx:loginId\}`, "Log4j loginId context", ThreatLevelMedium},
		{`\$\{ctx:remoteHost\}`, "Log4j remoteHost context", ThreatLevelMedium},
		{`\$\{env:USER\}`, "Log4j USER env", ThreatLevelMedium},
		{`\$\{env:USERNAME\}`, "Log4j USERNAME env", ThreatLevelMedium},
		{`\$\{env:HOME\}`, "Log4j HOME env", ThreatLevelMedium},
		{`\$\{env:PATH\}`, "Log4j PATH env", ThreatLevelMedium},
		{`\$\{env:JAVA_HOME\}`, "Log4j JAVA_HOME env", ThreatLevelMedium},
		{`\$\{sys:user.name\}`, "Log4j user.name sysprop", ThreatLevelMedium},
		{`\$\{sys:user.home\}`, "Log4j user.home sysprop", ThreatLevelMedium},
		{`\$\{sys:user.dir\}`, "Log4j user.dir sysprop", ThreatLevelMedium},
		{`\$\{sys:java.home\}`, "Log4j java.home sysprop", ThreatLevelMedium},
		{`\$\{sys:java.class.version\}`, "Log4j java.class.version sysprop", ThreatLevelLow},
		{`\$\{sys:java.vendor\}`, "Log4j java.vendor sysprop", ThreatLevelLow},
		{`\$\{sys:java.version\}`, "Log4j java.version sysprop", ThreatLevelLow},
		{`\$\{sys:os.name\}`, "Log4j os.name sysprop", ThreatLevelLow},
		{`\$\{sys:os.version\}`, "Log4j os.version sysprop", ThreatLevelLow},
		{`\$\{sys:os.arch\}`, "Log4j os.arch sysprop", ThreatLevelLow},
		{`\$\{sys:file.separator\}`, "Log4j file.separator sysprop", ThreatLevelLow},
		{`\$\{sys:path.separator\}`, "Log4j path.separator sysprop", ThreatLevelLow},
		{`\$\{sys:line.separator\}`, "Log4j line.separator sysprop", ThreatLevelLow},
		{`\$\{log4j:configLocation\}`, "Log4j configLocation", ThreatLevelLow},
		{`\$\{log4j:defaultConfigLocation\}`, "Log4j defaultConfigLocation", ThreatLevelLow},
		{`\$\{log4j:configuratorClass\}`, "Log4j configuratorClass", ThreatLevelLow},
		{`\$\{log4j:parentLoaderPriority\}`, "Log4j parentLoaderPriority", ThreatLevelMedium},
		{`\$\{jndi:ldap://`, "Log4j JNDI LDAP", ThreatLevelCritical},
		{`\$\{jndi:rmi://`, "Log4j JNDI RMI", ThreatLevelCritical},
		{`\$\{jndi:dns://`, "Log4j JNDI DNS", ThreatLevelCritical},
		{`\$\{jndi:iiop://`, "Log4j JNDI IIOP", ThreatLevelCritical},
		{`\$\{jndi:corba://`, "Log4j JNDI CORBA", ThreatLevelCritical},
		{`\$\{::-jndi:`, "Log4j bypass empty prefix", ThreatLevelCritical},
		{`\$\{::-ldap:`, "Log4j LDAP bypass", ThreatLevelCritical},
		{`\$\{::-rmi:`, "Log4j RMI bypass", ThreatLevelCritical},
		{`\$\{::-dns:`, "Log4j DNS bypass", ThreatLevelCritical},
		{`\$\{::-com\.sun\.jndi`, "Log4j JNDI object bypass", ThreatLevelCritical},
		{`\$\{env:AWSSESSION`, "Log4j AWS session token", ThreatLevelHigh},
		{`\$\{env:AWS_ACCESS_KEY`, "Log4j AWS access key", ThreatLevelHigh},
		{`\$\{env:AWS_SECRET_KEY`, "Log4j AWS secret key", ThreatLevelCritical},
		{`\$\{env:GOOGLE_APPLICATION_CREDENTIALS\}`, "Log4j GCP credentials", ThreatLevelCritical},
		{`\$\{env:HEROKU_API_KEY\}`, "Log4j Heroku API key", ThreatLevelHigh},
		{`\$\{env:SHELL\}`, "Log4j SHELL env", ThreatLevelMedium},
		{`\$\{env:SSH_.*?\}`, "Log4j SSH env", ThreatLevelHigh},
		{`\$\{::-\}`, "Log4j empty replacement", ThreatLevelMedium},
		{`\$\{.*?:.*?-.*?\}`, "Log4j alternative syntax", ThreatLevelHigh},
		{`\$\{.*?:.*?:\-.*?\}`, "Log4j alternative syntax 2", ThreatLevelHigh},
	}

	for _, p := range log4jPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Log4j Vulnerability: " + p.description,
				Recommendation: "Block request; Log4j exploitation pattern detected (CVE consideration)",
			})
		}
	}
}

func (a *ExpressionAnalyzer) analyzeSpringFrameworkVulnerabilities(data string, result *AnalysisResult) {
	springPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`class\.*`, "Spring class reference", ThreatLevelHigh},
		{`\.class\.forName`, "Spring Class.forName", ThreatLevelCritical},
		{`\.class\.getResource`, "Spring getResource", ThreatLevelHigh},
		{`\.class\.getClassLoader`, "Spring ClassLoader access", ThreatLevelCritical},
		{`@.*?\.class`, "Spring annotation class reference", ThreatLevelMedium},
		{`@.*?\.\w+`, "Spring annotation attribute access", ThreatLevelMedium},
		{`Spring\.class`, "Spring class direct reference", ThreatLevelHigh},
		{`ApplicationContext`, "Spring ApplicationContext", ThreatLevelHigh},
		{`BeanFactory`, "Spring BeanFactory", ThreatLevelHigh},
		{`ClassPathXmlApplicationContext`, "Spring ClassPathXmlApplicationContext", ThreatLevelHigh},
		{`FileSystemXmlApplicationContext`, "Spring FileSystemXmlApplicationContext", ThreatLevelHigh},
		{`XmlWebApplicationContext`, "Spring XmlWebApplicationContext", ThreatLevelHigh},
		{`AnnotationConfigApplicationContext`, "Spring AnnotationConfigApplicationContext", ThreatLevelHigh},
		{`getBean\(`, "Spring getBean() call", ThreatLevelHigh},
		{`getBeansOfType\(`, "Spring getBeansOfType() call", ThreatLevelHigh},
		{`getBeanDefinitionNames`, "Spring getBeanDefinitionNames()", ThreatLevelMedium},
		{`BeanWrapper`, "Spring BeanWrapper", ThreatLevelMedium},
		{`BeanWrapperImpl`, "Spring BeanWrapperImpl", ThreatLevelMedium},
		{`PropertyAccessor`, "Spring PropertyAccessor", ThreatLevelMedium},
		{`DirectFieldAccessor`, "Spring DirectFieldAccessor", ThreatLevelMedium},
		{`BeanWrapper.*?setPropertyValue`, "Spring setPropertyValue", ThreatLevelHigh},
		{`BeanWrapper.*?getPropertyValue`, "Spring getPropertyValue", ThreatLevelHigh},
		{`ReflectionUtils`, "Spring ReflectionUtils", ThreatLevelHigh},
		{`ReflectionUtils\.invokeMethod`, "Spring ReflectionUtils invokeMethod", ThreatLevelCritical},
		{`ReflectionUtils\.findMethod`, "Spring ReflectionUtils findMethod", ThreatLevelHigh},
		{`ReflectionUtils\.getField`, "Spring ReflectionUtils getField", ThreatLevelHigh},
		{`ReflectionUtils\.setField`, "Spring ReflectionUtils setField", ThreatLevelHigh},
		{`MethodHandler`, "Spring MethodHandler", ThreatLevelHigh},
		{`InvocableHandlerComponent`, "Spring InvocableHandlerComponent", ThreatLevelHigh},
		{`WebRequest.*?getParameter`, "Spring WebRequest getParameter", ThreatLevelMedium},
		{`WebRequest.*?getHeader`, "Spring WebRequest getHeader", ThreatLevelMedium},
		{`ServletRequest.*?getParameter`, "Spring ServletRequest getParameter", ThreatLevelMedium},
		{`HttpServletRequest.*?getParameter`, "Spring HttpServletRequest getParameter", ThreatLevelMedium},
		{`RequestContext.*?getParameter`, "Spring RequestContext getParameter", ThreatLevelMedium},
		{`RequestContextHolder.*?getRequestAttributes`, "Spring RequestContextHolder", ThreatLevelMedium},
		{`SessionLocaleResolver.*?setDefaultLocale`, "Spring SessionLocaleResolver", ThreatLevelMedium},
		{`CookieLocaleResolver.*?setDefaultCookieValue`, "Spring CookieLocaleResolver", ThreatLevelMedium},
		{`AcceptHeaderLocaleResolver`, "Spring AcceptHeaderLocaleResolver", ThreatLevelMedium},
		{`FlashMap.*?get.*?\(`, "Spring FlashMap get", ThreatLevelMedium},
		{`FlashMap.*?set.*?\(`, "Spring FlashMap set", ThreatLevelMedium},
		{`ModelAndView.*?setViewName`, "Spring ModelAndView setViewName", ThreatLevelMedium},
		{`ModelAndView.*?setView`, "Spring ModelAndView setView", ThreatLevelMedium},
		{`View.*?render.*?\(`, "Spring View render", ThreatLevelMedium},
		{`InternalResourceView.*?render.*?\(`, "Spring InternalResourceView render", ThreatLevelMedium},
		{`JstlView.*?render.*?\(`, "Spring JstlView render", ThreatLevelMedium},
		{`RedirectAttributes.*?addFlashAttribute`, "Spring RedirectAttributes", ThreatLevelMedium},
		{`ModelMap.*?addAttribute`, "Spring ModelMap addAttribute", ThreatLevelLow},
		{`BindingResult.*?reject.*?\(`, "Spring BindingResult reject", ThreatLevelMedium},
		{`Errors.*?reject.*?\(`, "Spring Errors reject", ThreatLevelMedium},
		{`HandlerInterceptor.*?preHandle.*?\(`, "Spring HandlerInterceptor", ThreatLevelMedium},
		{`HandlerInterceptor.*?postHandle.*?\(`, "Spring HandlerInterceptor postHandle", ThreatLevelMedium},
		{`HandlerInterceptor.*?afterCompletion.*?\(`, "Spring HandlerInterceptor afterCompletion", ThreatLevelMedium},
		{`LocaleContextHolder.*?setLocale`, "Spring LocaleContextHolder setLocale", ThreatLevelMedium},
		{`TimeZone.*?setDefault`, "Spring TimeZone setDefault", ThreatLevelMedium},
		{`ServletUriInformationCollector`, "Spring ServletUriInformationCollector", ThreatLevelMedium},
		{`Spring\.util\.ReflectionUtils`, "Spring util ReflectionUtils", ThreatLevelHigh},
		{`org\.springframework\.web\.util\.HtmlUtils`, "Spring HtmlUtils", ThreatLevelMedium},
		{`org\.springframework\.web\.util\.JavaScriptUtils`, "Spring JavaScriptUtils", ThreatLevelMedium},
		{`org\.springframework\.web\.util\.UriUtils`, "Spring UriUtils", ThreatLevelMedium},
		{`org\.springframework\.web\.util\.ContentCachingRequestWrapper`, "Spring ContentCachingRequestWrapper", ThreatLevelMedium},
		{`org\.springframework\.web\.util\.ContentCachingResponseWrapper`, "Spring ContentCachingResponseWrapper", ThreatLevelMedium},
	}

	for _, p := range springPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Spring Framework: " + p.description,
				Recommendation: "Validate Spring expressions; restrict reflection access",
			})
		}
	}
}

func (a *ExpressionAnalyzer) analyzeStruts2OGNL(data string, result *AnalysisResult) {
	ognlPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\#`, "OGNL variable prefix", ThreatLevelMedium},
		{`\%\{`, "OGNL percent expression start", ThreatLevelMedium},
		{`\$\{`, "OGNL dollar expression start", ThreatLevelMedium},
		{`\#_`, "OGNL underscore prefix", ThreatLevelCritical},
		{`\#this`, "OGNL this reference", ThreatLevelHigh},
		{`\#root`, "OGNL root reference", ThreatLevelHigh},
		{`\#context`, "OGNL context reference", ThreatLevelHigh},
		{`\#parameters`, "OGNL parameters reference", ThreatLevelHigh},
		{`\#request`, "OGNL request reference", ThreatLevelHigh},
		{`\#session`, "OGNL session reference", ThreatLevelHigh},
		{`\#application`, "OGNL application reference", ThreatLevelHigh},
		{`\#attr`, "OGNL attr reference", ThreatLevelMedium},
		{`\#values`, "OGNL values reference", ThreatLevelMedium},
		{`\#memberAccess`, "OGNL memberAccess reference", ThreatLevelCritical},
		{`\#_memberAccess`, "OGNL memberAccess bypass attempt", ThreatLevelCritical},
		{`\#allowedClasses`, "OGNL allowedClasses reference", ThreatLevelMedium},
		{`\#deniedClasses`, "OGNL deniedClasses reference", ThreatLevelMedium},
		{`\#executeClassifier`, "OGNL executeClassifier reference", ThreatLevelMedium},
		{`@.*?@`, "OGNL static class reference", ThreatLevelHigh},
		{`@.*?@class`, "OGNL class reference", ThreatLevelCritical},
		{`@.*?@forName`, "OGNL forName call", ThreatLevelCritical},
		{`@.*?@getClass`, "OGNL getClass call", ThreatLevelCritical},
		{`@.*?@getResource`, "OGNL getResource call", ThreatLevelHigh},
		{`@.*?@getDeclaredConstructor`, "OGNL getDeclaredConstructor", ThreatLevelCritical},
		{`@.*?@getDeclaredField`, "OGNL getDeclaredField", ThreatLevelCritical},
		{`@.*?@getMethod`, "OGNL getMethod", ThreatLevelCritical},
		{`@.*?@invokeMethod`, "OGNL invokeMethod", ThreatLevelCritical},
		{`@.*?@newInstance`, "OGNL newInstance", ThreatLevelCritical},
		{`@.*?@getConstructors`, "OGNL getConstructors", ThreatLevelHigh},
		{`@.*?@getMethods`, "OGNL getMethods", ThreatLevelHigh},
		{`@.*?@getFields`, "OGNL getFields", ThreatLevelHigh},
		{`@.*?Runtime@getRuntime`, "OGNL Runtime.getRuntime", ThreatLevelCritical},
		{`@.*?Runtime@exec`, "OGNL Runtime.exec", ThreatLevelCritical},
		{`@.*?ProcessBuilder@new`, "OGNL ProcessBuilder.new", ThreatLevelCritical},
		{`@.*?System@getProperty`, "OGNL System.getProperty", ThreatLevelHigh},
		{`@.*?System@setProperty`, "OGNL System.setProperty", ThreatLevelCritical},
		{`@.*?System@exit`, "OGNL System.exit", ThreatLevelCritical},
		{`@.*?ClassLoader@`, "OGNL ClassLoader reference", ThreatLevelCritical},
		{`@.*?Thread@currentThread`, "OGNL Thread.currentThread", ThreatLevelHigh},
		{`@.*?Thread@getContextClassLoader`, "OGNL Thread.getContextClassLoader", ThreatLevelCritical},
		{`new\s+java\.`, "OGNL new java object", ThreatLevelCritical},
		{`new\s+ProcessBuilder`, "OGNL new ProcessBuilder", ThreatLevelCritical},
		{`new\s+Runtime`, "OGNL new Runtime", ThreatLevelCritical},
		{`java\.lang\.System`, "OGNL java.lang.System", ThreatLevelCritical},
		{`java\.lang\.Runtime`, "OGNL java.lang.Runtime", ThreatLevelCritical},
		{`java\.lang\.ProcessBuilder`, "OGNL java.lang.ProcessBuilder", ThreatLevelCritical},
		{`java\.lang\.Class`, "OGNL java.lang.Class", ThreatLevelCritical},
		{`java\.lang\.ClassLoader`, "OGNL java.lang.ClassLoader", ThreatLevelCritical},
		{`java\.lang\.reflect\.`, "OGNL java.lang.reflect", ThreatLevelCritical},
		{`java\.io\.`, "OGNL java.io", ThreatLevelHigh},
		{`java\.net\.`, "OGNL java.net", ThreatLevelHigh},
		{`java\.util\.`, "OGNL java.util", ThreatLevelMedium},
	}

	for _, p := range ognlPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Struts2 OGNL: " + p.description,
				Recommendation: "Block request; OGNL exploitation pattern detected",
			})
		}
	}
}

func (a *ExpressionAnalyzer) analyzeMVELExpressions(data string, result *AnalysisResult) {
	mvelPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\{.*?\}`, "MVEL expression braces", ThreatLevelMedium},
		{`\.\w+\s*\(`, "MVEL method call", ThreatLevelMedium},
		{`\w+\s*\.\s*\w+\s*\(`, "MVEL chained method call", ThreatLevelMedium},
		{`\w+\s*\[\s*.*?\s*\]`, "MVEL array/list access", ThreatLevelMedium},
		{`\w+\s*\.\s*\w+`, "MVEL property access", ThreatLevelMedium},
		{`@.*?\s*\(`, "MVEL annotation call", ThreatLevelMedium},
		{`\w+\s*\?\s*\(`, "MVEL filter expression", ThreatLevelMedium},
		{`\w+\s*!\s*\(`, "MVEL projection expression", ThreatLevelMedium},
		{`\w+\s*in\s+\(`, "MVEL in operator", ThreatLevelLow},
		{`\w+\s*instanceof\s+`, "MVEL instanceof operator", ThreatLevelMedium},
		{`\w+\s*like\s+`, "MVEL like operator", ThreatLevelLow},
		{`\w+\s*matches\s+`, "MVEL matches operator", ThreatLevelMedium},
		{`\w+\s*between\s+`, "MVEL between operator", ThreatLevelLow},
		{`\w+\s*is\s+\w+`, "MVEL is operator", ThreatLevelLow},
		{`\w+\s*and\s+\w+`, "MVEL and operator", ThreatLevelLow},
		{`\w+\s*or\s+\w+`, "MVEL or operator", ThreatLevelLow},
		{`\w+\s*not\s+\w+`, "MVEL not operator", ThreatLevelLow},
		{`\w+\s*if\s+`, "MVEL if operator", ThreatLevelLow},
		{`\w+\s*else\s+`, "MVEL else operator", ThreatLevelLow},
		{`foreach\s*\{`, "MVEL foreach block", ThreatLevelMedium},
		{`for\s*\{`, "MVEL for block", ThreatLevelMedium},
		{`while\s*\{`, "MVEL while block", ThreatLevelMedium},
		{`def\s+\w+`, "MVEL def statement", ThreatLevelMedium},
		{`var\s+\w+`, "MVEL var statement", ThreatLevelLow},
		{`import\s+`, "MVEL import statement", ThreatLevelMedium},
		{`static\s+`, "MVEL static statement", ThreatLevelMedium},
		{`new\s+`, "MVEL new statement", ThreatLevelHigh},
		{`this`, "MVEL this reference", ThreatLevelMedium},
		{`super`, "MVEL super reference", ThreatLevelMedium},
		{`parent`, "MVEL parent reference", ThreatLevelMedium},
		{`context`, "MVEL context reference", ThreatLevelHigh},
		{`vars`, "MVEL vars reference", ThreatLevelHigh},
		{`out`, "MVEL out reference", ThreatLevelMedium},
		{`err`, "MVEL err reference", ThreatLevelMedium},
		{`System`, "MVEL System reference", ThreatLevelCritical},
		{`Runtime`, "MVEL Runtime reference", ThreatLevelCritical},
		{`ProcessBuilder`, "MVEL ProcessBuilder reference", ThreatLevelCritical},
		{`class`, "MVEL class reference", ThreatLevelHigh},
		{`getClass\(\)`, "MVEL getClass() call", ThreatLevelCritical},
		{`forName\(`, "MVEL Class.forName()", ThreatLevelCritical},
		{`getResource\(`, "MVEL getResource() call", ThreatLevelHigh},
		{`getResourceAsStream\(`, "MVEL getResourceAsStream()", ThreatLevelHigh},
		{`newInstance\(`, "MVEL newInstance() call", ThreatLevelCritical},
		{`getDeclaredConstructor\(`, "MVEL getDeclaredConstructor()", ThreatLevelCritical},
		{`getDeclaredField\(`, "MVEL getDeclaredField()", ThreatLevelCritical},
		{`getMethod\(`, "MVEL getMethod()", ThreatLevelCritical},
		{`invokeMethod\(`, "MVEL invokeMethod()", ThreatLevelCritical},
		{`setAccessible\(`, "MVEL setAccessible()", ThreatLevelCritical},
		{`exec\(`, "MVEL exec() call", ThreatLevelCritical},
		{`system\(`, "MVEL system() call", ThreatLevelCritical},
		{`Runtime\.getRuntime`, "MVEL Runtime.getRuntime()", ThreatLevelCritical},
		{`Runtime\.exec`, "MVEL Runtime.exec()", ThreatLevelCritical},
	}

	for _, p := range mvelPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "MVEL Expression: " + p.description,
				Recommendation: "Validate MVEL expressions; disable dangerous features",
			})
		}
	}
}

func (a *ExpressionAnalyzer) analyzeJBossELExpressions(data string, result *AnalysisResult) {
	jbossPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\#\{.*?\}`, "JBoss EL expression", ThreatLevelMedium},
		{`\$\{.*?\}`, "JBoss EL alternative syntax", ThreatLevelMedium},
		{`\#\{facesContext`, "JBoss facesContext access", ThreatLevelCritical},
		{`\#\{request`, "JBoss request access", ThreatLevelHigh},
		{`\#\{session`, "JBoss session access", ThreatLevelHigh},
		{`\#\{application`, "JBoss application access", ThreatLevelHigh},
		{`\#\{view`, "JBoss view access", ThreatLevelHigh},
		{`\#\{externalContext`, "JBoss externalContext access", ThreatLevelCritical},
		{`\#\{flash`, "JBoss flash scope", ThreatLevelMedium},
		{`\#\{resource`, "JBoss resource handler", ThreatLevelMedium},
		{`\#\{bean`, "JBoss bean access", ThreatLevelMedium},
		{`\#\{component`, "JBoss component access", ThreatLevelMedium},
		{`\#\{validator`, "JBoss validator access", ThreatLevelMedium},
		{`\#\{converter`, "JBoss converter access", ThreatLevelMedium},
		{`\#\{application\.getContext`, "JBoss application.getContext", ThreatLevelCritical},
		{`\#\{facesContext\.getApplication`, "JBoss facesContext.getApplication", ThreatLevelCritical},
		{`\#\{facesContext\.getExternalContext`, "JBoss facesContext.getExternalContext", ThreatLevelCritical},
		{`\#\{facesContext\.getRenderKit`, "JBoss facesContext.getRenderKit", ThreatLevelHigh},
		{`\#\{externalContext\.getSession`, "JBoss externalContext.getSession", ThreatLevelHigh},
		{`\#\{externalContext\.getRequest`, "JBoss externalContext.getRequest", ThreatLevelHigh},
		{`\#\{externalContext\.getResponse`, "JBoss externalContext.getResponse", ThreatLevelHigh},
		{`\#\{externalContext\.getRequestMap`, "JBoss externalContext.getRequestMap", ThreatLevelHigh},
		{`\#\{externalContext\.getSessionMap`, "JBoss externalContext.getSessionMap", ThreatLevelHigh},
		{`\#\{externalContext\.getApplicationMap`, "JBoss externalContext.getApplicationMap", ThreatLevelCritical},
		{`\#\{externalContext\.getInitParameter`, "JBoss externalContext.getInitParameter", ThreatLevelMedium},
		{`\#\{externalContext\.getResourceAsStream`, "JBoss externalContext.getResourceAsStream", ThreatLevelHigh},
		{`\#\{externalContext\.dispatch`, "JBoss externalContext.dispatch", ThreatLevelHigh},
		{`\#\{externalContext\.redirect`, "JBoss externalContext.redirect", ThreatLevelHigh},
		{`\#\{application\.createMethodBinding`, "JBoss application.createMethodBinding", ThreatLevelCritical},
		{`\#\{application\.createValueBinding`, "JBoss application.createValueBinding", ThreatLevelCritical},
		{`\#\{application\.getVariableResolver`, "JBoss application.getVariableResolver", ThreatLevelHigh},
		{`\#\{application\.getPropertyResolver`, "JBoss application.getPropertyResolver", ThreatLevelHigh},
		{`\#\{application\.getExpressionFactory`, "JBoss application.getExpressionFactory", ThreatLevelHigh},
		{`\#\{application\.evaluateExpressionGet`, "JBoss application.evaluateExpressionGet", ThreatLevelCritical},
		{`\#\{view\.getClass\(\)\}`, "JBoss view.getClass()", ThreatLevelCritical},
		{`\#\{view\.class.*?\}`, "JBoss view.class exploitation", ThreatLevelCritical},
		{`class.*?classLoader`, "JBoss class classLoader", ThreatLevelCritical},
		{`\.class\.forName`, "JBoss class.forName", ThreatLevelCritical},
	}

	for _, p := range jbossPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "JBoss EL: " + p.description,
				Recommendation: "Validate JBoss EL expressions; restrict sensitive object access",
			})
		}
	}
}

func (a *ExpressionAnalyzer) analyzeExpressionLanguageInjection(data string, result *AnalysisResult) {
	genericPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`expression\s*\(\s*["']`, "Expression language function call", ThreatLevelHigh},
		{`evaluate\s*\(\s*["']`, "Expression evaluate call", ThreatLevelHigh},
		{`eval\s*\(\s*["']`, "Expression eval call", ThreatLevelHigh},
		{`parseExpression\s*\(\s*["']`, "Expression parse call", ThreatLevelHigh},
		{`compileExpression\s*\(\s*["']`, "Expression compile call", ThreatLevelHigh},
		{`execute\s*\(\s*["']`, "Expression execute call", ThreatLevelHigh},
		{`run\s*\(\s*["']`, "Expression run call", ThreatLevelHigh},
		{`call\s*\(\s*["']`, "Expression call method", ThreatLevelMedium},
		{`apply\s*\(\s*["']`, "Expression apply call", ThreatLevelMedium},
		{`bind\s*\(\s*["']`, "Expression bind call", ThreatLevelMedium},
		{`import\s+.*?\.\*`, "Expression import all", ThreatLevelMedium},
		{`import\s+static`, "Expression static import", ThreatLevelMedium},
		{`static\s+import`, "Expression static import alternative", ThreatLevelMedium},
		{`\$+\{`, "Dollar-brace expression start", ThreatLevelMedium},
		{`\#+\{`, "Hash-brace expression start", ThreatLevelMedium},
		{`\%+\{`, "Percent-brace expression start", ThreatLevelMedium},
		{`\*\{`, "Star-brace expression start", ThreatLevelMedium},
		{`@\{.*?\}`, "At-brace expression", ThreatLevelMedium},
		{`\[\$`, "Bracket dollar expression", ThreatLevelMedium},
		{`\[\#`, "Bracket hash expression", ThreatLevelMedium},
		{`\$\[`, "Dollar bracket expression", ThreatLevelMedium},
		{`\#[`, "Hash bracket expression", ThreatLevelMedium},
		{`getAttribute\s*\(\s*["']`, "Attribute getter call", ThreatLevelMedium},
		{`setAttribute\s*\(\s*["']`, "Attribute setter call", ThreatLevelMedium},
		{`getParameter\s*\(\s*["']`, "Parameter getter", ThreatLevelMedium},
		{`getHeader\s*\(\s*["']`, "Header getter", ThreatLevelMedium},
		{`getCookie\s*\(\s*["']`, "Cookie getter", ThreatLevelMedium},
		{`getSession\s*\(\s*\)`, "Session getter", ThreatLevelHigh},
		{`getRequest\s*\(\s*\)`, "Request getter", ThreatLevelHigh},
		{`getResponse\s*\(\s*\)`, "Response getter", ThreatLevelHigh},
		{`getServletContext\s*\(\s*\)`, "ServletContext getter", ThreatLevelHigh},
		{`getContext\s*\(\s*\)`, "Context getter", ThreatLevelHigh},
		{`getClass\(\)\.classLoader`, "ClassLoader via getClass()", ThreatLevelCritical},
		{`class\.classLoader`, "ClassLoader via class", ThreatLevelCritical},
		{`class\.forName\(`, "Class.forName call", ThreatLevelCritical},
		{`\.forName\(.*?\)`, "forName call with args", ThreatLevelCritical},
		{`\.loadClass\(`, "ClassLoader.loadClass", ThreatLevelCritical},
		{`\.newInstance\(`, "Class.newInstance", ThreatLevelCritical},
		{`\.getDeclaredConstructor`, "getDeclaredConstructor call", ThreatLevelCritical},
		{`\.getDeclaredField`, "getDeclaredField call", ThreatLevelCritical},
		{`\.getMethod\(`, "getMethod call", ThreatLevelCritical},
		{`\.invoke\(`, "Reflection invoke call", ThreatLevelCritical},
		{`\.setAccessible`, "setAccessible call", ThreatLevelCritical},
		{`\.getField\(`, "getField call", ThreatLevelHigh},
		{`\.getResource\(`, "getResource call", ThreatLevelHigh},
		{`\.getResourceAsStream\(`, "getResourceAsStream call", ThreatLevelHigh},
		{`exec\s*\(\s*["']`, "exec call with string", ThreatLevelCritical},
		{`system\s*\(\s*["']`, "system call", ThreatLevelCritical},
		{`runtime\s*\.\s*exec`, "Runtime.exec call", ThreatLevelCritical},
		{`runtime\s*\.\s*getRuntime`, "Runtime.getRuntime call", ThreatLevelCritical},
		{`processBuilder\s*\(\s*\)`, "ProcessBuilder call", ThreatLevelCritical},
		{`processBuilder\.start`, "ProcessBuilder.start call", ThreatLevelCritical},
		{`java\.lang\.System`, "java.lang.System reference", ThreatLevelCritical},
		{`java\.lang\.Runtime`, "java.lang.Runtime reference", ThreatLevelCritical},
		{`java\.lang\.ProcessBuilder`, "java.lang.ProcessBuilder reference", ThreatLevelCritical},
		{`java\.lang\.Class`, "java.lang.Class reference", ThreatLevelCritical},
		{`java\.lang\.ClassLoader`, "java.lang.ClassLoader reference", ThreatLevelCritical},
		{`java\.lang\.reflect\.Method`, "java.lang.reflect.Method reference", ThreatLevelCritical},
		{`java\.lang\.reflect\.Field`, "java.lang.reflect.Field reference", ThreatLevelCritical},
		{`java\.lang\.reflect\.Constructor`, "java.lang.reflect.Constructor reference", ThreatLevelCritical},
		{`sun\.misc\.Unsafe`, "sun.misc.Unsafe reference", ThreatLevelCritical},
		{`sun\.reflect\.ReflectionFactory`, "sun.reflect.ReflectionFactory reference", ThreatLevelCritical},
		{`com\.sun\.jndi\.rmi\.registry`, "JNDI RMI registry reference", ThreatLevelCritical},
		{`com\.sun\.jndi\.ldap`, "JNDI LDAP reference", ThreatLevelCritical},
		{`javax\.naming\.Context`, "JNDI Context reference", ThreatLevelCritical},
		{`javax\.naming\.InitialContext`, "JNDI InitialContext reference", ThreatLevelCritical},
	}

	for _, p := range genericPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Expression Language Injection: " + p.description,
				Recommendation: "Validate expression input; disable dangerous operations",
			})
		}
	}
}
