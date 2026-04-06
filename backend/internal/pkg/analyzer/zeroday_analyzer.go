package analyzer

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

type ZeroDayAnalyzer struct {
	name         string
	version      string
	analyzerType string
	enabled      bool
	config       map[string]interface{}
	patterns     map[string]*regexp.Regexp
	mu           sync.RWMutex
}

func NewZeroDayAnalyzer() *ZeroDayAnalyzer {
	return &ZeroDayAnalyzer{
		name:         "zero_day_analyzer",
		version:      "1.0.0",
		analyzerType: "zero_day",
		enabled:      true,
		config:       make(map[string]interface{}),
		patterns:     make(map[string]*regexp.Regexp),
	}
}

func (a *ZeroDayAnalyzer) Name() string {
	return a.name
}

func (a *ZeroDayAnalyzer) Type() string {
	return a.analyzerType
}

func (a *ZeroDayAnalyzer) Version() string {
	return a.version
}

func (a *ZeroDayAnalyzer) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

func (a *ZeroDayAnalyzer) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

func (a *ZeroDayAnalyzer) Configure(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = config
	return nil
}

func (a *ZeroDayAnalyzer) Analyze(input *AnalysisInput) *AnalysisResult {
	start := time.Now()
	result := NewAnalysisResult(a)

	if input == nil || input.Raw == "" {
		return result
	}

	dataToAnalyze := a.prepareData(input)
	normalized := a.normalizeInput(dataToAnalyze)

	a.analyzeLog4jDetection(normalized, result)
	a.analyzeSpring4Shell(normalized, result)
	a.analyzeApacheZeroDay(normalized, result)
	a.analyzeExchangeVulnerabilities(normalized, result)
	a.analyzeOAVulnerabilities(normalized, result)
	a.analyzeThinkPHPVulnerability(normalized, result)
	a.analyzeECShopVulnerability(normalized, result)
	a.analyzeStrutsVulnerabilities(normalized, result)
	a.analyzeWordPressVulnerabilities(normalized, result)
	a.analyzeDrupalVulnerabilities(normalized, result)
	a.analyzeJoomlaVulnerabilities(normalized, result)
	a.analyzeAdobeVulnerabilities(normalized, result)
	a.analyzeWebLogicVulnerabilities(normalized, result)
	a.analyzeTomcatVulnerabilities(normalized, result)
	a.analyzeJBossVulnerabilities(normalized, result)
	a.analyzeWebSphereVulnerabilities(normalized, result)
	a.analyzeNodejsVulnerabilities(normalized, result)
	a.analyzePythonVulnerabilities(normalized, result)
	a.analyzeRubyVulnerabilities(normalized, result)
	a.analyzeJavaVulnerabilities(normalized, result)
	a.analyzeGoVulnerabilities(normalized, result)
	a.analyzeNetVulnerabilities(normalized, result)
	a.analyzePHPFrameworks(normalized, result)
	a.analyzeLaravelVulnerabilities(normalized, result)
	a.analyzeSymfonyVulnerabilities(normalized, result)
	a.analyzeCodeIgniterVulnerabilities(normalized, result)
	a.analyzeYiiVulnerabilities(normalized, result)
	a.analyzeCakePHPVulnerabilities(normalized, result)
	a.analyzeSymfonyRCE(normalized, result)
	a.analyzeLaravelDebugMode(normalized, result)

	result.ProcessingTime = time.Since(start)
	result.ShouldBlock = result.ShouldBlockRequest(0.6)
	if len(result.Matches) > 0 {
		result.ShouldLog = true
		result.ShouldAllow = !result.ShouldBlock
	}

	return result
}

func (a *ZeroDayAnalyzer) prepareData(input *AnalysisInput) string {
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

func (a *ZeroDayAnalyzer) normalizeInput(data string) string {
	data = strings.ToLower(data)
	data = a.decodeURLEncoding(data)
	data = a.decodeHexEncoding(data)
	data = a.decodeUnicodeEncoding(data)
	return data
}

func (a *ZeroDayAnalyzer) decodeURLEncoding(data string) string {
	pattern := regexp.MustCompile(`%([0-9a-fA-F]{2})`)
	return pattern.ReplaceAllStringFunc(data, func(match string) string {
		hex := match[1:]
		b := a.hexToByte(hex)
		return string(rune(b))
	})
}

func (a *ZeroDayAnalyzer) decodeHexEncoding(data string) string {
	pattern := regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	return pattern.ReplaceAllStringFunc(data, func(match string) string {
		hex := match[2:]
		b := a.hexToByte(hex)
		return string(rune(b))
	})
}

func (a *ZeroDayAnalyzer) decodeUnicodeEncoding(data string) string {
	pattern := regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
	return pattern.ReplaceAllStringFunc(data, func(match string) string {
		hex := match[2:]
		b1 := a.hexToByte(hex[:2])
		b2 := a.hexToByte(hex[2:])
		return string(rune(int(b1)<<8 | int(b2)))
	})
}

func (a *ZeroDayAnalyzer) hexToByte(s string) byte {
	var result byte
	for _, c := range s {
		result *= 16
		switch {
		case c >= '0' && c <= '9':
			result += byte(c - '0')
		case c >= 'a' && c <= 'f':
			result += byte(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			result += byte(c - 'A' + 10)
		}
	}
	return result
}

func (a *ZeroDayAnalyzer) analyzeLog4jDetection(data string, result *AnalysisResult) {
	log4jPatterns := []struct {
		pattern     string
		description string
		cve         string
		threatLevel ThreatLevel
	}{
		{`\$\{jndi:`, "JNDI注入 - Log4Shell (CVE-2021-44228)", "CVE-2021-44228", ThreatLevelCritical},
		{`\$\{jndi:ldap`, "JNDI LDAP注入 - Log4Shell", "CVE-2021-44228", ThreatLevelCritical},
		{`\$\{jndi:rmi`, "JNDI RMI注入 - Log4Shell", "CVE-2021-44228", ThreatLevelCritical},
		{`\$\{jndi:dns`, "JNDI DNS注入 - Log4Shell", "CVE-2021-44228", ThreatLevelCritical},
		{`\$\{jndi:iiop`, "JNDI IIOP注入 - Log4Shell", "CVE-2021-44228", ThreatLevelCritical},
		{`\$\{jndi:nis`, "JNDI NIS注入 - Log4Shell", "CVE-2021-44228", ThreatLevelCritical},
		{`\$\{jndi:nis史诗`, "JNDI NIS注入 - Log4Shell", "CVE-2021-44228", ThreatLevelCritical},
		{`\$\{lower:`, "Log4j Lower变量插值", "CVE-2021-44228", ThreatLevelHigh},
		{`\$\{upper:`, "Log4j Upper变量插值", "CVE-2021-44228", ThreatLevelHigh},
		{`\$\{env:`, "Log4j环境变量注入", "CVE-2021-44228", ThreatLevelHigh},
		{`\$\{ctx:`, "Log4j上下文注入", "CVE-2021-44228", ThreatLevelHigh},
		{`\$\{map:`, "Log4j Map注入", "CVE-2021-44228", ThreatLevelHigh},
		{`\$\{event:`, "Log4j事件注入", "CVE-2021-45046", ThreatLevelHigh},
		{`\$\{marker:`, "Log4j标记注入", "CVE-2021-45046", ThreatLevelHigh},
		{`log4j`, "Log4j库引用", "CVE-2021-44228", ThreatLevelMedium},
		{`org\.apache\.log4j`, "Log4j包引用", "CVE-2021-44228", ThreatLevelMedium},
		{`\$\{::-`, "Log4j空操作前缀绕过", "CVE-2021-45046", ThreatLevelCritical},
		{`\$\{jndi:ldap://`, "JNDI LDAP协议利用", "CVE-2021-44228", ThreatLevelCritical},
		{`\$\{jndi:rmi://`, "JNDI RMI协议利用", "CVE-2021-44228", ThreatLevelCritical},
		{`\$\{jndi:ldaps://`, "JNDI LDAPS协议利用", "CVE-2021-44228", ThreatLevelCritical},
		{`\$\{jndi:nis://`, "JNDI NIS协议利用", "CVE-2021-44228", ThreatLevelCritical},
		{`\$\{jndi:iiop://`, "JNDI IIOP协议利用", "CVE-2021-44228", ThreatLevelCritical},
		{`\$\{bundle:`, "Log4j Bundle注入", "CVE-2021-45046", ThreatLevelHigh},
		{`\$\{config:`, "Log4j配置注入", "CVE-2021-45046", ThreatLevelHigh},
	}

	for _, p := range log4jPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       p.cve,
				Recommendation: "立即升级Log4j到2.17.0+;禁用JNDI lookup",
			})
		}
	}
}

func (a *ZeroDayAnalyzer) analyzeSpring4Shell(data string, result *AnalysisResult) {
	spring4shellPatterns := []struct {
		pattern     string
		description string
		cve         string
		threatLevel ThreatLevel
	}{
		{`class\.module\.classLoader\.`, "Spring4Shell - ClassLoader操控", "CVE-2022-22965", ThreatLevelCritical},
		{`class\.module\.resources`, "Spring4Shell - Resources操控", "CVE-2022-22965", ThreatLevelCritical},
		{`class\.module\.classLoader\.url`, "Spring4Shell - ClassLoader URL注入", "CVE-2022-22965", ThreatLevelCritical},
		{`tomcat\.war`, "Spring4Shell - Tomcat WAR部署", "CVE-2022-22965", ThreatLevelCritical},
		{`org\.apache\.catalina`, "Spring4Shell - Tomcat连接器", "CVE-2022-22965", ThreatLevelHigh},
		{`org\.springframework\.web`, "Spring Framework引用", "CVE-2022-22965", ThreatLevelMedium},
		{`WebMvc`, "Spring WebMvc配置", "CVE-2022-22965", ThreatLevelMedium},
		{`@RestController`, "Spring REST控制器", "CVE-2022-22965", ThreatLevelMedium},
		{`classLoader\.resources`, "Spring4Shell - 资源操作", "CVE-2022-22965", ThreatLevelCritical},
		{`paramName`, "Spring4Shell - 参数名注入", "CVE-2022-22965", ThreatLevelCritical},
		{`suffix:`, "Spring4Shell - 模板后缀注入", "CVE-2022-22965", ThreatLevelHigh},
		{`class.module.classLoader`, "Spring4Shell漏洞利用", "CVE-2022-22965", ThreatLevelCritical},
		{`Runtime\.getRuntime`, "Java运行时执行", "CVE-2022-22965", ThreatLevelCritical},
		{`ProcessBuilder`, "ProcessBuilder命令执行", "CVE-2022-22965", ThreatLevelCritical},
		{`jakarta\. servlet`, "Jakarta Servlet引用", "CVE-2022-22965", ThreatLevelHigh},
		{`org\.apache\.tomee`, "Apache TomEE引用", "CVE-2022-22965", ThreatLevelMedium},
		{`spring\.web`, "Spring Boot Web依赖", "CVE-2022-22965", ThreatLevelMedium},
	}

	for _, p := range spring4shellPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       p.cve,
				Recommendation: "升级Spring Framework到5.3.18+或5.2.20+",
			})
		}
	}
}

func (a *ZeroDayAnalyzer) analyzeApacheZeroDay(data string, result *AnalysisResult) {
	apachePatterns := []struct {
		pattern     string
		description string
		cve         string
		threatLevel ThreatLevel
	}{
		{`CVE-2021-41773`, "Apache HTTPd路径穿越", "CVE-2021-41773", ThreatLevelHigh},
		{`CVE-2021-42013`, "Apache HTTPd路径穿越", "CVE-2021-42013", ThreatLevelCritical},
		{`/cgi-bin/.%2e/.%2e/.%2e/.%2e/`, "Apache路径穿越Payload", "CVE-2021-41773", ThreatLevelCritical},
		{`/icons/.%2e/.%2e/.%2e/.%2e/etc/passwd`, "Apache读取/etc/passwd", "CVE-2021-41773", ThreatLevelCritical},
		{`/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd`, "Apache CGI读取passwd", "CVE-2021-42013", ThreatLevelCritical},
		{`/cgi-bin/.%2e/.%2e/.%2e/.%2e/`, "Apache CGI路径穿越", "CVE-2021-42013", ThreatLevelCritical},
		{`mod_proxy`, "Apache代理模块", "CVE-2021-40438", ThreatLevelHigh},
		{`/admin/`, "Apache管理接口", "CVE-2021-41773", ThreatLevelMedium},
		{`\.htaccess`, "Apache htaccess配置", "CVE-2021-41773", ThreatLevelMedium},
		{`httpd\.conf`, "Apache配置文件", "CVE-2021-41773", ThreatLevelMedium},
	}

	for _, p := range apachePatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       p.cve,
				Recommendation: "升级Apache HTTP Server到最新版本",
			})
		}
	}
}

func (a *ZeroDayAnalyzer) analyzeExchangeVulnerabilities(data string, result *AnalysisResult) {
	exchangePatterns := []struct {
		pattern     string
		description string
		cve         string
		threatLevel ThreatLevel
	}{
		{`CVE-2021-26855`, "Exchange SSRF漏洞", "CVE-2021-26855", ThreatLevelCritical},
		{`CVE-2021-26857`, "Exchange反序列化漏洞", "CVE-2021-26857", ThreatLevelCritical},
		{`CVE-2021-26858`, "Exchange文件写入漏洞", "CVE-2021-26858", ThreatLevelCritical},
		{`CVE-2021-27065`, "Exchange远程代码执行", "CVE-2021-27065", ThreatLevelCritical},
		{`CVE-2022-41040`, "Exchange SSRF", "CVE-2022-41040", ThreatLevelHigh},
		{`CVE-2022-41082`, "Exchange RCE", "CVE-2022-41082", ThreatLevelCritical},
		{`/owa/auth/logon\.aspx`, "Outlook Web Access", "CVE-2021-26855", ThreatLevelMedium},
		{`/ecp/DDI/DDIService\.svc`, "Exchange控制面板API", "CVE-2021-26855", ThreatLevelHigh},
		{`X-Anchormailbox:`, "Exchange邮箱头注入", "CVE-2021-26855", ThreatLevelHigh},
		{`/mapi/nspi/`, "MAPI协议端点", "CVE-2021-26855", ThreatLevelMedium},
		{`/autodiscover/autodiscover\.json`, "自动发现服务", "CVE-2021-26855", ThreatLevelMedium},
		{`/powershell`, "PowerShell远程", "CVE-2022-41082", ThreatLevelHigh},
	}

	for _, p := range exchangePatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       p.cve,
				Recommendation: "立即修补Exchange漏洞",
			})
		}
	}
}

func (a *ZeroDayAnalyzer) analyzeOAVulnerabilities(data string, result *AnalysisResult) {
	oaPatterns := []struct {
		pattern     string
		description string
		cve         string
		threatLevel ThreatLevel
	}{
		{`致远OA`, "致远OA检测", "CVE-2021--browser-1", ThreatLevelMedium},
		{`seeyon`, "致远OA标识", "CVE-2021-26539", ThreatLevelMedium},
		{`/seeyon/`, "致远OA路径", "CVE-2021-26539", ThreatLevelHigh},
		{`/seeyon/ajax\.do`, "致远OA AJAX注入", "CVE-2021-26539", ThreatLevelHigh},
		{`/seeyon/qlb\.x`, "致远OA qlb接口", "CVE-2021-26539", ThreatLevelHigh},
		{`泛微OA`, "泛微OA检测", "CVE-2021-26539", ThreatLevelMedium},
		{`weaver`, "泛微OA标识", "CVE-2021-26539", ThreatLevelMedium},
		{`/weaver/`, "泛微OA路径", "CVE-2021-26539", ThreatLevelHigh},
		{`用友NC`, "用友NC检测", "CVE-2021-26539", ThreatLevelMedium},
		{`yonyou`, "用友标识", "CVE-2021-26539", ThreatLevelMedium},
		{`/uapws/`, "用友UAPWS接口", "CVE-2021-26539", ThreatLevelHigh},
		{`通达OA`, "通达OA检测", "CVE-2021-26539", ThreatLevelMedium},
		{`Tongda`, "通达OA标识", "CVE-2021-26539", ThreatLevelMedium},
		{`/tda/`, "通达OA路径", "CVE-2021-26539", ThreatLevelHigh},
		{`蓝凌OA`, "蓝凌OA检测", "CVE-2021-26539", ThreatLevelMedium},
		{`landray`, "蓝凌标识", "CVE-2021-26539", ThreatLevelMedium},
		{`/landray/`, "蓝凌OA路径", "CVE-2021-26539", ThreatLevelHigh},
		{`CVE-2021-26539`, "OA系统JNDI注入", "CVE-2021-26539", ThreatLevelCritical},
	}

	for _, p := range oaPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       p.cve,
				Recommendation: "修补OA系统漏洞",
			})
		}
	}
}

func (a *ZeroDayAnalyzer) analyzeThinkPHPVulnerability(data string, result *AnalysisResult) {
	thinkphpPatterns := []struct {
		pattern     string
		description string
		cve         string
		threatLevel ThreatLevel
	}{
		{`ThinkPHP`, "ThinkPHP框架检测", "CVE-2021-26539", ThreatLevelMedium},
		{`thinkphp`, "ThinkPHP标识", "CVE-2021-26539", ThreatLevelMedium},
		{`/thinkphp/`, "ThinkPHP路径", "CVE-2018-16362", ThreatLevelHigh},
		{`/thinkphp/public/`, "ThinkPHP公开路径", "CVE-2018-16362", ThreatLevelMedium},
		{`__construct`, "ThinkPHP构造函数方法调用", "CVE-2018-16362", ThreatLevelHigh},
		{`method=`, "ThinkPHP method参数", "CVE-2018-16362", ThreatLevelHigh},
		{`filter=`, "ThinkPHP filter参数", "CVE-2018-16362", ThreatLevelHigh},
		{`var_method=`, "ThinkPHP方法变量", "CVE-2019-9082", ThreatLevelHigh},
		{`var_pathinfo`, "ThinkPHP路径信息变量", "CVE-2018-20062", ThreatLevelHigh},
		{`s=`, "ThinkPHP路由变量", "CVE-2018-20062", ThreatLevelHigh},
		{`c=`, "ThinkPHP控制器变量", "CVE-2018-20062", ThreatLevelHigh},
		{`f=`, "ThinkPHP函数变量", "CVE-2018-20062", ThreatLevelHigh},
		{`/index/\w+/`, "ThinkPHP Index路由", "CVE-2018-20062", ThreatLevelMedium},
		{`\x5C`, "ThinkPHP反序列化", "CVE-2019-9082", ThreatLevelCritical},
		{`CVE-2018-16362`, "ThinkPHP < 5.0.23 RCE", "CVE-2018-16362", ThreatLevelCritical},
		{`CVE-2018-20062`, "ThinkPHP < 5.1.31 RCE", "CVE-2018-20062", ThreatLevelCritical},
		{`CVE-2019-9082`, "ThinkPHP < 5.0.24 RCE", "CVE-2019-9082", ThreatLevelCritical},
	}

	for _, p := range thinkphpPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       p.cve,
				Recommendation: "升级ThinkPHP到最新稳定版",
			})
		}
	}
}

func (a *ZeroDayAnalyzer) analyzeECShopVulnerability(data string, result *AnalysisResult) {
	ecshopPatterns := []struct {
		pattern     string
		description string
		cve         string
		threatLevel ThreatLevel
	}{
		{`ECShop`, "ECShop检测", "CVE-2021-26539", ThreatLevelMedium},
		{`ecshop`, "ECShop标识", "CVE-2021-26539", ThreatLevelMedium},
		{`/ecshop/`, "ECShop路径", "CVE-2021-26539", ThreatLevelHigh},
		{`/user\.php`, "ECShop用户模块", "CVE-2021-26539", ThreatLevelMedium},
		{`/flow\.php`, "ECShop流程模块", "CVE-2021-26539", ThreatLevelMedium},
		{`/category\.php`, "ECShop分类模块", "CVE-2021-26539", ThreatLevelMedium},
		{`referer`, "ECShop Referer注入", "CVE-2021-26539", ThreatLevelHigh},
		{`CVE-2021-26539`, "ECShop JNDI注入", "CVE-2021-26539", ThreatLevelCritical},
		{`sql_exercises`, "ECShop SQL注入", "CVE-2018-1273", ThreatLevelCritical},
		{`/api/`, "ECShop API路径", "CVE-2021-26539", ThreatLevelHigh},
	}

	for _, p := range ecshopPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       p.cve,
				Recommendation: "修补ECShop漏洞",
			})
		}
	}
}

func (a *ZeroDayAnalyzer) analyzeStrutsVulnerabilities(data string, result *AnalysisResult) {
	strutsPatterns := []struct {
		pattern     string
		description string
		cve         string
		threatLevel ThreatLevel
	}{
		{`CVE-2017-5638`, "Apache Struts S2-045 RCE", "CVE-2017-5638", ThreatLevelCritical},
		{`CVE-2018-11776`, "Apache Struts S2-057 RCE", "CVE-2018-11776", ThreatLevelCritical},
		{`CVE-2020-17530`, "Apache Struts RCE", "CVE-2020-17530", ThreatLevelCritical},
		{`Content-Type.*%{#`, "Struts OGNL注入", "CVE-2017-5638", ThreatLevelCritical},
		{`%{.*}`, "Struts OGNL表达式", "CVE-2017-5638", ThreatLevelCritical},
		{`\$\{.*\}`, "Struts OGNL变量", "CVE-2017-5638", ThreatLevelCritical},
		{`#_memberAccess`, "Struts权限绕过", "CVE-2018-11776", ThreatLevelHigh},
		{`#context`, "Struts上下文访问", "CVE-2017-5638", ThreatLevelCritical},
		{`#_driver_manager`, "Struts数据库驱动", "CVE-2017-5638", ThreatLevelCritical},
		{`#_Session`, "Struts会话访问", "CVE-2017-5638", ThreatLevelHigh},
		{`#_request`, "Struts请求访问", "CVE-2017-5638", ThreatLevelHigh},
		{`#_parameters`, "Struts参数访问", "CVE-2017-5638", ThreatLevelHigh},
		{`@org\.apache\.struts2`, "Struts2包引用", "CVE-2017-5638", ThreatLevelMedium},
		{`struts2-core`, "Struts2核心库", "CVE-2017-5638", ThreatLevelMedium},
		{`Content-Disposition.*filename`, "Struts文件上传", "CVE-2018-11776", ThreatLevelHigh},
	}

	for _, p := range strutsPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       p.cve,
				Recommendation: "升级Apache Struts到最新版本",
			})
		}
	}
}

func (a *ZeroDayAnalyzer) analyzeWordPressVulnerabilities(data string, result *AnalysisResult) {
	wpPatterns := []struct {
		pattern     string
		description string
		cve         string
		threatLevel ThreatLevel
	}{
		{`wp-admin`, "WordPress管理后台", "CVE-2021-26539", ThreatLevelMedium},
		{`wp-login\.php`, "WordPress登录页", "CVE-2021-26539", ThreatLevelMedium},
		{`wp-config\.php`, "WordPress配置文件", "CVE-2021-26539", ThreatLevelHigh},
		{`wp-content/uploads`, "WordPress上传目录", "CVE-2021-26539", ThreatLevelMedium},
		{`/wp-json/wp/v1/`, "WordPress REST API", "CVE-2021-26539", ThreatLevelMedium},
		{`/wp-json/`, "WordPress JSON API", "CVE-2021-26539", ThreatLevelLow},
		{`/xmlrpc\.php`, "WordPress XML-RPC", "CVE-2021-26539", ThreatLevelMedium},
		{`/wp-login\.php?action=register`, "WordPress用户注册", "CVE-2021-26539", ThreatLevelMedium},
		{`wp-includes/`, "WordPress核心文件", "CVE-2021-26539", ThreatLevelLow},
		{`wordpress_logged_in`, "WordPress会话Cookie", "CVE-2021-26539", ThreatLevelMedium},
		{`akismet`, "WordPress Akismet插件", "CVE-2021-26539", ThreatLevelLow},
		{`woocommerce`, "WooCommerce插件", "CVE-2021-26539", ThreatLevelMedium},
		{`CVE-2021-26539`, "WordPress JNDI注入", "CVE-2021-26539", ThreatLevelCritical},
		{`CVE-2021-29447`, "WordPress Media Library XXE", "CVE-2021-29447", ThreatLevelHigh},
		{`CVE-2021-29446`, "WordPress Audio HTML5 XSS", "CVE-2021-29446", ThreatLevelMedium},
	}

	for _, p := range wpPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       p.cve,
				Recommendation: "升级WordPress及插件",
			})
		}
	}
}

func (a *ZeroDayAnalyzer) analyzeDrupalVulnerabilities(data string, result *AnalysisResult) {
	drupalPatterns := []struct {
		pattern     string
		description string
		cve         string
		threatLevel ThreatLevel
	}{
		{`drupal`, "Drupal CMS检测", "CVE-2021-26539", ThreatLevelMedium},
		{`/user/login`, "Drupal用户登录", "CVE-2021-26539", ThreatLevelMedium},
		{`/node/add`, "Drupal内容创建", "CVE-2021-26539", ThreatLevelMedium},
		{`/admin/`, "Drupal管理后台", "CVE-2021-26539", ThreatLevelMedium},
		{`/api/`, "Drupal API路径", "CVE-2021-26539", ThreatLevelMedium},
		{`drupalSettings`, "Drupal客户端配置", "CVE-2021-26539", ThreatLevelLow},
		{`CVE-2018-7600`, "Drupalgeddon2 RCE", "CVE-2018-7600", ThreatLevelCritical},
		{`CVE-2018-7602`, "Drupalgeddon3 RCE", "CVE-2018-7602", ThreatLevelCritical},
		{`CVE-2019-6340`, "Drupal REST RCE", "CVE-2019-6340", ThreatLevelCritical},
		{`CVE-2020-28949`, "Drupal Cache RCE", "CVE-2020-28949", ThreatLevelHigh},
		{`CVE-2021-26539`, "Drupal JNDI注入", "CVE-2021-26539", ThreatLevelCritical},
		{`_drupal_exception`, "Drupal异常处理", "CVE-2018-7600", ThreatLevelHigh},
		{`webform`, "Drupal Webform模块", "CVE-2021-26539", ThreatLevelMedium},
	}

	for _, p := range drupalPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       p.cve,
				Recommendation: "升级Drupal到最新版本",
			})
		}
	}
}

func (a *ZeroDayAnalyzer) analyzeJoomlaVulnerabilities(data string, result *AnalysisResult) {
	joomlaPatterns := []struct {
		pattern     string
		description string
		cve         string
		threatLevel ThreatLevel
	}{
		{`joomla`, "Joomla CMS检测", "CVE-2021-26539", ThreatLevelMedium},
		{`/administrator/`, "Joomla管理后台", "CVE-2021-26539", ThreatLevelMedium},
		{`option=com_`, "Joomla组件参数", "CVE-2021-26539", ThreatLevelMedium},
		{`/index\.php\?option=com_`, "Joomla组件访问", "CVE-2021-26539", ThreatLevelMedium},
		{`CVE-2015-8562`, "Joomla RCE", "CVE-2015-8562", ThreatLevelCritical},
		{`CVE-2017-8917`, "Joomla SQL注入", "CVE-2017-8917", ThreatLevelCritical},
		{`CVE-2021-26539`, "Joomla JNDI注入", "CVE-2021-26539", ThreatLevelCritical},
		{`X-Forwarded-For.*\d+\.\d+\.\d+\.\d+`, "Joomla IP欺骗", "CVE-2015-8562", ThreatLevelMedium},
		{`user-agent.*joomla`, "Joomla用户代理", "CVE-2015-8562", ThreatLevelMedium},
		{`JMS::`, "Joomla数据库注入", "CVE-2017-8917", ThreatLevelHigh},
	}

	for _, p := range joomlaPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       p.cve,
				Recommendation: "升级Joomla到最新版本",
			})
		}
	}
}

func (a *ZeroDayAnalyzer) analyzeAdobeVulnerabilities(data string, result *AnalysisResult) {
	adobePatterns := []struct {
		pattern     string
		description string
		cve         string
		threatLevel ThreatLevel
	}{
		{`Adobe Experience Manager`, "Adobe AEM检测", "CVE-2021-26539", ThreatLevelMedium},
		{`aem`, "AEM标识", "CVE-2021-26539", ThreatLevelMedium},
		{`/content/\.form`, "AEM表单路径", "CVE-2021-26539", ThreatLevelHigh},
		{`/content/dam/`, "AEM数字资产", "CVE-2021-26539", ThreatLevelMedium},
		{`/bin/querybuilder`, "AEM查询构建器", "CVE-2021-26539", ThreatLevelHigh},
		{`/crx/de`, "AEM CRXDE Lite", "CVE-2021-26539", ThreatLevelHigh},
		{`/system/console`, "AEM控制台", "CVE-2021-26539", ThreatLevelHigh},
		{`CVE-2021-26539`, "AEM JNDI注入", "CVE-2021-26539", ThreatLevelCritical},
		{`CVE-2021-40646`, "AEM RCE", "CVE-2021-40646", ThreatLevelCritical},
		{`CVE-2022-28840`, "AEM RCE", "CVE-2022-28840", ThreatLevelCritical},
	}

	for _, p := range adobePatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       p.cve,
				Recommendation: "升级Adobe AEM到最新修补版本",
			})
		}
	}
}

func (a *ZeroDayAnalyzer) analyzeWebLogicVulnerabilities(data string, result *AnalysisResult) {
	weblogicPatterns := []struct {
		pattern     string
		description string
		cve         string
		threatLevel ThreatLevel
	}{
		{`WebLogic`, "WebLogic服务器检测", "CVE-2021-26539", ThreatLevelMedium},
		{`weblogic`, "WebLogic标识", "CVE-2021-26539", ThreatLevelMedium},
		{`/console/`, "WebLogic控制台", "CVE-2021-26539", ThreatLevelHigh},
		{`/uddiexplorer/`, "WebLogic UDDI", "CVE-2021-26539", ThreatLevelMedium},
		{`/wls-wsat/`, "WebLogic WLS-AT", "CVE-2017-10271", ThreatLevelCritical},
		{`/async/`, "WebLogic异步服务", "CVE-2019-2725", ThreatLevelCritical},
		{`CVE-2017-10271`, "WebLogic XMLDecoder RCE", "CVE-2017-10271", ThreatLevelCritical},
		{`CVE-2019-2725`, "WebLogic反序列化RCE", "CVE-2019-2725", ThreatLevelCritical},
		{`CVE-2019-2729`, "WebLogic反序列化RCE", "CVE-2019-2729", ThreatLevelCritical},
		{`CVE-2020-2551`, "WebLogic IIOP RCE", "CVE-2020-2551", ThreatLevelCritical},
		{`CVE-2020-2555`, "WebLogic T3 RCE", "CVE-2020-2555", ThreatLevelCritical},
		{`CVE-2021-26539`, "WebLogic JNDI注入", "CVE-2021-26539", ThreatLevelCritical},
		{`bea_wls`, "WebLogic会话", "CVE-2017-10271", ThreatLevelHigh},
		{`wls-wsat`, "WebLogic WLS-AT服务", "CVE-2017-10271", ThreatLevelCritical},
	}

	for _, p := range weblogicPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       p.cve,
				Recommendation: "修补WebLogic漏洞",
			})
		}
	}
}

func (a *ZeroDayAnalyzer) analyzeTomcatVulnerabilities(data string, result *AnalysisResult) {
	tomcatPatterns := []struct {
		pattern     string
		description string
		cve         string
		threatLevel ThreatLevel
	}{
		{`Apache Tomcat`, "Apache Tomcat检测", "CVE-2021-26539", ThreatLevelMedium},
		{`tomcat`, "Tomcat标识", "CVE-2021-26539", ThreatLevelMedium},
		{`/manager/html`, "Tomcat管理接口", "CVE-2021-26539", ThreatLevelHigh},
		{`/host-manager/html`, "Tomcat主机管理", "CVE-2021-26539", ThreatLevelHigh},
		{`/examples/`, "Tomcat示例应用", "CVE-2021-26539", ThreatLevelMedium},
		{`/docs/`, "Tomcat文档路径", "CVE-2021-26539", ThreatLevelLow},
		{`CVE-2020-1938`, "Tomcat Ghostcat", "CVE-2020-1938", ThreatLevelCritical},
		{`CVE-2019-0232`, "Tomcat RCE", "CVE-2019-0232", ThreatLevelCritical},
		{`CVE-2019-12418`, "Tomcat反序列化", "CVE-2019-12418", ThreatLevelHigh},
		{`CVE-2021-26539`, "Tomcat JNDI注入", "CVE-2021-26539", ThreatLevelCritical},
		{`ajp://`, "Tomcat AJP协议", "CVE-2020-1938", ThreatLevelHigh},
		{`/WEB-INF/web\.xml`, "Tomcat WEB-INF配置", "CVE-2021-26539", ThreatLevelMedium},
		{`/WEB-INF/classes/`, "Tomcat类路径", "CVE-2021-26539", ThreatLevelMedium},
	}

	for _, p := range tomcatPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       p.cve,
				Recommendation: "升级Tomcat到最新版本",
			})
		}
	}
}

func (a *ZeroDayAnalyzer) analyzeJBossVulnerabilities(data string, result *AnalysisResult) {
	jbossPatterns := []struct {
		pattern     string
		description string
		cve         string
		threatLevel ThreatLevel
	}{
		{`JBoss`, "JBoss应用服务器检测", "CVE-2021-26539", ThreatLevelMedium},
		{`jboss`, "JBoss标识", "CVE-2021-26539", ThreatLevelMedium},
		{`/jmx-console/`, "JBoss JMX控制台", "CVE-2021-26539", ThreatLevelHigh},
		{`/web-console/`, "JBoss Web控制台", "CVE-2021-26539", ThreatLevelHigh},
		{`/console/`, "JBoss管理控制台", "CVE-2021-26539", ThreatLevelHigh},
		{`/admin-console/`, "JBoss管理后台", "CVE-2021-26539", ThreatLevelHigh},
		{`/invoker/`, "JBoss JMX Invoker", "CVE-2017-12149", ThreatLevelCritical},
		{`/jndi/`, "JBoss JNDI", "CVE-2021-26539", ThreatLevelHigh},
		{`CVE-2017-12149`, "JBoss反序列化RCE", "CVE-2017-12149", ThreatLevelCritical},
		{`CVE-2021-26539`, "JBoss JNDI注入", "CVE-2021-26539", ThreatLevelCritical},
		{`/ SeamPrint`, "JBoss Seam打印", "CVE-2017-12149", ThreatLevelHigh},
		{`/exec/createDeployment`, "JBoss部署创建", "CVE-2017-12149", ThreatLevelCritical},
	}

	for _, p := range jbossPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       p.cve,
				Recommendation: "修补JBoss漏洞",
			})
		}
	}
}

func (a *ZeroDayAnalyzer) analyzeWebSphereVulnerabilities(data string, result *AnalysisResult) {
	webspherePatterns := []struct {
		pattern     string
		description string
		cve         string
		threatLevel ThreatLevel
	}{
		{`WebSphere`, "IBM WebSphere检测", "CVE-2021-26539", ThreatLevelMedium},
		{`websphere`, "WebSphere标识", "CVE-2021-26539", ThreatLevelMedium},
		{`/IBM/`, "WebSphere路径", "CVE-2021-26539", ThreatLevelMedium},
		{`/admin/`, "WebSphere管理", "CVE-2021-26539", ThreatLevelHigh},
		{`/manager/`, "WebSphere管理器", "CVE-2021-26539", ThreatLevelHigh},
		{`/servers/`, "WebSphere服务器", "CVE-2021-26539", ThreatLevelMedium},
		{`CVE-2020-4276`, "WebSphere RCE", "CVE-2020-4276", ThreatLevelCritical},
		{`CVE-2020-4362`, "WebSphere RCE", "CVE-2020-4362", ThreatLevelCritical},
		{`CVE-2021-26539`, "WebSphere JNDI注入", "CVE-2021-26539", ThreatLevelCritical},
		{`CVE-2019-4279`, "WebSphere远程代码执行", "CVE-2019-4279", ThreatLevelCritical},
		{`SOAPConnector`, "WebSphere SOAP连接", "CVE-2020-4276", ThreatLevelHigh},
	}

	for _, p := range webspherePatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       p.cve,
				Recommendation: "修补WebSphere漏洞",
			})
		}
	}
}

func (a *ZeroDayAnalyzer) analyzeNodejsVulnerabilities(data string, result *AnalysisResult) {
	nodejsPatterns := []struct {
		pattern     string
		description string
		cve         string
		threatLevel ThreatLevel
	}{
		{`node_modules`, "Node.js模块目录", "CVE-2021-26539", ThreatLevelLow},
		{`package\.json`, "Node.js包配置", "CVE-2021-26539", ThreatLevelLow},
		{`CVE-2021-23337`, "Node.js命令注入", "CVE-2021-23337", ThreatLevelHigh},
		{`CVE-2021-32640`, "Node.js Prototype Pollution", "CVE-2021-32640", ThreatLevelHigh},
		{`CVE-2021-23343`, "Node.js lodash命令注入", "CVE-2021-23343", ThreatLevelHigh},
		{`CVE-2020-8203`, "Node.js lodash Prototype Pollution", "CVE-2020-8203", ThreatLevelHigh},
		{`CVE-2019-10744`, "Node.js lodash Prototype Pollution", "CVE-2019-10744", ThreatLevelCritical},
		{`prototype`, "JavaScript原型链", "CVE-2019-10744", ThreatLevelMedium},
		{`__proto__`, "Prototype污染向量", "CVE-2019-10744", ThreatLevelHigh},
		{`constructor`, "构造函数引用", "CVE-2019-10744", ThreatLevelMedium},
		{`child_process`, "Node.js子进程", "CVE-2021-23337", ThreatLevelHigh},
		{`require\s*\(\s*['\x27]child_process`, "child_process引用", "CVE-2021-23337", ThreatLevelHigh},
		{`\bexec\s*\(`, "Node.js exec调用", "CVE-2021-23337", ThreatLevelHigh},
		{`\bspawn\s*\(`, "Node.js spawn调用", "CVE-2021-23337", ThreatLevelHigh},
	}

	for _, p := range nodejsPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       p.cve,
				Recommendation: "升级Node.js依赖包",
			})
		}
	}
}

func (a *ZeroDayAnalyzer) analyzePythonVulnerabilities(data string, result *AnalysisResult) {
	pythonPatterns := []struct {
		pattern     string
		description string
		cve         string
		threatLevel ThreatLevel
	}{
		{`CVE-2021-32708`, "Python aiohttp HTTP断行注入", "CVE-2021-32708", ThreatLevelHigh},
		{`CVE-2021-29921`, "Python ipaddress模块处理", "CVE-2021-29921", ThreatLevelMedium},
		{`CVE-2021-3737`, "Python http请求走私", "CVE-2021-3737", ThreatLevelHigh},
		{`CVE-2022-0391`, "Python asyncio SSL漏洞", "CVE-2022-0391", ThreatLevelHigh},
		{`__import__`, "Python动态导入", "CVE-2021-23337", ThreatLevelHigh},
		{`importlib`, "Python导入库", "CVE-2021-23337", ThreatLevelMedium},
		{`pickle\.loads`, "Python pickle反序列化", "CVE-2021-23337", ThreatLevelCritical},
		{`yaml\.load`, "Python YAML反序列化", "CVE-2021-23337", ThreatLevelCritical},
		{`eval\s*\(`, "Python eval调用", "CVE-2021-23337", ThreatLevelCritical},
		{`exec\s*\(`, "Python exec调用", "CVE-2021-23337", ThreatLevelCritical},
		{`os\.system`, "Python OS命令执行", "CVE-2021-23337", ThreatLevelCritical},
		{`subprocess\.call`, "Python子进程调用", "CVE-2021-23337", ThreatLevelHigh},
		{`urllib\.open`, "Python URL打开", "CVE-2021-32708", ThreatLevelMedium},
		{`Flask`, "Flask框架检测", "CVE-2021-23337", ThreatLevelMedium},
		{`Django`, "Django框架检测", "CVE-2021-23337", ThreatLevelMedium},
		{`CVE-2021-44420`, "Django RCE", "CVE-2021-44420", ThreatLevelCritical},
	}

	for _, p := range pythonPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       p.cve,
				Recommendation: "升级Python库和框架",
			})
		}
	}
}

func (a *ZeroDayAnalyzer) analyzeRubyVulnerabilities(data string, result *AnalysisResult) {
	rubyPatterns := []struct {
		pattern     string
		description string
		cve         string
		threatLevel ThreatLevel
	}{
		{`CVE-2020-8163`, "Ruby on Rails CSRF Token forgery", "CVE-2020-8163", ThreatLevelHigh},
		{`CVE-2020-8164`, "Ruby on Rails代码执行", "CVE-2020-8164", ThreatLevelCritical},
		{`CVE-2020-8165`, "Ruby on Rails文件遍历", "CVE-2020-8165", ThreatLevelHigh},
		{`CVE-2020-8166`, "Ruby on Rails SQL注入", "CVE-2020-8166", ThreatLevelCritical},
		{`CVE-2022-23634`, "Ruby on Rails RCE", "CVE-2022-23634", ThreatLevelCritical},
		{`render\s+.*\.json`, "Rails JSON渲染", "CVE-2020-8163", ThreatLevelMedium},
		{`render\s+.*\.xml`, "Rails XML渲染", "CVE-2020-8163", ThreatLevelMedium},
		{`send_file`, "Rails文件发送", "CVE-2020-8165", ThreatLevelHigh},
		{`send_data`, "Rails数据发送", "CVE-2020-8165", ThreatLevelHigh},
		{`system\s*\(`, "Ruby system调用", "CVE-2020-8164", ThreatLevelCritical},
		{`exec\s*\(`, "Ruby exec调用", "CVE-2020-8164", ThreatLevelCritical},
		{"`.*`", "Ruby反引号执行", "CVE-2020-8164", ThreatLevelCritical},
		{`Marshal\.load`, "Ruby Marshal反序列化", "CVE-2020-8164", ThreatLevelCritical},
		{`YAML\.load`, "Ruby YAML反序列化", "CVE-2020-8164", ThreatLevelCritical},
		{`ERB\.new`, "Ruby ERB模板注入", "CVE-2020-8164", ThreatLevelCritical},
	}

	for _, p := range rubyPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       p.cve,
				Recommendation: "升级Ruby和Rails版本",
			})
		}
	}
}

func (a *ZeroDayAnalyzer) analyzeJavaVulnerabilities(data string, result *AnalysisResult) {
	javaPatterns := []struct {
		pattern     string
		description string
		cve         string
		threatLevel ThreatLevel
	}{
		{`java\.lang\.Runtime`, "Java运行时", "CVE-2021-26539", ThreatLevelHigh},
		{`java\.lang\.ProcessBuilder`, "Java进程构建器", "CVE-2021-26539", ThreatLevelCritical},
		{`javax\.naming\.Context`, "JNDI上下文", "CVE-2021-26539", ThreatLevelCritical},
		{`javax\.naming\.ldap\.LdapName`, "LDAP名称查询", "CVE-2021-26539", ThreatLevelHigh},
		{`org\.apache\.commons`, "Apache Commons库", "CVE-2022-22965", ThreatLevelHigh},
		{`commons-collections`, "Apache Collections反序列化", "CVE-2015-4852", ThreatLevelCritical},
		{`CVE-2015-4852`, "Apache Commons反序列化", "CVE-2015-4852", ThreatLevelCritical},
		{`CVE-2017-12149`, "JBoss反序列化", "CVE-2017-12149", ThreatLevelCritical},
		{`CVE-2018-1273`, "Spring Data Commons RCE", "CVE-2018-1273", ThreatLevelCritical},
		{`CVE-2020-2555`, "Oracle Coherence RCE", "CVE-2020-2555", ThreatLevelCritical},
		{`CVE-2022-22965`, "Spring4Shell RCE", "CVE-2022-22965", ThreatLevelCritical},
		{`CVE-2021-44228`, "Log4Shell JNDI注入", "CVE-2021-44228", ThreatLevelCritical},
		{`sun\.misc\.BASE64Decoder`, "Java Base64解码器", "CVE-2021-26539", ThreatLevelMedium},
		{`ObjectInputStream`, "Java对象输入流", "CVE-2015-4852", ThreatLevelHigh},
		{`readObject`, "Java反序列化读取", "CVE-2015-4852", ThreatLevelHigh},
	}

	for _, p := range javaPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       p.cve,
				Recommendation: "修补Java漏洞",
			})
		}
	}
}

func (a *ZeroDayAnalyzer) analyzeGoVulnerabilities(data string, result *AnalysisResult) {
	goPatterns := []struct {
		pattern     string
		description string
		cve         string
		threatLevel ThreatLevel
	}{
		{`CVE-2021-33195`, "Go template RCE", "CVE-2021-33195", ThreatLevelHigh},
		{`CVE-2021-33196`, "Go gin框架漏洞", "CVE-2021-33196", ThreatLevelHigh},
		{`CVE-2021-33197`, "Go crypto漏洞", "CVE-2021-33197", ThreatLevelMedium},
		{`CVE-2022-23772`, "Go cmd/api RCE", "CVE-2022-23772", ThreatLevelCritical},
		{`CVE-2022-23773`, "Go仲裁RCE", "CVE-2022-23773", ThreatLevelCritical},
		{`CVE-2022-24918`, "Go regexp漏洞", "CVE-2022-24918", ThreatLevelHigh},
		{`os/exec`, "Go exec包", "CVE-2022-23772", ThreatLevelHigh},
		{`exec\.Command`, "Go命令执行", "CVE-2022-23772", ThreatLevelHigh},
		{`html/template`, "Go HTML模板", "CVE-2021-33195", ThreatLevelMedium},
		{`text/template`, "Go文本模板", "CVE-2021-33195", ThreatLevelMedium},
		{`regexp\.Compile`, "Go正则编译", "CVE-2022-24918", ThreatLevelMedium},
		{`gin-gonic/gin`, "Gin框架", "CVE-2021-33196", ThreatLevelMedium},
		{`gorilla/mux`, "Gorilla Mux路由", "CVE-2021-33196", ThreatLevelMedium},
		{`labstack/echo`, "Echo框架", "CVE-2021-33196", ThreatLevelMedium},
	}

	for _, p := range goPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       p.cve,
				Recommendation: "升级Go版本和依赖",
			})
		}
	}
}

func (a *ZeroDayAnalyzer) analyzeNetVulnerabilities(data string, result *AnalysisResult) {
	netPatterns := []struct {
		pattern     string
		description string
		cve         string
		threatLevel ThreatLevel
	}{
		{`CVE-2021-26855`, ".NET Exchange SSRF", "CVE-2021-26855", ThreatLevelCritical},
		{`CVE-2021-26857`, ".NET反序列化RCE", "CVE-2021-26857", ThreatLevelCritical},
		{`CVE-2021-26858`, ".NET文件写入", "CVE-2021-26858", ThreatLevelCritical},
		{`CVE-2021-27065`, ".NET RCE", "CVE-2021-27065", ThreatLevelCritical},
		{`CVE-2022-23218`, "Go标准库DNS漏洞", "CVE-2022-23218", ThreatLevelHigh},
		{`CVE-2022-22942`, ".NET DoS漏洞", "CVE-2022-22942", ThreatLevelHigh},
		{`ASP\.NET`, "ASP.NET检测", "CVE-2021-26855", ThreatLevelMedium},
		{`__VIEWSTATE`, "ASP.NET视图状态", "CVE-2021-26855", ThreatLevelMedium},
		{`System\.Diagnostics\.Process`, ".NET进程", "CVE-2021-26857", ThreatLevelHigh},
		{`System\.Reflection\.Assembly`, ".NET程序集加载", "CVE-2021-26857", ThreatLevelHigh},
		{`Newtonsoft\.Json`, "Json.NET反序列化", "CVE-2021-26857", ThreatLevelHigh},
		{`JavaScriptSerializer`, ".NET JavaScript序列化", "CVE-2021-26857", ThreatLevelHigh},
		{`XmlSerializer`, ".NET XML序列化", "CVE-2021-26857", ThreatLevelHigh},
		{`BinaryFormatter`, ".NET二进制格式化", "CVE-2021-26857", ThreatLevelCritical},
	}

	for _, p := range netPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       p.cve,
				Recommendation: "修补.NET漏洞",
			})
		}
	}
}

func (a *ZeroDayAnalyzer) analyzePHPFrameworks(data string, result *AnalysisResult) {
	phpFwPatterns := []struct {
		pattern     string
		description string
		cve         string
		threatLevel ThreatLevel
	}{
		{`Laravel`, "Laravel框架检测", "CVE-2021-26539", ThreatLevelMedium},
		{`laravel`, "Laravel标识", "CVE-2021-26539", ThreatLevelMedium},
		{`Symfony`, "Symfony框架检测", "CVE-2021-26539", ThreatLevelMedium},
		{`symfony`, "Symfony标识", "CVE-2021-26539", ThreatLevelMedium},
		{`CodeIgniter`, "CodeIgniter框架检测", "CVE-2021-26539", ThreatLevelMedium},
		{`codeigniter`, "CodeIgniter标识", "CVE-2021-26539", ThreatLevelMedium},
		{`Yii`, "Yii框架检测", "CVE-2021-26539", ThreatLevelMedium},
		{`yii`, "Yii标识", "CVE-2021-26539", ThreatLevelMedium},
		{`CakePHP`, "CakePHP框架检测", "CVE-2021-26539", ThreatLevelMedium},
		{`cakephp`, "CakePHP标识", "CVE-2021-26539", ThreatLevelMedium},
	}

	for _, p := range phpFwPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       p.cve,
				Recommendation: "修补PHP框架漏洞",
			})
		}
	}
}

func (a *ZeroDayAnalyzer) analyzeLaravelVulnerabilities(data string, result *AnalysisResult) {
	laravelPatterns := []struct {
		pattern     string
		description string
		cve         string
		threatLevel ThreatLevel
	}{
		{`CVE-2018-15133`, "Laravel RCE", "CVE-2018-15133", ThreatLevelCritical},
		{`CVE-2021-3129`, "Laravel Ignition RCE", "CVE-2021-3129", ThreatLevelCritical},
		{`CVE-2021-43503`, "Laravel XSS", "CVE-2021-43503", ThreatLevelMedium},
		{`Illuminate`, "Laravel Illuminate组件", "CVE-2021-3129", ThreatLevelHigh},
		{`/api/\.env`, "Laravel .env访问", "CVE-2018-15133", ThreatLevelCritical},
		{`/vendor/\.env`, "Laravel vendor .env", "CVE-2018-15133", ThreatLevelCritical},
		{`APP_KEY`, "Laravel APP_KEY泄露", "CVE-2018-15133", ThreatLevelCritical},
		{`php://input`, "PHP输入流", "CVE-2021-3129", ThreatLevelHigh},
		{`view-error`, "Laravel错误页面", "CVE-2021-3129", ThreatLevelHigh},
		{`Monolog`, "Laravel Monolog日志", "CVE-2021-3129", ThreatLevelMedium},
	}

	for _, p := range laravelPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       p.cve,
				Recommendation: "升级Laravel到最新版本",
			})
		}
	}
}

func (a *ZeroDayAnalyzer) analyzeSymfonyVulnerabilities(data string, result *AnalysisResult) {
	symfonyPatterns := []struct {
		pattern     string
		description string
		cve         string
		threatLevel ThreatLevel
	}{
		{`CVE-2020-5273`, "Symfony RCE", "CVE-2020-5273", ThreatLevelCritical},
		{`CVE-2019-10909`, "Symfony SQL注入", "CVE-2019-10909", ThreatLevelCritical},
		{`CVE-2019-10910`, "Symfony SSRF", "CVE-2019-10910", ThreatLevelHigh},
		{`CVE-2021-32708`, "Symfony HTTP断行注入", "CVE-2021-32708", ThreatLevelHigh},
		{`/ _profiler`, "Symfony分析器", "CVE-2020-5273", ThreatLevelHigh},
		{`/ _wdt`, "Symfony调试工具栏", "CVE-2020-5273", ThreatLevelHigh},
		{`_profiler_open`, "Symfony分析器打开", "CVE-2020-5273", ThreatLevelHigh},
		{`var/cache`, "Symfony缓存目录", "CVE-2020-5273", ThreatLevelMedium},
		{`vendor/symfony`, "Symfony供应商", "CVE-2020-5273", ThreatLevelMedium},
	}

	for _, p := range symfonyPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       p.cve,
				Recommendation: "升级Symfony到最新版本",
			})
		}
	}
}

func (a *ZeroDayAnalyzer) analyzeCodeIgniterVulnerabilities(data string, result *AnalysisResult) {
	codeigniterPatterns := []struct {
		pattern     string
		description string
		cve         string
		threatLevel ThreatLevel
	}{
		{`CVE-2021-26539`, "CodeIgniter JNDI注入", "CVE-2021-26539", ThreatLevelCritical},
		{`CVE-2016-10571`, "CodeIgniter SQL注入", "CVE-2016-10571", ThreatLevelCritical},
		{`/system/`, "CodeIgniter系统路径", "CVE-2021-26539", ThreatLevelHigh},
		{`/application/`, "CodeIgniter应用路径", "CVE-2021-26539", ThreatLevelMedium},
		{`/index\.php\?`, "CodeIgniter入口", "CVE-2021-26539", ThreatLevelLow},
		{`controller`, "CodeIgniter控制器", "CVE-2021-26539", ThreatLevelMedium},
		{`model`, "CodeIgniter模型", "CVE-2021-26539", ThreatLevelMedium},
	}

	for _, p := range codeigniterPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       p.cve,
				Recommendation: "升级CodeIgniter到最新版本",
			})
		}
	}
}

func (a *ZeroDayAnalyzer) analyzeYiiVulnerabilities(data string, result *AnalysisResult) {
	yiiPatterns := []struct {
		pattern     string
		description string
		cve         string
		threatLevel ThreatLevel
	}{
		{`CVE-2021-26539`, "Yii JNDI注入", "CVE-2021-26539", ThreatLevelCritical},
		{`CVE-2020-15147`, "Yii2 SQL注入", "CVE-2020-15147", ThreatLevelCritical},
		{`/backend/`, "Yii后端路径", "CVE-2021-26539", ThreatLevelMedium},
		{`/frontend/`, "Yii前端路径", "CVE-2021-26539", ThreatLevelMedium},
		{`/web/`, "Yii web根路径", "CVE-2021-26539", ThreatLevelMedium},
		{`yiisoft`, "Yii框架标识", "CVE-2021-26539", ThreatLevelMedium},
		{`@app`, "Yii应用别名", "CVE-2021-26539", ThreatLevelMedium},
		{`@webroot`, "Yii webroot别名", "CVE-2021-26539", ThreatLevelMedium},
	}

	for _, p := range yiiPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       p.cve,
				Recommendation: "升级Yii到最新版本",
			})
		}
	}
}

func (a *ZeroDayAnalyzer) analyzeCakePHPVulnerabilities(data string, result *AnalysisResult) {
	cakephpPatterns := []struct {
		pattern     string
		description string
		cve         string
		threatLevel ThreatLevel
	}{
		{`CVE-2021-26539`, "CakePHP JNDI注入", "CVE-2021-26539", ThreatLevelCritical},
		{`CVE-2016-10571`, "CakePHP SQL注入", "CVE-2016-10571", ThreatLevelCritical},
		{`/cake/`, "CakePHP路径", "CVE-2021-26539", ThreatLevelMedium},
		{`/cakephp/`, "CakePHP路径", "CVE-2021-26539", ThreatLevelMedium},
		{`CakePHP`, "CakePHP标识", "CVE-2021-26539", ThreatLevelMedium},
		{`/Controller/`, "CakePHP控制器", "CVE-2021-26539", ThreatLevelMedium},
		{`/Model/`, "CakePHP模型", "CVE-2021-26539", ThreatLevelMedium},
	}

	for _, p := range cakephpPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       p.cve,
				Recommendation: "升级CakePHP到最新版本",
			})
		}
	}
}

func (a *ZeroDayAnalyzer) analyzeSymfonyRCE(data string, result *AnalysisResult) {
	symfonyRCEPatterns := []struct {
		pattern     string
		description string
		cve         string
		threatLevel ThreatLevel
	}{
		{`CVE-2022-24894`, "Symfony RCE", "CVE-2022-24894", ThreatLevelCritical},
		{`CVE-2022-24895`, "Symfony SQL注入", "CVE-2022-24895", ThreatLevelCritical},
		{`CVE-2021-32708`, "Symfony HTTP响应分割", "CVE-2021-32708", ThreatLevelHigh},
		{`_fragment`, "Symfony片段参数", "CVE-2022-24894", ThreatLevelHigh},
		{`_controller`, "Symfony控制器参数", "CVE-2022-24894", ThreatLevelCritical},
		{`_format`, "Symfony格式参数", "CVE-2022-24894", ThreatLevelMedium},
		{`_locale`, "Symfony区域参数", "CVE-2022-24894", ThreatLevelMedium},
		{`_route`, "Symfony路由参数", "CVE-2022-24894", ThreatLevelMedium},
		{`template::`, "Symfony模板注入", "CVE-2022-24894", ThreatLevelCritical},
		{`LogicBundle`, "Symfony逻辑包", "CVE-2022-24894", ThreatLevelHigh},
	}

	for _, p := range symfonyRCEPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       p.cve,
				Recommendation: "升级Symfony到最新版本",
			})
		}
	}
}

func (a *ZeroDayAnalyzer) analyzeLaravelDebugMode(data string, result *AnalysisResult) {
	laravelDebugPatterns := []struct {
		pattern     string
		description string
		cve         string
		threatLevel ThreatLevel
	}{
		{`APP_DEBUG=true`, "Laravel调试模式", "CVE-2021-3129", ThreatLevelHigh},
		{`APP_DEBUG = true`, "Laravel调试模式", "CVE-2021-3129", ThreatLevelHigh},
		{`Ignition Solutions`, "Laravel Ignition错误页", "CVE-2021-3129", ThreatLevelHigh},
		{`/error/`, "Laravel错误路由", "CVE-2021-3129", ThreatLevelMedium},
		{`Illuminate\\\\Routing\\\\UrlGenerator`, "Laravel URL生成器", "CVE-2021-3129", ThreatLevelMedium},
		{`vendor/laravel/framework`, "Laravel框架路径", "CVE-2021-3129", ThreatLevelMedium},
		{"Whoops!\\s*Exception", "PHP Whoops错误", "CVE-2021-3129", ThreatLevelMedium},
		{`Symfony\\Component\\Debug`, "Symfony调试组件", "CVE-2021-3129", ThreatLevelMedium},
	}

	for _, p := range laravelDebugPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Evidence:       p.cve,
				Recommendation: "关闭Laravel调试模式",
			})
		}
	}
}
