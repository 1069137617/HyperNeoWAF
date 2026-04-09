package analyzer

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

type CrawlerAnalyzer struct {
	name           string
	version        string
	analyzerType   string
	enabled        bool
	config         map[string]interface{}
	mu             sync.RWMutex
	requestCount   int64
	lastRequestTime time.Time
	muRequests     sync.Mutex
}

func NewCrawlerAnalyzer() *CrawlerAnalyzer {
	return &CrawlerAnalyzer{
		name:           "crawler_analyzer",
		version:        "1.0.0",
		analyzerType:   "crawler_detection",
		enabled:        true,
		config:         make(map[string]interface{}),
		requestCount:   0,
		lastRequestTime: time.Now(),
	}
}

func (a *CrawlerAnalyzer) Name() string {
	return a.name
}

func (a *CrawlerAnalyzer) Type() string {
	return a.analyzerType
}

func (a *CrawlerAnalyzer) Version() string {
	return a.version
}

func (a *CrawlerAnalyzer) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

func (a *CrawlerAnalyzer) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

func (a *CrawlerAnalyzer) Configure(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = config
	return nil
}

func (a *CrawlerAnalyzer) Analyze(input *AnalysisInput) *AnalysisResult {
	start := time.Now()
	result := NewAnalysisResult(a)

	if input == nil {
		return result
	}

	a.analyzeCrawlerFingerprints(input, result)
	a.analyzeScannerFingerprints(input, result)
	a.analyzeMaliciousUA(input, result)
	a.analyzeRequestFrequency(input, result)
	a.analyzeSuspiciousBehavior(input, result)
	a.analyzeKnownBots(input, result)

	result.ProcessingTime = time.Since(start)
	result.ShouldBlock = result.ShouldBlockRequest(0.5)
	if len(result.Matches) > 0 {
		result.ShouldLog = true
		result.ShouldAllow = !result.ShouldBlock
	}

	return result
}

func (a *CrawlerAnalyzer) analyzeCrawlerFingerprints(input *AnalysisInput, result *AnalysisResult) {
	if input.UserAgent == "" {
		return
	}

	ua := strings.ToLower(input.UserAgent)

	crawlerPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)googlebot`, "Google爬虫", ThreatLevelLow},
		{`(?i)google-inspectiontool`, "Google检查工具", ThreatLevelLow},
		{`(?i)google-search-console`, "Google搜索控制台", ThreatLevelLow},
		{`(?i)bingbot`, "Bing爬虫", ThreatLevelLow},
		{`(?i)msnbot`, "MSN爬虫", ThreatLevelLow},
		{`(?i)bingpreview`, "Bing预览", ThreatLevelLow},
		{`(?i)slurp`, "Yahoo爬虫", ThreatLevelLow},
		{`(?i)yandex`, "Yandex爬虫", ThreatLevelLow},
		{`(?i)baiduspider`, "百度爬虫", ThreatLevelLow},
		{`(?i)baidu.com`, "百度爬虫", ThreatLevelLow},
		{`(?i)duckduckbot`, "DuckDuckGo爬虫", ThreatLevelLow},
		{`(?i)facebookexternalhit`, "Facebook爬虫", ThreatLevelLow},
		{`(?i)facebot`, "Facebook爬虫", ThreatLevelLow},
		{`(?i)twitterbot`, "Twitter爬虫", ThreatLevelLow},
		{`(?i)linkedinbot`, "LinkedIn爬虫", ThreatLevelLow},
		{`(?i)pinterest`, "Pinterest爬虫", ThreatLevelLow},
		{`(?i)applebot`, "Apple爬虫", ThreatLevelLow},
		{`(?i)amazonbot`, "Amazon爬虫", ThreatLevelLow},
		{`(?i)claudebot`, "Claude爬虫", ThreatLevelLow},
		{`(?i)anthropic-ai`, "Anthropic AI爬虫", ThreatLevelLow},
		{`(?i) GPTBot`, "OpenAI爬虫", ThreatLevelLow},
		{`(?i)CCBot`, "Common Crawl爬虫", ThreatLevelLow},
		{`(?i)cohere-ai`, "Cohere AI爬虫", ThreatLevelLow},
		{`(?i)imagesiftbot`, "ImageSift爬虫", ThreatLevelLow},
		{`(?i)diffbot`, "Diffbot爬虫", ThreatLevelLow},
		{`(?i) proximic`, " proximic爬虫", ThreatLevelLow},
		{`(?i) screaming`, "Screaming Frog SEO", ThreatLevelMedium},
		{`(?i) sitebulb`, "Sitebulb", ThreatLevelMedium},
		{`(?i)curl`, "cURL工具", ThreatLevelMedium},
		{`(?i)wget`, "Wget工具", ThreatLevelMedium},
		{`(?i)python-requests`, "Python requests库", ThreatLevelMedium},
		{`(?i)java\/`, "Java HTTP客户端", ThreatLevelMedium},
		{`(?i)go-http-client`, "Go HTTP客户端", ThreatLevelMedium},
		{`(?i)okhttp`, "OkHttp客户端", ThreatLevelMedium},
		{`(?i)libwww`, "libwww库", ThreatLevelMedium},
		{`(?i)httpclient`, "HTTPClient", ThreatLevelMedium},
		{`(?i)scalajvm`, "Scala JVM HTTP", ThreatLevelMedium},
		{`(?i)async-http`, "Async HTTP", ThreatLevelMedium},
		{`(?i)scrapy`, "Scrapy爬虫框架", ThreatLevelHigh},
		{`(?i)scrape`, "Scrape工具", ThreatLevelMedium},
		{`(?i) crawler`, "通用爬虫", ThreatLevelMedium},
		{`(?i)spider`, "通用蜘蛛", ThreatLevelMedium},
		{`(?i)bot`, "通用机器人", ThreatLevelMedium},
	}

	for _, p := range crawlerPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(ua) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "爬虫指纹检测 - " + p.description,
				Recommendation: "根据爬虫策略决定是否允许",
			})
		}
	}

	if strings.Contains(ua, "crawl") || strings.Contains(ua, "spider") || strings.Contains(ua, "bot") {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelLow,
			Pattern:        "generic_crawler_signature",
			Description:    "通用爬虫签名检测",
			Recommendation: "记录爬虫访问日志",
		})
	}
}

func (a *CrawlerAnalyzer) analyzeScannerFingerprints(input *AnalysisInput, result *AnalysisResult) {
	if input.UserAgent == "" && input.Raw == "" {
		return
	}

	dataToCheck := input.UserAgent + " " + input.Raw

	scannerPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)sqlmap`, "SQLMap扫描器", ThreatLevelCritical},
		{`(?i)nmap`, "Nmap扫描器", ThreatLevelHigh},
		{`(?i)nikto`, "Nikto Web扫描器", ThreatLevelHigh},
		{`(?i)burp`, "Burp Suite", ThreatLevelHigh},
		{`(?i)burpsuite`, "Burp Suite", ThreatLevelHigh},
		{`(?i)zap`, "OWASP ZAP", ThreatLevelHigh},
		{`(?i)owasp`, "OWASP工具", ThreatLevelHigh},
		{`(?i)acunetix`, "Acunetix漏洞扫描器", ThreatLevelCritical},
		{`(?i)w3af`, "W3AF扫描器", ThreatLevelHigh},
		{`(?i)metasploit`, "Metasploit框架", ThreatLevelCritical},
		{`(?i)masscan`, "Masscan端口扫描器", ThreatLevelHigh},
		{`(?i)zgrab`, "ZGrab扫描器", ThreatLevelHigh},
		{`(?i)dirbuster`, "DirBuster目录扫描", ThreatLevelHigh},
		{`(?i)gobuster`, "GoBuster目录扫描", ThreatLevelHigh},
		{`(?i)ffuf`, "FFUF模糊测试", ThreatLevelHigh},
		{`(?i>fuff`, "FUZZ模糊测试", ThreatLevelHigh},
		{`(?i)wfuzz`, "WFuzz模糊测试", ThreatLevelHigh},
		{`(?i)hydra`, "Hydra暴力破解", ThreatLevelCritical},
		{`(?i)medusa`, "Medusa暴力破解", ThreatLevelCritical},
		{`(?i>john`, "John the Ripper", ThreatLevelCritical},
		{`(?i)hashcat`, "Hashcat密码破解", ThreatLevelCritical},
		{`(?i)nikto`, "Nikto扫描器", ThreatLevelHigh},
		{`(?i)paros`, "Paros扫描器", ThreatLevelHigh},
		{`(?i)webslayer`, "WebScarab", ThreatLevelHigh},
		{`(?i)webscarab`, "WebScarab代理", ThreatLevelHigh},
		{`(?i)proxystrike`, "ProxyStrike", ThreatLevelHigh},
		{`(?i>wstunnel`, "隧道工具", ThreatLevelHigh},
		{`(?i) Vega`, "Vega扫描器", ThreatLevelHigh},
		{`(?i)Subgraph`, "Subgraph Vega", ThreatLevelHigh},
		{`(?i)arachni`, "Arachni扫描器", ThreatLevelHigh},
		{`(?i)skipfish`, "Skipfish扫描器", ThreatLevelHigh},
		{`(?i)ratproxy`, "Ratproxy代理", ThreatLevelHigh},
		{`(?i) Mallory`, "Mallory代理", ThreatLevelHigh},
		{`(?i)mitmproxy`, "MITM代理", ThreatLevelMedium},
		{`(?i)ettercap`, "Ettercap中间人", ThreatLevelHigh},
		{`(?i)sslyze`, "SSLyze扫描器", ThreatLevelMedium},
		{`(?i)testssl`, "TestSSL扫描器", ThreatLevelMedium},
		{`(?i)whatweb`, "WhatWeb指纹识别", ThreatLevelMedium},
		{`(?i>wappalyzer`, "Wappalyzer技术检测", ThreatLevelLow},
		{`(?i>builtwith`, "BuiltWith技术检测", ThreatLevelLow},
		{`(?i>netcraft`, "Netcraft技术检测", ThreatLevelLow},
		{`(?i)shodan`, "Shodan搜索引擎", ThreatLevelMedium},
		{`(?i>censys`, "Censys搜索引擎", ThreatLevelMedium},
		{`(?i>fofa`, "FoFa搜索引擎", ThreatLevelMedium},
		{`(?i>zoomeye`, "ZoomEye搜索引擎", ThreatLevelMedium},
		{`(?i>quake`, "360 Quake", ThreatLevelMedium},
		{`(?i)gobuster`, "GoBuster扫描器", ThreatLevelHigh},
		{`(?i)dirb`, "DIRB扫描器", ThreatLevelHigh},
		{`(?i)dirbuster`, "DirBuster扫描器", ThreatLevelHigh},
		{`(?i>vhost`, "VHost扫描器", ThreatLevelMedium},
		{`(?i>favicon`, "Favicon扫描器", ThreatLevelMedium},
		{`(?i>cmsscan`, "CMS扫描器", ThreatLevelMedium},
		{`(?i>wpscan`, "WordPress扫描器", ThreatLevelHigh},
		{`(?i)joomscan`, "Joomla扫描器", ThreatLevelHigh},
		{`(?i)drupalscan`, "Drupal扫描器", ThreatLevelHigh},
		{`(?i>getrevue`, "CMS指纹检测", ThreatLevelMedium},
		{`(?i>dotdotpwn`, "DotDotPwn路径遍历扫描", ThreatLevelHigh},
		{`(?i>fimap`, "FiMap文件包含扫描", ThreatLevelCritical},
		{`(?i)fimap`, "FiMap扫描器", ThreatLevelCritical},
		{`(?i)samrdump`, "SMB枚举工具", ThreatLevelCritical},
		{`(?i>smbclient`, "SMB客户端", ThreatLevelHigh},
		{`(?i>ldapsearch`, "LDAP搜索工具", ThreatLevelHigh},
		{`(?i)httprint`, "HTTPrint指纹识别", ThreatLevelMedium},
		{`(?i>httprecon`, "HTTPRecon指纹识别", ThreatLevelMedium},
		{`(?i>webhandler`, "WebHandler扫描器", ThreatLevelHigh},
		{`(?i)fim33`, "FiMap变体", ThreatLevelCritical},
		{`(?i>pangolin`, " Pangolin SQL注入", ThreatLevelCritical},
		{`(?i>havij`, "Havij SQL注入", ThreatLevelCritical},
		{`(?i)sqlninja`, "SQLNinja SQL注入", ThreatLevelCritical},
		{`(?i)absinthe`, "Absinthe SQL注入", ThreatLevelCritical},
		{`(?i>blindelephant`, "BlindElephant扫描器", ThreatLevelMedium},
		{`(?i>wpscan`, "WPScan WordPress扫描", ThreatLevelHigh},
		{`(?i>plesk`, "Plesk指纹", ThreatLevelLow},
		{`(?i>cpanel`, "cPanel指纹", ThreatLevelLow},
		{`(?i)整站下载器`, "整站下载器", ThreatLevelHigh},
		{`(?i>teleport`, "Teleport Pro", ThreatLevelHigh},
		{`(?i>httrack`, "HTTrack网站克隆", ThreatLevelHigh},
		{`(?i>webzip`, "WebZip", ThreatLevelHigh},
		{`(?i>blackwidow`, "BlackWidow爬虫", ThreatLevelHigh},
		{`(?i>webcopier`, "WebCopier", ThreatLevelHigh},
		{`(?i>webmastercoffee`, "WebMaster Coffee", ThreatLevelMedium},
		{`(?i)netcraft`, "Netcraft", ThreatLevelMedium},
		{`(?i)爬虫`, "中文爬虫", ThreatLevelMedium},
		{`(?i)扫描器`, "中文扫描器", ThreatLevelMedium},
		{`(?i)暴力`, "暴力破解工具", ThreatLevelCritical},
		{`(?i)攻击`, "攻击工具", ThreatLevelCritical},
	}

	for _, p := range scannerPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(dataToCheck) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "扫描器指纹检测 - " + p.description,
				Recommendation: "阻止恶意扫描器访问",
			})
		}
	}
}

func (a *CrawlerAnalyzer) analyzeMaliciousUA(input *AnalysisInput, result *AnalysisResult) {
	if input.UserAgent == "" {
		return
	}

	ua := input.UserAgent

	maliciousPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)hack`, "黑客工具UA", ThreatLevelCritical},
		{`(?i)attacker`, "攻击者UA", ThreatLevelCritical},
		{`(?i)扫描`, "扫描器UA", ThreatLevelCritical},
		{`(?i)exploit`, "漏洞利用UA", ThreatLevelCritical},
		{`(?i)malware`, "恶意软件UA", ThreatLevelCritical},
		{`(?i)virus`, "病毒UA", ThreatLevelCritical},
		{`(?i)spam`, "垃圾信息UA", ThreatLevelHigh},
		{`(?i)spider`, "爬虫UA", ThreatLevelMedium},
		{`(?i)bot`, "机器人UA", ThreatLevelMedium},
		{`(?i)test`, "测试UA", ThreatLevelLow},
		{`(?i)^-`, "可疑短UA", ThreatLevelMedium},
		{`(?i)^Mozilla\/[1-3]\.`, "旧版Mozilla", ThreatLevelMedium},
		{`(?i)^Lynx`, "文本浏览器", ThreatLevelLow},
		{`(?i)w3m`, "W3M浏览器", ThreatLevelLow},
		{`(?i)curl\/[1-6]\.`, "旧版cURL", ThreatLevelMedium},
		{`(?i)python-urllib\/[12]\.`, "旧版Python urllib", ThreatLevelMedium},
		{`(?i)^$`, "空白UA", ThreatLevelMedium},
		{`(?i)java\/1\.[0-4]`, "旧版Java", ThreatLevelMedium},
		{`(?i>ruby`, "Ruby HTTP客户端", ThreatLevelMedium},
		{`(?i)libwww-perl`, "LibWWW Perl", ThreatLevelMedium},
		{`(?i)perl`, "Perl HTTP客户端", ThreatLevelMedium},
		{`(?i>php`, "PHP HTTP客户端", ThreatLevelMedium},
		{`(?i>cfml`, "ColdFusion", ThreatLevelMedium},
		{`(?i>batch`, "批处理脚本", ThreatLevelHigh},
		{`(?i)powershell`, "PowerShell脚本", ThreatLevelHigh},
		{`(?i)cmd\.exe`, "CMD脚本", ThreatLevelHigh},
		{`(?i)mshta`, "MSHTA执行", ThreatLevelCritical},
		{`(?i>wscript`, "WScript执行", ThreatLevelHigh},
		{`(?i>cscript`, "CScript执行", ThreatLevelHigh},
		{`(?i)regsvr32`, "RegSvr32执行", ThreatLevelCritical},
		{`(?i>rundll32`, "Rundll32执行", ThreatLevelCritical},
		{`(?i>msiexec`, "MSI执行", ThreatLevelCritical},
		{`(?i>installutil`, "InstallUtil执行", ThreatLevelCritical},
		{`(?i>msbuild`, "MSBuild执行", ThreatLevelCritical},
		{`(?i>certutil`, "CertUtil工具", ThreatLevelCritical},
		{`(?i_bitsadmin`, "BITSAdmin", ThreatLevelCritical},
		{`(?i)nslookup`, "NsLookup", ThreatLevelMedium},
		{`(?i>nc\.exe`, "NetCat", ThreatLevelCritical},
		{`(?i)ncat`, "NetCat", ThreatLevelCritical},
		{`(?i>powershell\.exe`, "PowerShell执行", ThreatLevelCritical},
		{`(?i)\\win\\system`, "Windows系统路径", ThreatLevelHigh},
		{`(?i)/bin/sh`, "Unix Shell", ThreatLevelCritical},
		{`(?i)/bin/bash`, "Bash Shell", ThreatLevelCritical},
		{`(?i)/usr/bin/`, "Unix系统路径", ThreatLevelHigh},
		{`(?i)\\windows\\system32`, "Windows系统路径", ThreatLevelHigh},
		{`(?i)tmp`, "临时文件路径", ThreatLevelMedium},
		{`(?i)temp`, "临时文件路径", ThreatLevelMedium},
		{`(?i)var/tmp`, "Unix临时目录", ThreatLevelMedium},
	}

	for _, p := range maliciousPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(ua) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "恶意UA检测 - " + p.description,
				Recommendation: "阻止使用恶意UA的请求",
			})
		}
	}
}

func (a *CrawlerAnalyzer) analyzeRequestFrequency(input *AnalysisInput, result *AnalysisResult) {
	if input.ClientIP == "" {
		return
	}

	a.muRequests.Lock()
	defer a.muRequests.Unlock()

	now := time.Now()
	elapsed := now.Sub(a.lastRequestTime).Seconds()

	if elapsed > 0 && elapsed < 0.001 {
		result.AddMatch(Match{
			Type:           MatchTypeBehavioral,
			ThreatLevel:    ThreatLevelHigh,
			Pattern:        "extremely_high_request_frequency",
			Description:    "异常高请求频率",
			Recommendation: "限制请求频率",
		})
	}

	if a.requestCount > 1000 && elapsed < 60 {
		result.AddMatch(Match{
			Type:           MatchTypeBehavioral,
			ThreatLevel:    ThreatLevelHigh,
			Pattern:        "high_request_volume",
			Description:    "高请求量检测",
			Evidence:       "60秒内超过1000请求",
			Recommendation: "考虑限流或封锁",
		})
	}

	a.requestCount++
	a.lastRequestTime = now
}

func (a *CrawlerAnalyzer) analyzeSuspiciousBehavior(input *AnalysisInput, result *AnalysisResult) {
	dataToCheck := input.Raw + " " + input.Path + " " + input.QueryString

	suspiciousPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\.git\/`, "Git仓库访问", ThreatLevelHigh},
		{`(?i)\.git\/config`, "Git配置访问", ThreatLevelHigh},
		{`(?i)\.git\/HEAD`, "Git HEAD访问", ThreatLevelHigh},
		{`(?i)\.svn\/`, "SVN仓库访问", ThreatLevelHigh},
		{`(?i)\.svn\/entries`, "SVN条目访问", ThreatLevelHigh},
		{`(?i)\.hg\/`, "Mercurial仓库访问", ThreatLevelHigh},
		{`(?i)\.bzr\/`, "Bazaar仓库访问", ThreatLevelHigh},
		{`(?i)\.env`, "环境变量文件", ThreatLevelCritical},
		{`(?i)\.aws\/credentials`, "AWS凭证文件", ThreatLevelCritical},
		{`(?i)\.npmrc`, "NPM配置文件", ThreatLevelMedium},
		{`(?i)\.yarnrc`, "Yarn配置文件", ThreatLevelMedium},
		{`(?i)composer\.json`, "Composer配置", ThreatLevelMedium},
		{`(?i)package\.json`, "NPM包配置", ThreatLevelMedium},
		{`(?i)Gemfile`, "Ruby Gem配置", ThreatLevelMedium},
		{`(?i)requirements\.txt`, "Python依赖配置", ThreatLevelMedium},
		{`(?i)config\.php`, "PHP配置文件", ThreatLevelHigh},
		{`(?i)wp-config\.php`, "WordPress配置", ThreatLevelHigh},
		{`(?i>settings\.py`, "Django设置", ThreatLevelHigh},
		{`(?i)application\.properties`, "Java属性配置", ThreatLevelHigh},
		{`(?i)web\.config`, "ASP.NET配置", ThreatLevelHigh},
		{`(?i)\.htaccess`, "Apache配置", ThreatLevelMedium},
		{`(?i)\.htpasswd`, "Apache密码文件", ThreatLevelHigh},
		{`(?i)backup`, "备份文件", ThreatLevelHigh},
		{`(?i)\.bak`, "备份文件", ThreatLevelHigh},
		{`(?i)\.old`, "旧文件", ThreatLevelMedium},
		{`(?i)\.zip`, "压缩文件", ThreatLevelMedium},
		{`(?i)\.tar`, "归档文件", ThreatLevelMedium},
		{`(?i)\.gz`, "压缩文件", ThreatLevelMedium},
		{`(?i)\.rar`, "压缩文件", ThreatLevelMedium},
		{`(?i)\.sql`, "SQL文件", ThreatLevelHigh},
		{`(?i)\.dump`, "数据库dump", ThreatLevelHigh},
		{`(?i)debug`, "调试端点", ThreatLevelHigh},
		{`(?i)actuator`, "Spring Actuator", ThreatLevelHigh},
		{`(?i)env`, "环境端点", ThreatLevelHigh},
		{`(?i)swagger`, "Swagger文档", ThreatLevelMedium},
		{`(?i)api\/docs`, "API文档", ThreatLevelMedium},
		{`(?i)favicon\.ico`, "Favicon探测", ThreatLevelLow},
		{`(?i)robots\.txt`, "Robots.txt探测", ThreatLevelLow},
		{`(?i)sitemap\.xml`, "Sitemap探测", ThreatLevelLow},
		{`(?i>crossdomain\.xml`, "Flash跨域策略", ThreatLevelMedium},
		{`(?i)clientaccesspolicy\.xml`, "Silverlight跨域", ThreatLevelMedium},
		{`(?i>xmlrpc\.php`, "XML-RPC探测", ThreatLevelMedium},
		{`(?i)wlwmanifest\.xml`, "Windows Live Writer", ThreatLevelMedium},
		{`(?i)readme`, "README文件", ThreatLevelLow},
		{`(?i)CHANGELOG`, "变更日志", ThreatLevelLow},
		{`(?i>LICENSE`, "许可证文件", ThreatLevelLow},
		{`(?i)wp-login`, "WordPress登录", ThreatLevelHigh},
		{`(?i)administrator`, "管理后台", ThreatLevelHigh},
		{`(?i)admin\/`, "管理路径", ThreatLevelMedium},
		{`(?i)phpmyadmin`, "phpMyAdmin", ThreatLevelHigh},
		{`(?i)sqladm`, "SQL管理", ThreatLevelHigh},
		{`(?i).DS_Store`, "macOS元数据", ThreatLevelLow},
		{`(?i)Thumbs\.db`, "Windows缩略图", ThreatLevelLow},
		{`(?i)>WFuzz`, "WFuzz模糊测试", ThreatLevelHigh},
		{`(?i)>fuzz`, "模糊测试", ThreatLevelHigh},
		{`(?i)>buster`, "目录爆破", ThreatLevelHigh},
	}

	for _, p := range suspiciousPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(dataToCheck) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "可疑行为检测 - " + p.description,
				Recommendation: "监控可疑访问模式",
			})
		}
	}

	sensitivePathCount := 0
	for _, p := range suspiciousPatterns {
		if p.threatLevel >= ThreatLevelHigh {
			re := regexp.MustCompile(p.pattern)
			if re.MatchString(dataToCheck) {
				sensitivePathCount++
			}
		}
	}

	if sensitivePathCount > 3 {
		result.AddMatch(Match{
			Type:           MatchTypeBehavioral,
			ThreatLevel:    ThreatLevelHigh,
			Pattern:        "multiple_sensitive_path_access",
			Description:    "多敏感路径访问模式",
			Evidence:       "60秒内访问超过3个敏感路径",
			Recommendation: "封锁扫描行为",
		})
	}
}

func (a *CrawlerAnalyzer) analyzeKnownBots(input *AnalysisInput, result *AnalysisResult) {
	if input.UserAgent == "" {
		return
	}

	ua := input.UserAgent

	knownBadBots := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)masscan`, "Masscan端口扫描器", ThreatLevelCritical},
		{`(?i)棱镜`, "棱镜扫描器", ThreatLevelCritical},
		{`(?i)image::store`, "Image::Store采集器", ThreatLevelHigh},
		{`(?i)dataapi`, "DataAPI采集器", ThreatLevelMedium},
		{`(?i)sogou`, "搜狗爬虫", ThreatLevelMedium},
		{`(?i)yisou`, "宜搜爬虫", ThreatLevelMedium},
		{`(?i)easouspider`, "Easou爬虫", ThreatLevelMedium},
		{`(?i)bingpreview`, "Bing预览爬虫", ThreatLevelLow},
		{`(?i>addthis`, "AddThis分享爬虫", ThreatLevelMedium},
		{`(?i>slack`, "Slack爬虫", ThreatLevelMedium},
		{`(?i>telegram`, "Telegram爬虫", ThreatLevelMedium},
		{`(?i)whatsapp`, "WhatsApp爬虫", ThreatLevelMedium},
		{`(?i)skypeuripreview`, "Skype预览爬虫", ThreatLevelMedium},
		{`(?i>ia_archiver`, "Alexa爬虫", ThreatLevelMedium},
		{`(?i>naver`, "Naver爬虫", ThreatLevelMedium},
		{`(?i)exabot`, "Exabot爬虫", ThreatLevelMedium},
		{`(?i)CCBot`, "CommonCrawl爬虫", ThreatLevelLow},
		{`(?i>Seznam`, "Seznam爬虫", ThreatLevelMedium},
		{`(?i>Mail\.RU`, "Mail.ru爬虫", ThreatLevelMedium},
		{`(?i>Qwant`, "Qwant爬虫", ThreatLevelMedium},
		{`(?i>DuckDuckBot`, "DuckDuckGo爬虫", ThreatLevelLow},
		{`(?i>Teleport`, "Teleport Pro爬虫", ThreatLevelCritical},
		{`(?i>TeleportPro`, "Teleport Pro爬虫", ThreatLevelCritical},
		{`(?i>Website Downloader`, "Website Downloader", ThreatLevelHigh},
		{`(?i>HTTrack`, "HTTrack网站克隆", ThreatLevelHigh},
		{`(?i>WebCopy`, "WebCopy爬虫", ThreatLevelHigh},
		{`(?i>Offline Explorer`, "Offline Explorer", ThreatLevelHigh},
		{`(?i>EmailCollector`, "邮件收集器", ThreatLevelCritical},
		{`(?i>EmailSiphon`, "邮件Siphon", ThreatLevelCritical},
		{`(?i>Bad crawler`, "恶意爬虫", ThreatLevelHigh},
		{`(?i)true Bot`, "真机器人", ThreatLevelMedium},
	}

	for _, p := range knownBadBots {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(ua) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "已知恶意爬虫 - " + p.description,
				Recommendation: "根据爬虫策略处理",
			})
		}
	}
}
