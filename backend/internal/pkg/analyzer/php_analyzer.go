package analyzer

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

type PHPAnalyzer struct {
	name         string
	version      string
	analyzerType string
	enabled      bool
	config       map[string]interface{}
	mu           sync.RWMutex
}

func NewPHPAnalyzer() *PHPAnalyzer {
	return &PHPAnalyzer{
		name:         "php_analyzer",
		version:      "2.0.0",
		analyzerType: "php_injection",
		enabled:      true,
		config:       make(map[string]interface{}),
	}
}

func (a *PHPAnalyzer) Name() string {
	return a.name
}

func (a *PHPAnalyzer) Type() string {
	return a.analyzerType
}

func (a *PHPAnalyzer) Version() string {
	return a.version
}

func (a *PHPAnalyzer) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

func (a *PHPAnalyzer) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

func (a *PHPAnalyzer) Configure(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = config
	return nil
}

func (a *PHPAnalyzer) Analyze(input *AnalysisInput) *AnalysisResult {
	start := time.Now()
	result := NewAnalysisResult(a)

	if input == nil || input.Raw == "" {
		return result
	}

	dataToAnalyze := a.prepareData(input)
	normalized := a.normalizeInput(dataToAnalyze)

	a.analyzeCodeExecution(dataToAnalyze, result)
	a.analyzeEvalPatterns(dataToAnalyze, result)
	a.analyzeFileOperations(dataToAnalyze, result)
	a.analyzeSSRF(dataToAnalyze, result)
	a.analyzeDeserialization(dataToAnalyze, result)
	a.analyzeLDAPInjection(dataToAnalyze, result)
	a.analyzeXMLInjection(dataToAnalyze, result)
	a.analyzeMailInjection(dataToAnalyze, result)
	a.analyzepreg_replace(dataToAnalyze, result)
	a.analyzeassert(dataToAnalyze, result)
	a.analyzeDynamicProperties(dataToAnalyze, result)
	a.analyzeTypeJuggling(dataToAnalyze, result)
	a.analyzePathTraversal(dataToAnalyze, result)
	a.analyzeServerSideInjection(dataToAnalyze, result)

	a.analyzePHP8Specific(normalized, result)
	a.analyzeOPcacheBypass(normalized, result)
	a.analyzePharDeserialization(normalized, result)
	a.analyzeCommandInjection(normalized, result)

	result.ProcessingTime = time.Since(start)
	result.ShouldBlock = result.ShouldBlockRequest(0.65)
	if len(result.Matches) > 0 {
		result.ShouldLog = true
		result.ShouldAllow = !result.ShouldBlock
	}

	return result
}

func (a *PHPAnalyzer) prepareData(input *AnalysisInput) string {
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

func (a *PHPAnalyzer) normalizeInput(data string) string {
	data = strings.ToLower(data)
	data = a.decodeURLEncoding(data)
	data = a.decodeHexEncoding(data)
	data = a.decodeUnicodeEncoding(data)
	return data
}

func (a *PHPAnalyzer) decodeURLEncoding(data string) string {
	pattern := regexp.MustCompile(`%([0-9a-fA-F]{2})`)
	return pattern.ReplaceAllStringFunc(data, func(match string) string {
		hex := match[1:]
		b := a.hexToByte(hex)
		return string(rune(b))
	})
}

func (a *PHPAnalyzer) decodeHexEncoding(data string) string {
	pattern := regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	return pattern.ReplaceAllStringFunc(data, func(match string) string {
		hex := match[2:]
		b := a.hexToByte(hex)
		return string(rune(b))
	})
}

func (a *PHPAnalyzer) decodeUnicodeEncoding(data string) string {
	pattern := regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
	return pattern.ReplaceAllStringFunc(data, func(match string) string {
		hex := match[2:]
		b1 := a.hexToByte(hex[:2])
		b2 := a.hexToByte(hex[2:])
		return string(rune(int(b1)<<8 | int(b2)))
	})
}

func (a *PHPAnalyzer) hexToByte(s string) byte {
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

func (a *PHPAnalyzer) analyzeCodeExecution(data string, result *AnalysisResult) {
	codeExecPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\beval\s*\(`, "PHP eval() - 动态代码执行", ThreatLevelCritical},
		{`(?i)\bassert\s*\(`, "PHP assert() - 动态代码执行", ThreatLevelCritical},
		{`(?i)\bcreate_function\s*\(`, "PHP create_function() - 动态函数创建", ThreatLevelCritical},
		{`(?i)\bcall_user_func\s*\(`, "PHP call_user_func() - 回调执行", ThreatLevelHigh},
		{`(?i)\bcall_user_func_array\s*\(`, "PHP call_user_func_array() - 回调带参数", ThreatLevelHigh},
		{`(?i)\bforward_static_call\s*\(`, "PHP forward_static_call()", ThreatLevelHigh},
		{`(?i)\bforward_static_call_array\s*\(`, "PHP forward_static_call_array()", ThreatLevelHigh},
		{`(?i)\bfunc_get_args\s*\(`, "PHP func_get_args() - 参数操纵", ThreatLevelMedium},
		{`(?i)\bfunc_num_args\s*\(`, "PHP func_num_args()", ThreatLevelMedium},
		{`(?i)\bget_defined_vars\s*\(`, "PHP get_defined_vars() - 变量枚举", ThreatLevelMedium},
		{`(?i)\bget_defined_constants\s*\(`, "PHP get_defined_constants()", ThreatLevelLow},
		{`(?i)\bget_defined_functions\s*\(`, "PHP get_defined_functions()", ThreatLevelHigh},
		{`(?i)\bregister_tick_function\s*\(`, "PHP register_tick_function()", ThreatLevelHigh},
		{`(?i)\bregister_shutdown_function\s*\(`, "PHP register_shutdown_function()", ThreatLevelHigh},
		{`(?i)\bspl_autoload_register\s*\(`, "PHP spl_autoload_register()", ThreatLevelMedium},
		{`(?i)\bspl_autoload_functions\s*\(`, "PHP spl_autoload_functions()", ThreatLevelMedium},
		{`(?i)\bunserialize\s*\(`, "PHP unserialize() - 对象反序列化", ThreatLevelCritical},
		{`(?i)\bparse_str\s*\(`, "PHP parse_str() - 查询字符串解析", ThreatLevelHigh},
		{`(?i)\bmb_parse_str\s*\(`, "PHP mb_parse_str()", ThreatLevelHigh},
		{`(?i)\bextract\s*\(`, "PHP extract() - 变量提取", ThreatLevelCritical},
		{`(?i)\bparse_ini_file\s*\(`, "PHP parse_ini_file()", ThreatLevelMedium},
		{`(?i)\bparse_ini_string\s*\(`, "PHP parse_ini_string()", ThreatLevelMedium},
		{`(?i)\bhighlight_file\s*\(`, "PHP highlight_file() - 文件源码泄露", ThreatLevelHigh},
		{`(?i)\bshow_source\s*\(`, "PHP show_source()", ThreatLevelHigh},
		{`(?i)\breadfile\s*\(`, "PHP readfile()", ThreatLevelMedium},
		{`(?i)\bfile_get_contents\s*\(`, "PHP file_get_contents()", ThreatLevelMedium},
		{`(?i)\bfile_put_contents\s*\(`, "PHP file_put_contents()", ThreatLevelCritical},
		{`(?i)\bfopen\s*\(`, "PHP fopen()", ThreatLevelHigh},
		{`(?i)\bfwrite\s*\(`, "PHP fwrite()", ThreatLevelHigh},
		{`(?i)\binclude\s*\(`, "PHP include()", ThreatLevelCritical},
		{`(?i)\binclude_once\s*\(`, "PHP include_once()", ThreatLevelCritical},
		{`(?i)\brequire\s*\(`, "PHP require()", ThreatLevelCritical},
		{`(?i)\brequire_once\s*\(`, "PHP require_once()", ThreatLevelCritical},
		{`(?i)\bvirtual\s*\(`, "PHP virtual() - Apache特定", ThreatLevelHigh},
		{`(?i)\bheader\s*\(`, "PHP header() - HTTP头注入", ThreatLevelMedium},
		{`(?i)\bheader_remove\s*\(`, "PHP header_remove()", ThreatLevelMedium},
		{`(?i)\bsetcookie\s*\(`, "PHP setcookie()", ThreatLevelLow},
		{`(?i)\bsession_start\s*\(`, "PHP session_start()", ThreatLevelLow},
		{`(?i)\bsession_id\s*\(`, "PHP session_id() - 会话固定", ThreatLevelMedium},
		{`(?i)\bReflectionMethod::invoke\s*\(`, "PHP ReflectionMethod::invoke() - 反射调用", ThreatLevelCritical},
		{`(?i)\bReflectionClass::newInstance\s*\(`, "PHP ReflectionClass::newInstance() - 反射实例化", ThreatLevelCritical},
		{`(?i)\bReflectionFunction::invoke\s*\(`, "PHP ReflectionFunction::invoke() - 函数反射调用", ThreatLevelCritical},
	}

	for _, p := range codeExecPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "避免动态代码执行;使用函数名白名单",
			})
		}
	}
}

func (a *PHPAnalyzer) analyzeEvalPatterns(data string, result *AnalysisResult) {
	evalPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\$\{\w+\}`, "PHP可变变量 ($$)", ThreatLevelHigh},
		{`\$\{.*\}`, "PHP花括号内变量插值", ThreatLevelHigh},
		{`(?i)\$\$`, "双美元符号 (可变变量)", ThreatLevelHigh},
		{`(?i)\$\w+\s*\(`, "变量函数调用: $func()", ThreatLevelCritical},
		{`(?i)\\\\x`, "十六进制编码字符", ThreatLevelMedium},
		{`(?i)\\\\[0-7]{3}`, "八进制编码字符", ThreatLevelMedium},
		{`(?i)base64_decode\s*\(`, "Base64解码", ThreatLevelHigh},
		{`(?i)base64_encode\s*\(`, "Base64编码", ThreatLevelLow},
		{`(?i)gzinflate\s*\(`, "gzinflate - 解压缩", ThreatLevelHigh},
		{`(?i)gzdeflate\s*\(`, "gzdeflate - 压缩", ThreatLevelLow},
		{`(?i)str_rot13\s*\(`, "str_rot13 - 编码", ThreatLevelMedium},
		{`(?i)pack\s*\(.*['\"]\w['\"]`, "pack()带格式", ThreatLevelHigh},
		{`(?i)unpack\s*\(`, "unpack() - 二进制解包", ThreatLevelHigh},
		{`(?i)chr\s*\(`, "chr() - ASCII转字符", ThreatLevelMedium},
		{`(?i)ord\s*\(`, "ord() - 字符转ASCII", ThreatLevelLow},
		{`(?i)bin2hex\s*\(`, "bin2hex - 二进制转十六进制", ThreatLevelMedium},
		{`(?i)hex2bin\s*\(`, "hex2bin - 十六进制转二进制", ThreatLevelMedium},
		{`(?i)mcrypt_`, "mcrypt扩展 (已废弃)", ThreatLevelHigh},
		{`(?i)mhash_`, "mhash扩展", ThreatLevelMedium},
		{`(?i)crypt\s*\(`, "crypt() - 单向哈希", ThreatLevelLow},
		{`(?i)hash_`, "哈希函数", ThreatLevelLow},
		{`(?i)md5\s*\(`, "MD5哈希", ThreatLevelLow},
		{`(?i)sha1\s*\(`, "SHA1哈希", ThreatLevelLow},
		{`(?i)password_hash\s*\(`, "password_hash()", ThreatLevelLow},
		{`(?i)rot13\s*\(`, "rot13编码", ThreatLevelLow},
		{`(?i)implode\s*\(.*\$`, "implode()拼接", ThreatLevelMedium},
		{`(?i)join\s*\(.*\$`, "join()拼接", ThreatLevelMedium},
		{`(?i)preg_filter\s*\(.*\$`, "preg_filter()变量模式", ThreatLevelHigh},
		{`(?i)mb_send_mail\s*\(.*\$`, "mb_send_mail()变量", ThreatLevelMedium},
		{`(?i)html_entity_decode\s*\(.*\$`, "html_entity_decode()变量", ThreatLevelHigh},
		{`(?i)htmlentities\s*\(.*\$`, "htmlentities()变量", ThreatLevelMedium},
		{`(?i)get_html_translation_table\s*\(`, "get_html_translation_table()", ThreatLevelMedium},
	}

	for _, p := range evalPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "验证和清理输入;避免动态评估",
			})
		}
	}
}

func (a *PHPAnalyzer) analyzeFileOperations(data string, result *AnalysisResult) {
	fileOpPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\breadfile\s*\([^)]*\b/etc/`, "读取/etc/文件", ThreatLevelHigh},
		{`(?i)\breadfile\s*\([^)]*\bpasswd`, "读取passwd文件", ThreatLevelHigh},
		{`(?i)\bfile_get_contents\s*\([^)]*\b/etc/`, "通过file_get_contents读取/etc/", ThreatLevelHigh},
		{`(?i)\bfile_get_contents\s*\([^)]*php://input`, "读取php://input", ThreatLevelHigh},
		{`(?i)\bfile_get_contents\s*\([^)]*php://filter`, "PHP过滤器流", ThreatLevelHigh},
		{`(?i)\bglob\s*\(`, "glob() - 目录列表", ThreatLevelMedium},
		{`(?i)\bopendir\s*\(`, "opendir() - 打开目录", ThreatLevelMedium},
		{`(?i)\bscandir\s*\(`, "scandir() - 目录扫描", ThreatLevelMedium},
		{`(?i)\breaddir\s*\(`, "readdir() - 读取目录项", ThreatLevelMedium},
		{`(?i)\bdir\s*\(`, "dir() - 目录类", ThreatLevelMedium},
		{`(?i)\bchdir\s*\(`, "chdir() - 改变目录", ThreatLevelHigh},
		{`(?i)\bchroot\s*\(`, "chroot() - 改变根目录", ThreatLevelCritical},
		{`(?i)\bmkdir\s*\(`, "mkdir() - 创建目录", ThreatLevelMedium},
		{`(?i)\brmdir\s*\(`, "rmdir() - 删除目录", ThreatLevelHigh},
		{`(?i)\bcopy\s*\(`, "copy() - 复制文件", ThreatLevelMedium},
		{`(?i)\brename\s*\(`, "rename() - 重命名文件", ThreatLevelMedium},
		{`(?i)\bunlink\s*\(`, "unlink() - 删除文件", ThreatLevelHigh},
		{`(?i)\blink\s*\(`, "link() - 创建硬链接", ThreatLevelMedium},
		{`(?i)\bsymlink\s*\(`, "symlink() - 创建符号链接", ThreatLevelHigh},
		{`(?i)\breadlink\s*\(`, "readlink() - 读取符号链接目标", ThreatLevelMedium},
		{`(?i)\bchmod\s*\(`, "chmod() - 改变权限", ThreatLevelHigh},
		{`(?i)\bchown\s*\(`, "chown() - 改变所有者", ThreatLevelHigh},
		{`(?i)\bchgrp\s*\(`, "chgrp() - 改变组", ThreatLevelHigh},
		{`(?i)\btouch\s*\(`, "touch() - 创建空文件", ThreatLevelLow},
		{`(?i)\bfilemtime\s*\(`, "filemtime() - 文件修改时间", ThreatLevelLow},
		{`(?i)\bfilesize\s*\(`, "filesize() - 文件大小", ThreatLevelLow},
		{`(?i)\bfileowner\s*\(`, "fileowner() - 文件所有者", ThreatLevelLow},
		{`(?i)\bfileperms\s*\(`, "fileperms() - 文件权限", ThreatLevelLow},
		{`(?i)\bfiletype\s*\(`, "filetype() - 文件类型", ThreatLevelLow},
		{`(?i)\bis_dir\s*\(`, "is_dir() - 检查是否为目录", ThreatLevelLow},
		{`(?i)\bis_file\s*\(`, "is_file() - 检查是否为文件", ThreatLevelLow},
		{`(?i)\bis_link\s*\(`, "is_link() - 检查是否为符号链接", ThreatLevelMedium},
		{`(?i)\bis_writable\s*\(`, "is_writable() - 检查可写性", ThreatLevelLow},
		{`(?i)\bis_readable\s*\(`, "is_readable() - 检查可读性", ThreatLevelLow},
		{`(?i)\bfile_exists\s*\(`, "file_exists() - 检查文件存在", ThreatLevelLow},
		{`(?i)\bstat\s*\(`, "stat() - 文件状态", ThreatLevelLow},
		{`(?i)\bfilesort\s*\(`, "filesort() - 文件排序", ThreatLevelLow},
		{`(?i)\bgetimagesize\s*\(`, "getimagesize() - 图片信息", ThreatLevelLow},
		{`(?i)\bpathinfo\s*\(`, "pathinfo() - 路径信息", ThreatLevelLow},
		{`(?i)\bbasename\s*\(`, "basename() - 基名", ThreatLevelLow},
		{`(?i)\bdirname\s*\(`, "dirname() - 目录名", ThreatLevelLow},
		{`(?i)\bpathinfo\s*\([^)]*PATHINFO`, "pathinfo带PATHINFO_*", ThreatLevelLow},
		{`(?i)\brealpath\s*\(`, "realpath() - 解析路径", ThreatLevelMedium},
		{`(?i)\bZipArchive::addFile\s*\(`, "ZipArchive::addFile() - ZIP操作", ThreatLevelHigh},
		{`(?i)\bZipArchive::open\s*\(`, "ZipArchive::open() - ZIP打开", ThreatLevelHigh},
		{`(?i)\b Phar::loadPhar\s*\(`, "Phar::loadPhar() - PHAR操作", ThreatLevelCritical},
		{`(?i)\bPhar::mapPhar\s*\(`, "Phar::mapPhar() - PHAR映射", ThreatLevelCritical},
	}

	for _, p := range fileOpPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "验证文件路径;使用open_basedir限制",
			})
		}
	}
}

func (a *PHPAnalyzer) analyzeSSRF(data string, result *AnalysisResult) {
	ssrfPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\bfile_get_contents\s*\([^)]*http`, "file_get_contents带HTTP", ThreatLevelHigh},
		{`(?i)\bcurl_setopt\s*\([^)]*CURLOPT_URL`, "Curl URL设置", ThreatLevelHigh},
		{`(?i)\bcurl_exec\s*\(`, "curl_exec()", ThreatLevelHigh},
		{`(?i)\bfsockopen\s*\(`, "fsockopen() - 套接字连接", ThreatLevelHigh},
		{`(?i)\bpfsockopen\s*\(`, "pfsockopen() - 持久套接字", ThreatLevelHigh},
		{`(?i)\bget_headers\s*\(`, "get_headers() - HTTP响应头", ThreatLevelMedium},
		{`(?i)\bget_meta_tags\s*\(`, "get_meta_tags() - Meta标签提取", ThreatLevelMedium},
		{`(?i)\bhttp_build_query\s*\(`, "http_build_query()", ThreatLevelLow},
		{`(?i)\bstream_context_create\s*\(`, "stream_context_create()", ThreatLevelMedium},
		{`(?i)\bstream_socket_client\s*\(`, "stream_socket_client()", ThreatLevelHigh},
		{`(?i)\bstream_socket_server\s*\(`, "stream_socket_server()", ThreatLevelMedium},
		{`(?i)\bsocket_connect\s*\(`, "socket_connect()", ThreatLevelHigh},
		{`(?i)\bftp_connect\s*\(`, "ftp_connect()", ThreatLevelHigh},
		{`(?i)\bftp_login\s*\(`, "ftp_login()", ThreatLevelHigh},
		{`(?i)\bmysqli_connect\s*\(`, "mysqli_connect() - MySQL连接", ThreatLevelMedium},
		{`(?i)\bmysqli_real_connect\s*\(`, "mysqli_real_connect()", ThreatLevelMedium},
		{`(?i)\bpdo->prepare\s*\(`, "PDO prepare (SQL注入向量)", ThreatLevelHigh},
		{`(?i)\bmongo_connect\s*\(`, "MongoDB连接", ThreatLevelHigh},
		{`(?i)\bMemcache::connect\s*\(`, "Memcache连接", ThreatLevelMedium},
		{`(?i)\bMemcached::connect\s*\(`, "Memcached连接", ThreatLevelMedium},
		{`(?i)\bRedis::connect\s*\(`, "Redis连接", ThreatLevelMedium},
		{`(?i)\bRabbitMQ::connect\s*\(`, "RabbitMQ连接", ThreatLevelMedium},
		{`127\.0\.0\.1`, "本地IP引用", ThreatLevelMedium},
		{`(?i)localhost`, "本地主机名", ThreatLevelMedium},
		{`0x7f000001`, "十六进制编码的127.0.0.1", ThreatLevelHigh},
		{`(?i)\b@file\s*\(`, "静默文件操作(@)", ThreatLevelMedium},
		{`(?i)\bguzzlehttp\b.*http://`, "Guzzle HTTP客户端", ThreatLevelMedium},
		{`(?i)\bwp_remote_get\s*\(`, "WordPress远程GET", ThreatLevelMedium},
		{`(?i)\bwp_remote_post\s*\(`, "WordPress远程POST", ThreatLevelMedium},
		{`(?i)\bcurl_setopt_array\s*\(`, "curl_setopt_array()", ThreatLevelHigh},
		{`(?i)\bsoapcli_call\b`, "SOAP客户端调用", ThreatLevelMedium},
	}

	for _, p := range ssrfPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "验证URL;使用允许主机白名单",
			})
		}
	}
}

func (a *PHPAnalyzer) analyzeDeserialization(data string, result *AnalysisResult) {
	deserializePatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\bunserialize\s*\(`, "unserialize() - PHP对象反序列化", ThreatLevelCritical},
		{`(?i)\b__wakeup\s*\(`, "__wakeup()魔术方法", ThreatLevelHigh},
		{`(?i)\b__destruct\s*\(`, "__destruct()魔术方法", ThreatLevelHigh},
		{`(?i)\b__toString\s*\(`, "__toString()魔术方法", ThreatLevelHigh},
		{`(?i)\b__get\s*\(`, "__get()魔术方法", ThreatLevelMedium},
		{`(?i)\b__set\s*\(`, "__set()魔术方法", ThreatLevelMedium},
		{`(?i)\b__call\s*\(`, "__call()魔术方法", ThreatLevelMedium},
		{`(?i)\b__invoke\s*\(`, "__invoke()魔术方法", ThreatLevelMedium},
		{`(?i)\b__set_state\s*\(`, "__set_state()魔术方法", ThreatLevelMedium},
		{`(?i)\b__clone\s*\(`, "__clone()魔术方法", ThreatLevelLow},
		{`(?i)\b__sleep\s*\(`, "__sleep()魔术方法", ThreatLevelLow},
		{`O:\+?\d+:`, "序列化PHP对象 (base64或原始)", ThreatLevelCritical},
		{`C:\+?\d+:`, "序列化自定义对象", ThreatLevelCritical},
		{`a:\+?\d+:`, "序列化PHP数组", ThreatLevelMedium},
		{`s:\+?\d+:"`, "序列化PHP字符串", ThreatLevelMedium},
		{`(?i)\bvar_export\s*\(.*\$`, "var_export带变量", ThreatLevelMedium},
		{`(?i)\bvar_dump\s*\(.*\$`, "var_dump带变量", ThreatLevelMedium},
		{`(?i)\bprint_r\s*\(.*\$`, "print_r带变量", ThreatLevelMedium},
		{`(?i)\bdebug_zval_dump\s*\(`, "debug_zval_dump()", ThreatLevelMedium},
		{`(?i)\bdebug_print_backtrace\s*\(`, "debug_print_backtrace()", ThreatLevelLow},
		{`(?i)\b__debugInfo\s*\(`, "__debugInfo()魔术方法", ThreatLevelHigh},
		{`(?i)\b__set_raw_data\s*\(`, "__set_raw_data()魔术方法", ThreatLevelHigh},
		{`(?i)\b__get_raw_data\s*\(`, "__get_raw_data()魔术方法", ThreatLevelHigh},
	}

	for _, p := range deserializePatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "永远不要反序列化用户输入;使用JSON替代",
			})
		}
	}
}

func (a *PHPAnalyzer) analyzeLDAPInjection(data string, result *AnalysisResult) {
	ldapPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\bldap_connect\s*\(`, "ldap_connect()", ThreatLevelLow},
		{`(?i)\bldap_bind\s*\(`, "ldap_bind()", ThreatLevelMedium},
		{`(?i)\bldap_search\s*\(`, "ldap_search()", ThreatLevelMedium},
		{`(?i)\bldap_first_entry\s*\(`, "ldap_first_entry()", ThreatLevelLow},
		{`(?i)\bldap_next_entry\s*\(`, "ldap_next_entry()", ThreatLevelLow},
		{`(?i)\bldap_get_entries\s*\(`, "ldap_get_entries()", ThreatLevelLow},
		{`(?i)\*\)\(`, "LDAP通配符注入", ThreatLevelHigh},
		{`(?i)\(\w+=.*\*`, "LDAP属性注入", ThreatLevelHigh},
		{`(?i)\x00`, "NULL字节注入", ThreatLevelHigh},
		{`(?i)\.\./`, "LDAP DN路径遍历", ThreatLevelHigh},
		{`(?i)dc=`, "LDAP域组件注入", ThreatLevelMedium},
		{`(?i)ou=`, "LDAP组织单元注入", ThreatLevelMedium},
		{`(?i)cn=.*\*`, "LDAP通用名称注入", ThreatLevelMedium},
		{`(?i)\(\w+\)\(`, "LDAP过滤器注入", ThreatLevelHigh},
	}

	for _, p := range ldapPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "转义LDAP特殊字符;使用参数化查询",
			})
		}
	}
}

func (a *PHPAnalyzer) analyzeXMLInjection(data string, result *AnalysisResult) {
	xmlPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\bsimplexml_load_string\s*\(`, "simplexml_load_string()", ThreatLevelHigh},
		{`(?i)\bsimplexml_load_file\s*\(`, "simplexml_load_file()", ThreatLevelHigh},
		{`(?i)\bDOMDocument->loadXML\s*\(`, "DOMDocument loadXML()", ThreatLevelHigh},
		{`(?i)\bDOMDocument->load\s*\(`, "DOMDocument load()", ThreatLevelHigh},
		{`(?i)\bxml_parse\s*\(`, "xml_parse()", ThreatLevelMedium},
		{`(?i)\bxml_parser_create\s*\(`, "xml_parser_create()", ThreatLevelMedium},
		{`(?i)\bxml_set_object\s*\(`, "xml_set_object()", ThreatLevelMedium},
		{`(?i)<!\[\[CDATA\[`, "CDATA段注入", ThreatLevelMedium},
		{`(?i)<!DOCTYPE`, "DOCTYPE注入", ThreatLevelMedium},
		{`(?i)<!ENTITY`, "ENTITY声明注入", ThreatLevelCritical},
		{`(?i)SYSTEM\s+"`, "外部实体 (XXE)", ThreatLevelCritical},
		{`(?i)PUBLIC\s+"`, "外部实体PUBLIC", ThreatLevelCritical},
		{`(?i)php://filter`, "PHP过滤器包装器在XML中", ThreatLevelHigh},
		{`(?i)expect://`, "Expect协议包装器", ThreatLevelCritical},
		{`(?i)ogg://`, "Ogg协议包装器", ThreatLevelHigh},
		{`(?i)zip://`, "Zip协议包装器", ThreatLevelCritical},
		{`(?i) Phar://`, "Phar协议包装器", ThreatLevelCritical},
		{`(?i)\bSimpleXMLElement->asXML\s*\(`, "SimpleXML asXML()", ThreatLevelMedium},
		{`(?i)\bDOMDocument->saveXML\s*\(`, "DOMDocument saveXML()", ThreatLevelMedium},
		{`(?i)\bxinclude`, "XInclude注入", ThreatLevelHigh},
		{`(?i)xmlns\s*=\s*["']?http`, "XML命名空间注入", ThreatLevelMedium},
	}

	for _, p := range xmlPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "禁用外部实体;使用DOMDocument LIBXML_NOENT",
			})
		}
	}
}

func (a *PHPAnalyzer) analyzeMailInjection(data string, result *AnalysisResult) {
	mailPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\bmail\s*\(`, "mail()函数", ThreatLevelMedium},
		{`(?i)\bsendmail\s*\(`, "sendmail()", ThreatLevelMedium},
		{`(?i)\bmb_send_mail\s*\(`, "mb_send_mail()", ThreatLevelMedium},
		{`(?i)\bqmail_inject\s*\(`, "qmail_inject()", ThreatLevelMedium},
		{`(?i)\bimap_mail\s*\(`, "imap_mail()", ThreatLevelMedium},
		{`(?i)mailto:`, "mailto:协议", ThreatLevelMedium},
		{`%0a`, "换行符注入 (CRLF)", ThreatLevelHigh},
		{`%0d`, "回车符注入", ThreatLevelHigh},
		{`%0a%0a`, "双换行符注入", ThreatLevelCritical},
		{`(?i)Content-Type:`, "Content-Type头注入", ThreatLevelHigh},
		{`(?i)From:`, "From头注入", ThreatLevelHigh},
		{`(?i)To:`, "To头注入", ThreatLevelMedium},
		{`(?i)CC:`, "CC头注入", ThreatLevelMedium},
		{`(?i)BCC:`, "BCC头注入", ThreatLevelMedium},
		{`(?i)Subject:`, "Subject头注入", ThreatLevelMedium},
		{`(?i)\battachement`, "附件文件名注入", ThreatLevelHigh},
		{`(?i)\.phar`, "Phar存档注入", ThreatLevelHigh},
		{`(?i)\.phtml`, "PHP文件扩展名注入", ThreatLevelHigh},
		{`(?i)\r\n`, "CRLF序列", ThreatLevelHigh},
		{`(?i)\n`, "单独换行符", ThreatLevelMedium},
	}

	for _, p := range mailPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "验证和清理邮件头;剥离换行符",
			})
		}
	}
}

func (a *PHPAnalyzer) analyzepreg_replace(data string, result *AnalysisResult) {
	pregPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\bpreg_replace\s*\([^)]*/e`, "preg_replace带/e修饰符 (代码执行)", ThreatLevelCritical},
		{`(?i)\bpreg_replace\s*\([^)]*\$`, "preg_replace带变量模式", ThreatLevelHigh},
		{`(?i)\bpreg_match\s*\([^)]*\$`, "preg_match带变量模式", ThreatLevelMedium},
		{`(?i)\bpreg_match_all\s*\([^)]*\$`, "preg_match_all带变量", ThreatLevelMedium},
		{`(?i)\bpreg_split\s*\([^)]*\$`, "preg_split带变量", ThreatLevelMedium},
		{`(?i)\bpreg_grep\s*\([^)]*\$`, "preg_grep带变量", ThreatLevelMedium},
		{`(?i)\bpreg_replace_callback\s*\([^)]*\$`, "preg_replace_callback带变量", ThreatLevelHigh},
		{`(?i)\bmb_ereg_replace\s*\([^)]*\$`, "mb_ereg_replace带变量", ThreatLevelHigh},
		{`(?i)\bmb_eregi_replace\s*\([^)]*\$`, "mb_eregi_replace带变量", ThreatLevelHigh},
		{`(?i)\bstr_replace\s*\(.*\$`, "str_replace带变量", ThreatLevelMedium},
		{`(?i)\bstr_ireplace\s*\(.*\$`, "str_ireplace带变量", ThreatLevelMedium},
		{`(?i)\bsubstr_replace\s*\(.*\$`, "substr_replace带变量", ThreatLevelMedium},
		{`(?i)\bpreg_replace_callback_array\s*\(`, "preg_replace_callback_array()", ThreatLevelHigh},
		{`(?i)\bmb_ereg_replace_callback\s*\(`, "mb_ereg_replace_callback()", ThreatLevelHigh},
	}

	for _, p := range pregPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "使用模式白名单;避免动态regex来自用户输入",
			})
		}
	}
}

func (a *PHPAnalyzer) analyzeassert(data string, result *AnalysisResult) {
	assertPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\bassert\s*\(\s*\$`, "assert()带变量", ThreatLevelCritical},
		{`(?i)\bassert\s*\(\s*\$_\w+`, "assert()带用户变量", ThreatLevelCritical},
		{`(?i)\bassert\s*\(\s*\$GLOBALS`, "assert()带$GLOBALS", ThreatLevelCritical},
		{`(?i)\bassert\s*\(\s*\$_GET`, "assert()带$_GET", ThreatLevelCritical},
		{`(?i)\bassert\s*\(\s*\$_POST`, "assert()带$_POST", ThreatLevelCritical},
		{`(?i)\bassert\s*\(\s*\$_REQUEST`, "assert()带$_REQUEST", ThreatLevelCritical},
		{`(?i)\bassert\s*\(\s*\$_COOKIE`, "assert()带$_COOKIE", ThreatLevelCritical},
		{`(?i)\bassert\s*\(\s*\$_SESSION`, "assert()带$_SESSION", ThreatLevelCritical},
		{`(?i)\bassert_options\s*\(`, "assert_options() - 断言配置", ThreatLevelHigh},
		{`(?i)\bassert_options\s*\(\s*2\s*,`, "assert_options启用断言", ThreatLevelHigh},
	}

	for _, p := range assertPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "永远不要assert()用户输入;在生产环境禁用断言",
			})
		}
	}
}

func (a *PHPAnalyzer) analyzeDynamicProperties(data string, result *AnalysisResult) {
	dynamicPropPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\$\w+\[\$\w+\]`, "可变变量数组访问", ThreatLevelHigh},
		{`\$\w+->\{\$\w+\}`, "通过变量的动态属性访问", ThreatLevelHigh},
		{`(?i)\b\$_GET\s*\[`, "$_GET数组访问", ThreatLevelMedium},
		{`(?i)\b\$_POST\s*\[`, "$_POST数组访问", ThreatLevelMedium},
		{`(?i)\b\$_REQUEST\s*\[`, "$_REQUEST数组访问", ThreatLevelMedium},
		{`(?i)\b\$_COOKIE\s*\[`, "$_COOKIE数组访问", ThreatLevelMedium},
		{`(?i)\b\$_SERVER\s*\[`, "$_SERVER数组访问", ThreatLevelMedium},
		{`(?i)\b\$_SESSION\s*\[`, "$_SESSION数组访问", ThreatLevelMedium},
		{`(?i)\b\$_FILES\s*\[`, "$_FILES数组访问", ThreatLevelMedium},
		{`(?i)\b\$_ENV\s*\[`, "$_ENV数组访问", ThreatLevelMedium},
		{`(?i)\b\$GLOBALS\s*\[`, "$GLOBALS数组访问", ThreatLevelHigh},
		{`(?i)\b\$_GET\s*\(\s*\$`, "$_GET函数调用变量", ThreatLevelHigh},
		{`(?i)\b\$_POST\s*\(\s*\$`, "$_POST函数调用变量", ThreatLevelHigh},
		{`(?i)\b\$_REQUEST\s*\(\s*\$`, "$_REQUEST函数调用变量", ThreatLevelHigh},
	}

	for _, p := range dynamicPropPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "使用静态属性访问;验证数组键",
			})
		}
	}
}

func (a *PHPAnalyzer) analyzeTypeJuggling(data string, result *AnalysisResult) {
	jugglingPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\btrim\s*\(\s*\$`, "trim()带变量", ThreatLevelLow},
		{`(?i)\bin_array\s*\([^)]*true\b`, "in_array带strict=false (类型转换)", ThreatLevelHigh},
		{`(?i)\bin_array\s*\([^)]*TRUE\b`, "in_array带TRUE (类型转换)", ThreatLevelHigh},
		{`(?i)\bin_array\s*\([^)]*1\b`, "in_array带1 (类型转换)", ThreatLevelHigh},
		{`(?i)\bstrcmp\s*\([^)]*\$`, "strcmp带变量", ThreatLevelMedium},
		{`(?i)\bstrcasecmp\s*\([^)]*\$`, "strcasecmp带变量", ThreatLevelMedium},
		{`(?i)\bhash_equals\s*\([^)]*\$`, "hash_equals (时序攻击)", ThreatLevelLow},
		{`(?i)\bctype_digit\s*\([^)]*\$`, "ctype_digit带变量", ThreatLevelMedium},
		{`(?i)\bis_numeric\s*\([^)]*\$`, "is_numeric带变量", ThreatLevelMedium},
		{`(?i)\bis_int\s*\([^)]*\$`, "is_int带变量", ThreatLevelMedium},
		{`(?i)\bis_string\s*\([^)]*\$`, "is_string带变量", ThreatLevelLow},
		{`(?i)\bis_array\s*\([^)]*\$`, "is_array带变量", ThreatLevelLow},
		{`(?i)\bis_null\s*\([^)]*\$`, "is_null带变量", ThreatLevelLow},
		{`(?i)\bis_bool\s*\([^)]*\$`, "is_bool带变量", ThreatLevelLow},
		{`(?i)\bis_float\s*\([^)]*\$`, "is_float带变量", ThreatLevelLow},
		{`(?i)\bis_object\s*\([^)]*\$`, "is_object带变量", ThreatLevelLow},
		{`(?i)\bsettype\s*\([^)]*\$`, "settype() - 类型强制转换", ThreatLevelMedium},
		{`(?i)\bintval\s*\([^)]*\$`, "intval() - 整数转换", ThreatLevelMedium},
		{`(?i)\bstrval\s*\([^)]*\$`, "strval() - 字符串转换", ThreatLevelLow},
		{`(?i)\bfloatval\s*\([^)]*\$`, "floatval() - 浮点转换", ThreatLevelMedium},
		{`(?i)\bboolval\s*\([^)]*\$`, "boolval() - 布尔转换", ThreatLevelLow},
		{`(?i)\bempty\s*\(\s*\$`, "empty()带变量", ThreatLevelMedium},
		{`(?i)\bisset\s*\(\s*\$`, "isset()带变量", ThreatLevelLow},
		{`(?i)\bunset\s*\(\s*\$`, "unset()带变量", ThreatLevelMedium},
	}

	for _, p := range jugglingPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "使用严格比较(===);避免类型转换",
			})
		}
	}
}

func (a *PHPAnalyzer) analyzePathTraversal(data string, result *AnalysisResult) {
	pathTraversalPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\.\./`, "路径遍历: ../", ThreatLevelCritical},
		{`(?i)\.\.\\/`, "路径遍历: ../ (反斜杠)", ThreatLevelCritical},
		{`%2e%2e/`, "URL编码的../", ThreatLevelCritical},
		{`%2e%2e\\/`, "URL编码的../ (反斜杠)", ThreatLevelCritical},
		{`%2e./`, "双重编码 .%2e/", ThreatLevelCritical},
		{`%2e.\\/`, "双重编码 .%2e\\", ThreatLevelCritical},
		{`%2e%2e%255`, "双重编码 ..%255", ThreatLevelCritical},
		{`(?i)\.\./\.\./`, "多重路径遍历", ThreatLevelCritical},
		{`(?i)/etc/passwd`, "引用/etc/passwd", ThreatLevelCritical},
		{`(?i)/etc/shadow`, "引用/etc/shadow", ThreatLevelCritical},
		{`(?i)/etc/hosts`, "引用/etc/hosts", ThreatLevelMedium},
		{`c:\\windows`, "Windows路径: c:\\windows", ThreatLevelHigh},
		{`c:\\boot\.ini`, "Windows boot.ini", ThreatLevelMedium},
		{`(?i)\.\./\.\./\.\./`, "深度路径遍历", ThreatLevelCritical},
		{`%c0%ae%c0%ae/`, "Unicode路径遍历 (C0)", ThreatLevelCritical},
		{`%c1%9c`, "Unicode反斜杠 (C1)", ThreatLevelCritical},
		{`(?i)\.\./\|/etc/passwd`, "路径遍历+passwd", ThreatLevelCritical},
		{`(?i)php://input`, "PHP输入包装器", ThreatLevelHigh},
		{`(?i)php://filter`, "PHP过滤器包装器", ThreatLevelHigh},
		{`(?i)data://`, "Data URI方案", ThreatLevelHigh},
		{`(?i)expect://`, "Expect协议", ThreatLevelCritical},
		{`(?i)zip://`, "Zip包装器", ThreatLevelHigh},
		{`(?i)phar://`, "Phar包装器", ThreatLevelHigh},
		{`(?i)glob://`, "Glob包装器", ThreatLevelMedium},
		{`(?i)ssh2://`, "SSH2包装器", ThreatLevelHigh},
		{`(?i)\.\.\.%00`, "路径遍历+NULL字节", ThreatLevelCritical},
		{`(?i)\.\./\.\./\.\./\.\./`, "四重路径遍历", ThreatLevelCritical},
	}

	for _, p := range pathTraversalPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "使用realpath()验证;限制open_basedir",
			})
		}
	}
}

func (a *PHPAnalyzer) analyzeServerSideInjection(data string, result *AnalysisResult) {
	ssiPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)<\?php\s+echo`, "PHP服务器端echo", ThreatLevelHigh},
		{`(?i)<\?=\s*\$`, "PHP短echo带变量", ThreatLevelHigh},
		{`(?i)<script\s+language\s*=\s*["']?php`, "脚本PHP标签", ThreatLevelHigh},
		{`(?i)<%\s*echo`, "ASP风格PHP标签", ThreatLevelMedium},
		{`(?i)<%\s*=\s*\$`, "ASP风格PHP短echo", ThreatLevelMedium},
		{`(?i)\?>\s*<?php`, "交替PHP标签切换", ThreatLevelMedium},
		{`(?i)\bCookie\s*:`, "HTTP Cookie头", ThreatLevelMedium},
		{`(?i)\bUser-Agent\s*:`, "HTTP User-Agent头", ThreatLevelMedium},
		{`(?i)\bAccept\s*:`, "HTTP Accept头", ThreatLevelLow},
		{`(?i)\bReferer\s*:`, "HTTP Referer头", ThreatLevelMedium},
		{`(?i)\bX-Forwarded-For\s*:`, "X-Forwarded-For头", ThreatLevelMedium},
		{`(?i)\bX-Real-IP\s*:`, "X-Real-IP头", ThreatLevelMedium},
		{`(?i)\bHost\s*:`, "HTTP Host头", ThreatLevelMedium},
		{`(?i)\bAuthorization\s*:`, "HTTP Authorization头", ThreatLevelMedium},
		{`(?i)<\?xml`, "XML标签注入", ThreatLevelMedium},
		{`(?i)<php`, "PHP标签注入", ThreatLevelHigh},
	}

	for _, p := range ssiPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "验证和转义所有用户可控头",
			})
		}
	}
}

func (a *PHPAnalyzer) analyzePHP8Specific(data string, result *AnalysisResult) {
	php8Patterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\bmysqli_execute\s*\(`, "mysqli_execute() - MySQLi执行", ThreatLevelMedium},
		{`(?i)\bmysqli_stmt_execute\s*\(`, "mysqli_stmt_execute() - MySQLi预处理执行", ThreatLevelMedium},
		{`(?i)\bFibers?\s*\(`, "Fiber::start() - PHP 8.1+协程", ThreatLevelMedium},
		{`(?i)\bmatch\s*\(\s*\$`, "match表达式带变量 (PHP 8.0)", ThreatLevelMedium},
		{`(?i)\bnullsafe\s*->`, "nullsafe操作符 ?->", ThreatLevelLow},
		{`(?i)\bNamedArguments\s*\(`, "命名参数 (PHP 8.0)", ThreatLevelLow},
		{`(?i)\bAttribute\s*\(`, "属性 (PHP 8.0)", ThreatLevelLow},
		{`(?i)\bunion\s+types\s*:`, "联合类型 (PHP 8.0)", ThreatLevelLow},
		{`(?i)\bnever\s+return\s*:`, "never返回类型 (PHP 8.1)", ThreatLevelLow},
		{`(?i)\benum\s*\$`, "枚举 (PHP 8.1)", ThreatLevelLow},
		{`(?i)\breadonly\s*\$`, "readonly属性 (PHP 8.1)", ThreatLevelLow},
		{`(?i)\bfirst_class_callable\s*\(`, "first_class_callable (PHP 8.1)", ThreatLevelLow},
		{`(?i)\bphpinfo\s*\(`, "phpinfo() - 信息泄露", ThreatLevelMedium},
		{`(?i)\bget_defined_vars\b`, "get_defined_vars() - 变量泄露", ThreatLevelMedium},
	}

	for _, p := range php8Patterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "谨慎使用新特性;防止信息泄露",
			})
		}
	}
}

func (a *PHPAnalyzer) analyzeOPcacheBypass(data string, result *AnalysisResult) {
	opcachePatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)opcache\.enable\s*=\s*0`, "OPcache禁用", ThreatLevelMedium},
		{`(?i)opcache_get_configuration\s*\(`, "OPcache配置获取", ThreatLevelMedium},
		{`(?i)opcache_get_status\s*\(`, "OPcache状态获取", ThreatLevelMedium},
		{`(?i)opcache_compile_file\s*\(`, "OPcache编译文件", ThreatLevelHigh},
		{`(?i)opcache_invalidate\s*\(`, "OPcache使缓存失效", ThreatLevelHigh},
		{`(?i)opcache_reset\s*\(`, "OPcache重置", ThreatLevelCritical},
		{`(?i)/tmp/php沙盒`, "PHP临时文件操作", ThreatLevelHigh},
		{`(?i)\/var\/tmp\/php`, "PHP临时文件操作", ThreatLevelHigh},
		{`(?i)\/proc\/self\/environ`, "进程环境文件读取", ThreatLevelHigh},
		{`(?i)\/proc\/self\/fd/`, "进程文件描述符访问", ThreatLevelHigh},
	}

	for _, p := range opcachePatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "保护OPcache配置;禁用危险函数",
			})
		}
	}
}

func (a *PHPAnalyzer) analyzePharDeserialization(data string, result *AnalysisResult) {
	pharPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\bphar://`, "Phar协议触发反序列化", ThreatLevelCritical},
		{`(?i)\bphar::setStub\s*\(`, "Phar::setStub()设置存根", ThreatLevelHigh},
		{`(?i)\bphar::getStub\s*\(`, "Phar::getStub()获取存根", ThreatLevelMedium},
		{`(?i)\bphar::getMetadata\s*\(`, "Phar::getMetadata()获取元数据", ThreatLevelHigh},
		{`(?i)\bPharData::addFile\s*\(`, "PharData::addFile()添加文件", ThreatLevelHigh},
		{`(?i)\bPharData::__construct\s*\(`, "PharData::__construct()构造", ThreatLevelHigh},
		{`(?i)\bSplFileInfo::getFilename\s*\(`, "SplFileInfo::getFilename()获取文件名", ThreatLevelMedium},
		{`(?i)\bSplFileObject::fopen\s*\(`, "SplFileObject::fopen()文件操作", ThreatLevelHigh},
		{`(?i)\.phar`, "Phar文件扩展名", ThreatLevelMedium},
		{`(?i)zip://.*#`, "Zip包装器Phar伪协议", ThreatLevelCritical},
		{`(?i)tar://`, "Tar包装器Phar伪协议", ThreatLevelCritical},
		{`(?i) Phar://manifest_files`, "Phar清单文件注入", ThreatLevelCritical},
		{`(?i)\/phar\.phar`, "Phar文件路径", ThreatLevelMedium},
		{`(?i)serialize\.callback_filter`, "序列化回调过滤器", ThreatLevelCritical},
	}

	for _, p := range pharPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "禁用Phar协议;禁止对象反序列化用户输入",
			})
		}
	}
}

func (a *PHPAnalyzer) analyzeCommandInjection(data string, result *AnalysisResult) {
	cmdPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\bsystem\s*\(\s*\$`, "system()命令执行", ThreatLevelCritical},
		{`(?i)\bexec\s*\(\s*\$`, "exec()命令执行", ThreatLevelCritical},
		{`(?i)\bshell_exec\s*\(\s*\$`, "shell_exec()命令执行", ThreatLevelCritical},
		{`(?i)\bpopen\s*\(\s*\$`, "popen()命令执行", ThreatLevelCritical},
		{`(?i)\bproc_open\s*\(\s*\$`, "proc_open()命令执行", ThreatLevelCritical},
		{`(?i)\bpassthru\s*\(\s*\$`, "passthru()命令执行", ThreatLevelCritical},
		{`(?i)\bpcntl_exec\s*\(\s*\$`, "pcntl_exec()命令执行", ThreatLevelCritical},
		{`(?i)\bproc_close\s*\(\s*\$`, "proc_close()进程关闭", ThreatLevelMedium},
		{`(?i)\bproc_terminate\s*\(\s*\$`, "proc_terminate()进程终止", ThreatLevelMedium},
		{`(?i)\bproc_get_status\s*\(\s*\$`, "proc_get_status()进程状态", ThreatLevelMedium},
		{`(?i)\bproc_nice\s*\(\s*\$`, "proc_nice()进程优先级", ThreatLevelLow},
		{`(?i)escapeshellcmd\s*\(\s*\$`, "escapeshellcmd()转义", ThreatLevelMedium},
		{`(?i)escapeshellarg\s*\(\s*\$`, "escapeshellarg()转义", ThreatLevelMedium},
		{`(?i)\bwget\s+`, "wget命令执行", ThreatLevelCritical},
		{`(?i)\bcurl\s+`, "curl命令执行", ThreatLevelCritical},
		{`(?i)\bbash\s+-c\s+`, "bash -c命令执行", ThreatLevelCritical},
		{`(?i)\bsh\s+-c\s+`, "sh -c命令执行", ThreatLevelCritical},
		{`(?i)\bpython\s+-c\s+`, "python -c命令执行", ThreatLevelCritical},
		{`(?i)\bperl\s+-e\s+`, "perl -e命令执行", ThreatLevelCritical},
		{`(?i)\bruby\s+-e\s+`, "ruby -e命令执行", ThreatLevelCritical},
		{`(?i)\bnc\s+-e\s+`, "netcat -e命令执行", ThreatLevelCritical},
		{`(?i)\brm\s+-rf\s+\/`, "递归删除根目录", ThreatLevelCritical},
		{`(?i)\bmkfs\.`, "格式化命令", ThreatLevelCritical},
		{`(?i)\bdd\s+.*of\s*=\/`, "直接写入设备", ThreatLevelCritical},
	}

	for _, p := range cmdPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "禁止命令执行函数;使用白名单验证输入",
			})
		}
	}
}
