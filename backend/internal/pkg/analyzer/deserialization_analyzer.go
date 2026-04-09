package analyzer

import (
	"encoding/base64"
	"regexp"
	"strings"
	"sync"
	"time"
)

type DeserializationAnalyzer struct {
	name             string
	version          string
	analyzerType     string
	enabled          bool
	config           map[string]interface{}
	dangerousClasses []string
	mu               sync.RWMutex
}

func NewDeserializationAnalyzer() *DeserializationAnalyzer {
	return &DeserializationAnalyzer{
		name:         "deserialization_analyzer",
		version:      "1.0.0",
		analyzerType: "deserialization",
		enabled:      true,
		config:       make(map[string]interface{}),
		dangerousClasses: []string{
			"java.beans.EventHandler",
			"java.lang.ProcessBuilder",
			"java.lang.Runtime",
			"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
			"org.apache.commons.collections.Transformer",
			"org.apache.commons.collections.functors.InvokerTransformer",
			"org.apache.commons.collections.functors.ChainedTransformer",
			"org.apache.commons.collections.functors.ConstantTransformer",
			"org.apache.commons.collections.functors.InstantiateTransformer",
			"org.apache.commons.collections.functors.InstantiateTransformer",
			"org.apache.commons.configuration.JNDIConfiguration",
			"org.apache.commons.configuration2.JNDIConfiguration",
			"org.apache.wicket.util.parse弥合",
			"com.sun.rowset.JdbcRowSetImpl",
			"com.sun.deploy.security.ruleset",
			"sun.rmi.server.UnicastRef",
			"sun.rmi.server.UnicastRef",
			"java.rmi.registry.Registry",
			"java.rmi.server.RemoteObjectInvocationHandler",
			"javax.naming.ldap.LdapName",
			"javax.naming.ldap.Rdn",
			"org.springframework.beans.factory.ObjectFactory",
			"org.springframework.beans.factory.config.PropertyPathFactory",
			"org.springframework.core.SerializableTypeWrapper",
			"org.springframework.transaction.support.AbstractPlatformTransactionManager",
			"com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase",
			"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource",
			"oracle.jdbc.connector.OracleGeneratedPhysicalConnection",
			"org.apache.xalan.xsltc.trax.TemplatesImpl",
		},
	}
}

func (a *DeserializationAnalyzer) Name() string {
	return a.name
}

func (a *DeserializationAnalyzer) Type() string {
	return a.analyzerType
}

func (a *DeserializationAnalyzer) Version() string {
	return a.version
}

func (a *DeserializationAnalyzer) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

func (a *DeserializationAnalyzer) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

func (a *DeserializationAnalyzer) Configure(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if classes, ok := config["dangerous_classes"].([]string); ok {
		a.dangerousClasses = classes
	}
	a.config = config
	return nil
}

func (a *DeserializationAnalyzer) Analyze(input *AnalysisInput) *AnalysisResult {
	start := time.Now()
	result := NewAnalysisResult(a)

	if input == nil || input.Raw == "" {
		return result
	}

	dataToAnalyze := a.prepareData(input)

	a.analyzeJavaDeserialization(dataToAnalyze, result)
	a.analyzePHPSerialization(dataToAnalyze, result)
	a.analyzePythonSerialization(dataToAnalyze, result)
	a.analyzeDotNetSerialization(dataToAnalyze, result)
	a.analyzeGadgetChainPatterns(dataToAnalyze, result)
	a.analyzeMagicBytes(dataToAnalyze, result)
	a.analyzeKnownExploitPatterns(dataToAnalyze, result)

	result.ProcessingTime = time.Since(start)
	result.ShouldBlock = result.ShouldBlockRequest(0.5)
	if len(result.Matches) > 0 {
		result.ShouldLog = true
		result.ShouldAllow = !result.ShouldBlock
	}

	return result
}

func (a *DeserializationAnalyzer) prepareData(input *AnalysisInput) string {
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

func (a *DeserializationAnalyzer) analyzeJavaDeserialization(data string, result *AnalysisResult) {
	javaPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\xac\xed\x00\x05`, "Java序列化魔术字节 (STREAM_MAGIC)", ThreatLevelCritical},
		{`ac\xed\x00\x05`, "Java序列化头部", ThreatLevelCritical},
		{`(?i)rO0AB`, "Base64编码Java序列化 (RObject)", ThreatLevelCritical},
		{`(?i)yv66`, "Base64变形Java序列化", ThreatLevelCritical},
		{`(?i)ObjectInputStream`, "Java对象输入流", ThreatLevelHigh},
		{`(?i)ObjectInputStream`, "Java反序列化", ThreatLevelHigh},
		{`(?i)readObject\s*\(`, "反序列化方法调用", ThreatLevelHigh},
		{`(?i)readUnshared\s*\(`, "反序列化方法调用", ThreatLevelHigh},
		{`(?i)java\.lang\.ProcessBuilder`, "Java ProcessBuilder类", ThreatLevelCritical},
		{`(?i)java\.lang\.Runtime`, "Java Runtime类", ThreatLevelCritical},
		{`(?i)javax\.script\.ScriptEngineManager`, "Java ScriptEngineManager", ThreatLevelHigh},
		{`(?i)java\.beans\.EventHandler`, "Java EventHandler", ThreatLevelCritical},
		{`(?i)sun\.misc\.Base64Decoder`, "Base64解码器", ThreatLevelMedium},
		{`(?i)com\.sun\.rowset\.JdbcRowSetImpl`, "JDBC RowSet gadget", ThreatLevelCritical},
		{`(?i)com\.sun\.org\.apache\.xalan`, "Xalan XSLTC gadget", ThreatLevelCritical},
		{`(?i)org\.apache\.commons\.collections\.Transformer`, "Commons Collections gadget", ThreatLevelCritical},
		{`(?i)org\.apache\.commons\.collections\.functors`, "Commons Functors gadget", ThreatLevelCritical},
		{`(?i)InvokerTransformer`, "反射调用gadget", ThreatLevelCritical},
		{`(?i)ChainedTransformer`, "链式转换gadget", ThreatLevelCritical},
		{`(?i)ConstantTransformer`, "常量转换gadget", ThreatLevelCritical},
		{`(?i)InstantiateTransformer`, "实例化转换gadget", ThreatLevelCritical},
		{`(?i)TransformedMap`, "转换Map gadget", ThreatLevelCritical},
		{`(?i)LazyMap`, "延迟Map gadget", ThreatLevelCritical},
		{`(?i)TiedMapEntry`, "TiedMapEntry gadget", ThreatLevelCritical},
		{`(?i)HashMap`, "HashMap反序列化", ThreatLevelHigh},
		{`(?i)HashSet`, "HashSet反序列化", ThreatLevelHigh},
		{`(?i)ArrayList`, "ArrayList反序列化", ThreatLevelMedium},
		{`(?i)LinkedList`, "LinkedList反序列化", ThreatLevelMedium},
		{`(?i)Hashtable`, "Hashtable反序列化", ThreatLevelMedium},
		{`(?i)TreeMap`, "TreeMap反序列化", ThreatLevelMedium},
		{`(?i)TreeSet`, "TreeSet反序列化", ThreatLevelMedium},
		{`(?i)PriorityQueue`, "PriorityQueue反序列化", ThreatLevelMedium},
	}

	for _, p := range javaPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Java反序列化威胁 - " + p.description,
				Recommendation: "禁用Java反序列化或使用白名单",
			})
		}
	}

	for _, class := range a.dangerousClasses {
		if strings.Contains(data, class) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelCritical,
				Pattern:        class,
				Description:    "危险Gadget类: " + class,
				Recommendation: "阻止包含危险类的序列化数据",
			})
		}
	}
}

func (a *DeserializationAnalyzer) analyzePHPSerialization(data string, result *AnalysisResult) {
	phpPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)O:\d+:"[^"]+":\d+:`, "PHP对象序列化", ThreatLevelHigh},
		{`(?i)O:13:"Serializable":0:{}`, "PHP Serializable接口", ThreatLevelHigh},
		{`(?i)C:\d+:"[^"]+":\d+:`, "PHP自定义序列化", ThreatLevelHigh},
		{`(?i)a:\d+:\{`, "PHP数组序列化", ThreatLevelMedium},
		{`(?i)s:\d+:"[^"]*"`, "PHP字符串序列化", ThreatLevelMedium},
		{`(?i)i:\d+;`, "PHP整数序列化", ThreatLevelLow},
		{`(?i)d:\d+\.\d+;`, "PHP双精度序列化", ThreatLevelLow},
		{`(?i)N;`, "PHP NULL序列化", ThreatLevelLow},
		{`(?i>b:\d+;)`, "PHP布尔序列化", ThreatLevelLow},
		{`(?i)__wakeup\s*\(`, "PHP __wakeup魔术方法", ThreatLevelHigh},
		{`(?i)__destruct\s*\(`, "PHP __destruct魔术方法", ThreatLevelHigh},
		{`(?i)__toString\s*\(`, "PHP __toString魔术方法", ThreatLevelHigh},
		{`(?i)__call\s*\(`, "PHP __call魔术方法", ThreatLevelHigh},
		{`(?i)unserialize\s*\(`, "PHP反序列化调用", ThreatLevelCritical},
		{`(?i)eval\s*\(\s*\$`, "PHP eval动态执行", ThreatLevelCritical},
		{`(?i)system\s*\(`, "PHP system命令执行", ThreatLevelCritical},
		{`(?i)exec\s*\(`, "PHP exec命令执行", ThreatLevelCritical},
		{`(?i)passthru\s*\(`, "PHP passthru命令执行", ThreatLevelCritical},
		{`(?i)shell_exec\s*\(`, "PHP shell_exec命令执行", ThreatLevelCritical},
		{`(?i)proc_open\s*\(`, "PHP proc_open进程执行", ThreatLevelHigh},
		{`(?i)popen\s*\(`, "PHP popen进程执行", ThreatLevelHigh},
		{`(?i)assert\s*\(`, "PHP assert代码执行", ThreatLevelCritical},
		{`(?i)preg_replace\s*\(\s*.*e`, "PHP preg_replace /e修饰符", ThreatLevelCritical},
		{`(?i>create_function\s*\(`, "PHP create_function代码生成", ThreatLevelHigh},
		{`(?i)call_user_func\s*\(`, "PHP回调函数", ThreatLevelHigh},
		{`(?i)call_user_func_array\s*\(`, "PHP回调数组函数", ThreatLevelHigh},
		{`(?i)array_map\s*\(`, "PHP数组映射函数", ThreatLevelMedium},
		{`(?i)file_get_contents\s*\(`, "PHP文件读取", ThreatLevelMedium},
		{`(?i)fopen\s*\(`, "PHP文件打开", ThreatLevelMedium},
		{`(?i)include\s+`, "PHP include文件包含", ThreatLevelHigh},
		{`(?i)include_once\s+`, "PHP include_once文件包含", ThreatLevelHigh},
		{`(?i)require\s+`, "PHP require文件包含", ThreatLevelHigh},
		{`(?i)require_once\s+`, "PHP require_once文件包含", ThreatLevelHigh},
		{`(?i)base64_decode\s*\(`, "PHP Base64解码", ThreatLevelMedium},
		{`(?i)gzuncompress\s*\(`, "PHP压缩解压", ThreatLevelMedium},
		{`(?i)gzinflate\s*\(`, "PHP压缩解压", ThreatLevelMedium},
		{`(?i) Phar://`, "PHP Phar协议", ThreatLevelCritical},
		{`(?i)C:42:"ArrayObject"`, "PHP ArrayObject", ThreatLevelMedium},
	}

	for _, p := range phpPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "PHP反序列化威胁 - " + p.description,
				Recommendation: "禁用PHP反序列化或使用安全替代方案",
			})
		}
	}

	if strings.Contains(data, "C:47:\"Doctrine\\\\") || strings.Contains(data, "C:49:\"Symfony\\\\") {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelCritical,
			Pattern:        "php_doctrine_or_symfony",
			Description:    "Doctrine/Symfony反序列化gadget链",
			Recommendation: "阻止包含框架特定gadget的序列化数据",
		})
	}

	phpObjectInjections := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`O:\d+:"[^"]*Exception":\d+:\{`, "PHP异常对象注入", ThreatLevelHigh},
		{`O:\d+:"[^"]*Error":\d+:\{`, "PHP错误对象注入", ThreatLevelHigh},
		{`O:\d+:"[^"]*ArrayObject":\d+:\{`, "PHP ArrayObject注入", ThreatLevelHigh},
		{`O:\d+:"[^"]*SplFileObject":\d+:\{`, "PHP SplFileObject注入", ThreatLevelCritical},
		{`O:\d+:"[^"]*SplStack":\d+:\{`, "PHP SplStack注入", ThreatLevelHigh},
		{`O:\d+:"[^"]*SplDoublyLinkedList":\d+:\{`, "PHP LinkedList注入", ThreatLevelHigh},
	}

	for _, p := range phpObjectInjections {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "PHP对象注入 - " + p.description,
				Recommendation: "验证反序列化输入类型",
			})
		}
	}
}

func (a *DeserializationAnalyzer) analyzePythonSerialization(data string, result *AnalysisResult) {
	pythonPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)pickle\.loads?\s*\(`, "Python pickle反序列化", ThreatLevelCritical},
		{`(?i)pickle\.load\s*\(`, "Python pickle.load反序列化", ThreatLevelCritical},
		{`(?i)cpickle\.loads?\s*\(`, "Python cpickle反序列化", ThreatLevelCritical},
		{`(?i)__reduce__\s*\(`, "Python __reduce__方法", ThreatLevelCritical},
		{`(?i)__reduce_ex__\s*\(`, "Python __reduce_ex__方法", ThreatLevelCritical},
		{`(?i)__getstate__\s*\(`, "Python __getstate__方法", ThreatLevelHigh},
		{`(?i)__setstate__\s*\(`, "Python __setstate__方法", ThreatLevelHigh},
		{`(?i)marshal\.loads?\s*\(`, "Python marshal反序列化", ThreatLevelCritical},
		{`(?i)shelve\.open\s*\(`, "Python shelve反序列化", ThreatLevelHigh},
		{`(?i)yaml\.load\s*\(`, "Python YAML反序列化", ThreatLevelCritical},
		{`(?i)yaml\.unsafe_load\s*\(`, "Python不安全YAML加载", ThreatLevelCritical},
		{`(?i)eval\s*\(.*\(`, "Python eval动态执行", ThreatLevelCritical},
		{`(?i>exec\s*\(`, "Python exec动态执行", ThreatLevelCritical},
		{`(?i)subprocess`, "Python subprocess模块", ThreatLevelHigh},
		{`(?i)os\.system\s*\(`, "Python os.system命令执行", ThreatLevelCritical},
		{`(?i)os\.popen\s*\(`, "Python os.popen命令执行", ThreatLevelHigh},
		{`(?i)os\.spawn`, "Python os.spawn进程", ThreatLevelHigh},
		{`(?i)pty\.spawn`, "Python pty.spawn伪终端", ThreatLevelHigh},
		{`(?i)multiprocessing`, "Python多进程模块", ThreatLevelMedium},
		{`(?i>threading`, "Python线程模块", ThreatLevelMedium},
		{`(?i)import\s+os`, "Python os模块导入", ThreatLevelMedium},
		{`(?i>import\s+subprocess`, "Python subprocess导入", ThreatLevelMedium},
		{`(?i>import\s+sys`, "Python sys模块导入", ThreatLevelMedium},
		{`(?i>__import__\s*\(`, "Python动态导入", ThreatLevelHigh},
		{`(?i)getattr\s*\(`, "Python getattr动态属性访问", ThreatLevelHigh},
		{`(?i)setattr\s*\(`, "Python setattr动态属性设置", ThreatLevelHigh},
		{`(?i)delattr\s*\(`, "Python delattr动态属性删除", ThreatLevelMedium},
		{`(?i>hasattr\s*\(`, "Python hasattr属性检查", ThreatLevelMedium},
		{`(?i)compile\s*\(`, "Python compile代码编译", ThreatLevelHigh},
		{`(?i)input\s*\(`, "Python input用户输入", ThreatLevelMedium},
		{`(?i)open\s*\(.*\)`, "Python文件操作", ThreatLevelHigh},
		{`(?i)file\s*\(`, "Python file文件操作", ThreatLevelHigh},
		{`(?i)memoryview\s*\(`, "Python memoryview", ThreatLevelMedium},
		{`(?i>types\.FunctionType`, "Python函数类型", ThreatLevelHigh},
		{`(?i>lambda.*:`, "Python lambda函数", ThreatLevelMedium},
		{`(?i)builtins`, "Pythonbuiltins模块", ThreatLevelHigh},
		{`(?i)__globals__`, "Python全局命名空间", ThreatLevelHigh},
		{`(?i)__code__`, "Python代码对象", ThreatLevelHigh},
		{`(?i>__builtins__`, "Python内置函数", ThreatLevelHigh},
		{`(?i>TZINFO`, "Python TZINFO时区gadget", ThreatLevelHigh},
		{`(?i)setcomponent`, "Python setcomponent gadget", ThreatLevelHigh},
		{`(?i>django`, "Python Django框架", ThreatLevelMedium},
		{`(?i)flask`, "Python Flask框架", ThreatLevelMedium},
		{`(?i>django\.core\.signing`, "Django签名模块", ThreatLevelMedium},
		{`(?i>jinja2`, "Python Jinja2模板", ThreatLevelMedium},
	}

	for _, p := range pythonPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "Python反序列化威胁 - " + p.description,
				Recommendation: "使用json代替pickle，或使用signed pickle",
			})
		}
	}

	if strings.Contains(data, "\x80\x03") || strings.Contains(data, "\x80\x04") || strings.Contains(data, "\x80\x05") {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelCritical,
			Pattern:        "pickle_magic_bytes",
			Description:    "Pickle协议字节检测",
			Recommendation: "阻止pickle格式的序列化数据",
		})
	}
}

func (a *DeserializationAnalyzer) analyzeDotNetSerialization(data string, result *AnalysisResult) {
	dotnetPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)<assembly`, "XML序列化程序集", ThreatLevelHigh},
		{`(?i)<type`, "XML序列化类型", ThreatLevelHigh},
		{`(?i)<kernel`, "BinaryFormatter序列化", ThreatLevelHigh},
		{`(?i)BinaryFormatter`, ".NET BinaryFormatter", ThreatLevelCritical},
		{`(?i)NetDataContractSerializer`, ".NET NetDataContractSerializer", ThreatLevelHigh},
		{`(?i>DataContractSerializer`, ".NET DataContractSerializer", ThreatLevelMedium},
		{`(?i)DataContractJsonSerializer`, ".NET JSON序列化", ThreatLevelMedium},
		{`(?i)JavaScriptSerializer`, ".NET JavaScriptSerializer", ThreatLevelMedium},
		{`(?i>JsonSerializer`, ".NET JsonSerializer", ThreatLevelMedium},
		{`(?i>XmlSerializer`, ".NET XmlSerializer", ThreatLevelMedium},
		{`(?i)LosFormatter`, ".NET LosFormatter", ThreatLevelHigh},
		{`(?i>ObjectStateFormatter`, ".NET ObjectStateFormatter", ThreatLevelHigh},
		{`(?i>SoapFormatter`, ".NET SoapFormatter", ThreatLevelHigh},
		{`(?i)TypeNameHandling`, ".NET TypeNameHandling配置", ThreatLevelCritical},
		{`(?i)TypeNameAssemblyFormat`, ".NET类型名称格式", ThreatLevelHigh},
		{`(?i)SerializationBinder`, ".NET SerializationBinder", ThreatLevelHigh},
		{`(?i>System\.Windows\.Forms`, ".NET Windows Forms", ThreatLevelMedium},
		{`(?i)System\.Drawing`, ".NET System.Drawing", ThreatLevelMedium},
		{`(?i)PSObject`, ".NET PSObject", ThreatLevelHigh},
		{`(?i)System\.Diagnostics\.Process`, ".NET进程类", ThreatLevelCritical},
		{`(?i)System\.IO\.FileStream`, ".NET文件流", ThreatLevelHigh},
		{`(?i)System\.Reflection\.Assembly`, ".NET程序集反射", ThreatLevelHigh},
		{`(?i)System\.CodeDom`, ".NET CodeDOM", ThreatLevelHigh},
		{`(?i>System\.Management`, ".NET Management", ThreatLevelHigh},
		{`(?i)System\.Net\.WebClient`, ".NET WebClient", ThreatLevelHigh},
		{`(?i)System\.Net\.Http`, ".NET Http", ThreatLevelMedium},
		{`(?i)System\.Xml\.XmlDocument`, ".NET XML文档", ThreatLevelMedium},
		{`(?i)System\.Runtime\.IntrusiveMaps`, ".NET IntrusiveMaps", ThreatLevelHigh},
		{`(?i)SessionsPitfall`, ".NET Session反序列化", ThreatLevelHigh},
		{`(?i)__ViewState`, "ASP.NET ViewState", ThreatLevelMedium},
		{`(?i>__VIEWSTATE`, "ASP.NET ViewState大写", ThreatLevelMedium},
		{`(?i>__RequestVerificationToken`, "ASP.NET验证令牌", ThreatLevelMedium},
	}

	for _, p := range dotnetPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    ".NET反序列化威胁 - " + p.description,
				Recommendation: "禁用BinaryFormatter等危险序列化器",
			})
		}
	}
}

func (a *DeserializationAnalyzer) analyzeGadgetChainPatterns(data string, result *AnalysisResult) {
	gadgetChainPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)TemplatesImpl.*bytecodes`, "Java TemplatesImpl gadget", ThreatLevelCritical},
		{`(?i)AnnotationInvocationHandler`, "Java AnnotationInvocationHandler", ThreatLevelCritical},
		{`(?i)BadAttributeValueExpException`, "Java BadAttributeValueExpException", ThreatLevelCritical},
		{`(?i)EqualsBean`, "Java EqualsBean gadget", ThreatLevelCritical},
		{`(?i)JdbcRowSetImpl.*execute`, "Java JdbcRowSetImpl gadget", ThreatLevelCritical},
		{`(?i)RemoteObjectInvocationHandler`, "Java RemoteObjectInvocationHandler", ThreatLevelCritical},
		{`(?i)UnicastRef.*remote`, "Java UnicastRef gadget", ThreatLevelCritical},
		{`(?i)sun.*RemoteRef`, "Java RemoteRef gadget", ThreatLevelCritical},
		{`(?i)RMI.*registry`, "Java RMI registry gadget", ThreatLevelCritical},
		{`(?i)JRMP.*Listener`, "Java JRMP Listener gadget", ThreatLevelCritical},
		{`(?i)DTDDocumentImpl`, "Java DTDDocumentImpl gadget", ThreatLevelCritical},
		{`(?i)XslTransform`, "Java XslTransform gadget", ThreatLevelCritical},
		{`(?i)DocumentBuilderFactory.*disallow-doctype-decl`, "防止XXE配置", ThreatLevelMedium},
		{`(?i)TransformerFactory`, "Java TransformerFactory", ThreatLevelHigh},
		{`(?i)SAXParserFactory`, "Java SAXParserFactory", ThreatLevelHigh},
		{`(?i)XMLInputFactory`, "Java XMLInputFactory", ThreatLevelHigh},
		{`(?i)Unmarshaller`, "Java Unmarshaller", ThreatLevelHigh},
		{`(?i)JAXBIntrospector`, "Java JAXBIntrospector", ThreatLevelHigh},
		{`(?i)XMLDecoder`, "Java XMLDecoder", ThreatLevelCritical},
		{`(?i)ObjectInputStream.*validateClass`, "Java验证类", ThreatLevelHigh},
		{`(?i)sealedObject`, "Java SealedObject", ThreatLevelMedium},
		{`(?i)SerializablePermission`, "Java SerializablePermission", ThreatLevelMedium},
		{`(?i>setRestrictedMode`, "Java restricted模式", ThreatLevelMedium},
		{`(?i)绿色` + `ACL`, "Java安全ACL", ThreatLevelMedium},
		{`(?i)PrivateCredentialPermission`, "Java凭证权限", ThreatLevelMedium},
		{`(?i)DestructionNotify`, "Java DestructionNotofy", ThreatLevelHigh},
		{`(?i)sys.*executeCommand`, "Python sys执行命令", ThreatLevelCritical},
		{`(?i>subprocess.Popen`, "Python subprocess.Popen", ThreatLevelCritical},
		{`(?i>pty.spawn.*spawn`, "Python pty spawn", ThreatLevelCritical},
		{`(?i)>__import__.*os`, "Python动态导入os", ThreatLevelCritical},
		{`(?i>eval.*input`, "Python eval输入", ThreatLevelCritical},
		{`(?i)>exec.*input`, "Python exec输入", ThreatLevelCritical},
		{`(?i)>open.*read`, "Python open读取", ThreatLevelHigh},
		{`(?i)>os.environ`, "Python环境变量访问", ThreatLevelMedium},
		{`(?i)MethodDispatcher`, "Ruby MethodDispatcher", ThreatLevelCritical},
		{`(?i>ActiveModel::Errors`, "Rails ActiveModel Errors", ThreatLevelCritical},
		{`(?i)ERB::new.*render`, "Rails ERB模板注入", ThreatLevelCritical},
		{`(?i)YAML.load.*render`, "Rails YAML渲染", ThreatLevelCritical},
		{`(?i)JSON.parse.*render`, "Rails JSON解析", ThreatLevelMedium},
		{`(?i>Marshal\.load`, "Ruby Marshal.load", ThreatLevelCritical},
	}

	for _, p := range gadgetChainPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "反序列化Gadget链 - " + p.description,
				Recommendation: "阻止已知gadget链的反序列化",
			})
		}
	}
}

func (a *DeserializationAnalyzer) analyzeMagicBytes(data string, result *AnalysisResult) {
	magicBytePatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`\xac\xed\x00\x05`, "Java序列化字节", ThreatLevelCritical},
		{`\xfe\xed\xff\xff`, "Mac Binary PropertyList", ThreatLevelHigh},
		{`\x00\x00\x00\xff\xff\xff\xff`, "Amf0 Flash/AMF序列化", ThreatLevelCritical},
		{`\x00\x00\x00`, "AMF3序列化", ThreatLevelCritical},
		{`\x80`, "Ruby Marshal序列化", ThreatLevelCritical},
		{`\x80\x04\x08`, "Ruby Marshal v4", ThreatLevelCritical},
		{`\x80\x05`, "Python pickle v5", ThreatLevelCritical},
		{`\x80\x03`, "Python pickle v3", ThreatLevelCritical},
		{`\x80\x04`, "Python pickle v4", ThreatLevelCritical},
		{`\x80\x06`, "Python pickle v6", ThreatLevelCritical},
		{`dtd`, "XML DTD序列化", ThreatLevelHigh},
		{`<?xml version`, "XML序列化", ThreatLevelMedium},
		{`{.*"type".*:.*}`, "JSON序列化", ThreatLevelLow},
		{`\{.*"\\$type"`, "JSON .NET类型注入", ThreatLevelCritical},
		{`\{.*"__type"`, "JSON类型信息", ThreatLevelHigh},
	}

	for _, p := range magicBytePatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "序列化魔术字节 - " + p.description,
				Recommendation: "验证序列化数据类型",
			})
		}
	}

	encodedPayloads := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)base64_decode\(`, "Base64编码检测", ThreatLevelMedium},
		{`(?i)base64_decode.*unserialize`, "Base64+反序列化", ThreatLevelCritical},
		{`(?i>gzinflate\(.*base64`, "压缩+Base64+反序列化", ThreatLevelCritical},
		{`(?i)url_decode\(`, "URL解码检测", ThreatLevelMedium},
		{`(?i)urldecode\(`, "URL解码检测", ThreatLevelMedium},
		{`(?i)rawurldecode\(`, "Raw URL解码检测", ThreatLevelMedium},
	}

	for _, p := range encodedPayloads {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "编码序列化威胁 - " + p.description,
				Recommendation: "解码后验证序列化内容",
			})
		}
	}
}

func (a *DeserializationAnalyzer) analyzeKnownExploitPatterns(data string, result *AnalysisResult) {
	exploitPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)CommonsCollections.*exec`, "Apache CommonsCollections攻击", ThreatLevelCritical},
		{`(?i)Spring.*Framwork.*Code`, "Spring框架代码执行", ThreatLevelCritical},
		{`(?i)RMI.*RemoteCode`, "RMI远程代码执行", ThreatLevelCritical},
		{`(?i)Hessian.*bug`, "Hessian反序列化漏洞", ThreatLevelCritical},
		{`(?i)BlazeDS.*deserialization`, "BlazeDS反序列化", ThreatLevelCritical},
		{`(?i>JSONIC.*deserialization`, "JSONIC反序列化漏洞", ThreatLevelCritical},
		{`(?i)Jackson.*deserialization`, "Jackson反序列化漏洞", ThreatLevelCritical},
		{`(?i)Fastjson.*deserialization`, "Fastjson反序列化漏洞", ThreatLevelCritical},
		{`(?i)Struts.*remote`, "Struts远程代码执行", ThreatLevelCritical},
		{`(?i)Struts2.*rest`, "Struts2 REST插件漏洞", ThreatLevelCritical},
		{`(?i)ognl.*execute`, "OGNL表达式注入", ThreatLevelCritical},
		{`(?i)\@eval\(`, "PHP eval注入", ThreatLevelCritical},
		{`(?i)\@system\(`, "PHP system注入", ThreatLevelCritical},
		{`(?i)\@passthru\(`, "PHP passthru注入", ThreatLevelCritical},
		{`(?i)\@exec\(`, "PHP exec注入", ThreatLevelCritical},
		{`(?i)\@shell_exec`, "PHP shell_exec注入", ThreatLevelCritical},
		{`(?i)\@proc_open`, "PHP proc_open注入", ThreatLevelCritical},
		{`(?i)\@popen`, "PHP popen注入", ThreatLevelHigh},
		{`(?i)\@serialize\(`, "PHP serialize利用", ThreatLevelCritical},
		{`(?i)\@unserialize\(`, "PHP unserialize利用", ThreatLevelCritical},
		{`(?i)python.*reverse`, "Python反向shell", ThreatLevelCritical},
		{`(?i)python.*shell`, "Python shell", ThreatLevelCritical},
		{`(?i)pickle.*os\.popen`, "Pickle os.popen执行", ThreatLevelCritical},
		{`(?i)pickle.*subprocess`, "Pickle subprocess执行", ThreatLevelCritical},
		{`(?i)yaml.*load.*Loader`, "YAML unsafe load", ThreatLevelCritical},
		{`(?i)yaml.*unsafe_load`, "YAML unsafe load", ThreatLevelCritical},
		{`(?i)ruby.*shell`, "Ruby shell执行", ThreatLevelCritical},
		{`(?i)Marshal\.load.*load`, "Ruby Marshal.load", ThreatLevelCritical},
	}

	for _, p := range exploitPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "已知反序列化漏洞利用 - " + p.description,
				Recommendation: "阻止已知漏洞利用模式的序列化数据",
			})
		}
	}

	ysoserialPatterns := []string{
		`(?i)ysoserial`,
		`(?i>Java笑了`,
		`(?i>GadgetChain`,
		`(?i>Payload`,
		`(?i>ROIS`,
		`(?i>Resin`,
		`(?i>Vaadin`,
		`(?i>Myfaces`,
		`(?i>Hibernate`,
		`(?i>Beanshell`,
		`(?i>C3P0`,
		`(?i>Wicket`,
	}

	for _, pattern := range ysoserialPatterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelCritical,
				Pattern:        pattern,
				Description:    "ysoserial工具生成的payload",
				Recommendation: "阻止ysoserial生成的序列化payload",
			})
		}
	}
}

func (a *DeserializationAnalyzer) decodeBase64(data string) string {
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return ""
	}
	return string(decoded)
}
