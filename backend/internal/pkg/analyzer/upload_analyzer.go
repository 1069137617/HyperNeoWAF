package analyzer

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

type FileUploadAnalyzer struct {
	name         string
	version      string
	analyzerType string
	enabled      bool
	config       map[string]interface{}
	mu           sync.RWMutex
}

func NewFileUploadAnalyzer() *FileUploadAnalyzer {
	return &FileUploadAnalyzer{
		name:         "file_upload_analyzer",
		version:      "1.0.0",
		analyzerType: "file_upload",
		enabled:      true,
		config:       make(map[string]interface{}),
	}
}

func (a *FileUploadAnalyzer) Name() string {
	return a.name
}

func (a *FileUploadAnalyzer) Type() string {
	return a.analyzerType
}

func (a *FileUploadAnalyzer) Version() string {
	return a.version
}

func (a *FileUploadAnalyzer) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

func (a *FileUploadAnalyzer) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

func (a *FileUploadAnalyzer) Configure(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = config
	return nil
}

type UploadAnalysisInput struct {
	RawData      []byte
	Filename     string
	ContentType  string
	FileSize     int64
	Extension    string
	Metadata     map[string]interface{}
}

func (a *FileUploadAnalyzer) Analyze(input *AnalysisInput) *AnalysisResult {
	start := time.Now()
	result := NewAnalysisResult(a)

	if input == nil || input.Raw == "" {
		return result
	}

	a.analyzeDoubleExtensions(input.Raw, result)
	a.analyzeContentTypeSpoofing(input.Raw, input.ContentType, result)
	a.analyzeFilenamePatterns(input.Raw, result)

	result.ProcessingTime = time.Since(start)
	result.ShouldBlock = result.ShouldBlockRequest(0.6)
	if len(result.Matches) > 0 {
		result.ShouldLog = true
		result.ShouldAllow = !result.ShouldBlock
	}

	return result
}

func (a *FileUploadAnalyzer) AnalyzeFileData(uploadInput *UploadAnalysisInput) *AnalysisResult {
	start := time.Now()
	result := NewAnalysisResult(a)

	if uploadInput == nil || len(uploadInput.RawData) == 0 {
		return result
	}

	a.analyzeMagicBytes(uploadInput.RawData, result)
	a.analyzeEmbeddedScripts(uploadInput.RawData, result)
	a.analyzeExifData(uploadInput.RawData, result)
	a.analyzePolyglotFiles(uploadInput.RawData, result)
	a.analyzeFilenamePatterns(string(uploadInput.RawData), result)

	result.ProcessingTime = time.Since(start)
	result.ShouldBlock = result.ShouldBlockRequest(0.6)
	if len(result.Matches) > 0 {
		result.ShouldLog = true
		result.ShouldAllow = !result.ShouldBlock
	}

	return result
}

func (a *FileUploadAnalyzer) analyzeDoubleExtensions(data string, result *AnalysisResult) {
	doubleExtPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\.php\d*\.`, "PHP version extension (double ext)", ThreatLevelCritical},
		{`(?i)\.phtml\.`, "PHP alias extension", ThreatLevelCritical},
		{`(?i)\.phar\.`, "PHAR archive", ThreatLevelCritical},
		{`(?i)\.phpt\.`, "PHP test file", ThreatLevelCritical},
		{`(?i)\.asp\.`, "ASP extension", ThreatLevelCritical},
		{`(?i)\.aspx\.`, "ASP.NET extension", ThreatLevelCritical},
		{`(?i)\.cer\.`, "Certificate (can contain script)", ThreatLevelCritical},
		{`(?i)\.cgi\.`, "CGI script", ThreatLevelCritical},
		{`(?i)\.pl\.`, "Perl script", ThreatLevelCritical},
		{`(?i)\.py\.`, "Python script", ThreatLevelCritical},
		{`(?i)\.rb\.`, "Ruby script", ThreatLevelCritical},
		{`(?i)\.jsp\.`, "JavaServer Pages", ThreatLevelCritical},
		{`(?i)\.jspx\.`, "JavaServer Pages XML", ThreatLevelCritical},
		{`(?i)\.js\.`, "JavaScript file", ThreatLevelHigh},
		{`(?i)\.html?\.`, "HTML in extension", ThreatLevelHigh},
		{`(?i)\.htm\.`, "HTML file", ThreatLevelHigh},
		{`(?i)\.svg\.`, "SVG (can contain scripts)", ThreatLevelHigh},
		{`(?i)\.xml\.`, "XML file (XSS vector)", ThreatLevelHigh},
		{`(?i)\.xhtml\.`, "XHTML file", ThreatLevelHigh},
		{`(?i)\.htaccess\.`, "HTACCESS file", ThreatLevelHigh},
		{`(?i)\.htpasswd\.`, "HTPASSWD file", ThreatLevelHigh},
		{`(?i)\.ini\.`, "INI configuration", ThreatLevelHigh},
		{`(?i)\.conf\.`, "Config file", ThreatLevelHigh},
		{`(?i)\.config\.`, "Config file", ThreatLevelHigh},
		{`(?i)\.sh\.`, "Shell script", ThreatLevelCritical},
		{`(?i)\.bash\.`, "Bash script", ThreatLevelCritical},
		{`(?i)\.bashrc\.`, "Bashrc", ThreatLevelHigh},
		{`(?i)\.zsh\.`, "Zsh script", ThreatLevelCritical},
		{`(?i)\.bat\.`, "Batch file (Windows)", ThreatLevelHigh},
		{`(?i)\.cmd\.`, "CMD file (Windows)", ThreatLevelHigh},
		{`(?i)\.ps1\.`, "PowerShell script", ThreatLevelCritical},
		{`(?i)\.pif\.`, "PIF file (Windows)", ThreatLevelHigh},
		{`(?i)\.application\.`, "ClickOnce app", ThreatLevelHigh},
		{`(?i)\.msi\.`, "Windows installer", ThreatLevelHigh},
		{`(?i)\.dll\.`, "Dynamic link library", ThreatLevelCritical},
		{`(?i)\.exe\.`, "Executable", ThreatLevelCritical},
		{`(?i)\.scr\.`, "Screensaver", ThreatLevelCritical},
		{`(?i)\.com\.`, "Command file", ThreatLevelCritical},
		{`(?i)\.jar\.`, "Java archive", ThreatLevelCritical},
		{`(?i)\.war\.`, "Web archive", ThreatLevelCritical},
		{`(?i)\.jsp\.war`, "JSP in war", ThreatLevelCritical},
		{`(?i)\.php\.jpg`, "PHP disguised as JPG", ThreatLevelCritical},
		{`(?i)\.php\.png`, "PHP disguised as PNG", ThreatLevelCritical},
		{`(?i)\.php\.gif`, "PHP disguised as GIF", ThreatLevelCritical},
		{`(?i)\.php\.pdf`, "PHP disguised as PDF", ThreatLevelCritical},
	}

	for _, p := range doubleExtPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			matches := re.FindAllStringIndex(data, -1)
			for _, match := range matches {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    p.threatLevel,
					Pattern:        p.pattern,
					Position:       match[0],
					Length:         match[1] - match[0],
					Description:    "Suspicious double extension: " + p.description,
					Evidence:       data[match[0]:min(match[1], match[0]+60)],
					Recommendation: "Block executable extensions; verify file type via magic bytes",
				})
			}
		}
	}
}

func (a *FileUploadAnalyzer) analyzeContentTypeSpoofing(rawData string, contentType string, result *AnalysisResult) {
	if contentType == "" {
		return
	}

	contentType = strings.ToLower(contentType)
	claimedType := strings.Split(contentType, ";")[0]
	claimedType = strings.TrimSpace(claimedType)

	allowedImageTypes := map[string]bool{
		"image/jpeg": true,
		"image/png":  true,
		"image/gif":  true,
		"image/bmp":  true,
		"image/webp": true,
		"image/tiff": true,
	}

	allowedDocTypes := map[string]bool{
		"application/pdf":                                                                             true,
		"application/msword":                                                                           true,
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document":                      true,
		"application/vnd.ms-excel":                                                                     true,
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":                            true,
	}

	hasExecutable := regexp.MustCompile(`(?i)\.(php|phtml|phar|asp|aspx|jsp|js|cgi|pl|py|rb|sh|bash|exe|dll|jar|war|ps1|bat|cmd|scr|com)`)
	if hasExecutable.MatchString(rawData) && allowedImageTypes[claimedType] {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelCritical,
			Pattern:        "content_type_mismatch",
			Description:    "Content-Type mismatch: executable content claimed as image",
			Evidence:       claimedType,
			Recommendation: "Verify file magic bytes match claimed Content-Type",
		})
	}

	if hasExecutable.MatchString(rawData) && allowedDocTypes[claimedType] {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelCritical,
			Pattern:        "content_type_mismatch",
			Description:    "Content-Type mismatch: executable content claimed as document",
			Evidence:       claimedType,
			Recommendation: "Verify file magic bytes match claimed Content-Type",
		})
	}

	binaryPatterns := []struct {
		pattern     *regexp.Regexp
		description string
		threatLevel ThreatLevel
	}{
		{regexp.MustCompile(`(?i)<\?php`), "PHP code embedded", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)<script`), "Script tag embedded", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)<%@`), "ASP/JSP directive", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)<html`), "HTML tag embedded", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)<iframe`), "Iframe tag embedded", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)javascript:`), "JavaScript protocol", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)eval\s*\(`), "Eval function call", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)system\s*\(`), "System call", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)exec\s*\(`), "Exec call", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)passthru\s*\(`), "Passthru call", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)shell_exec`), "Shell exec", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)base64_decode`), "Base64 decode", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)<?xml`), "XML declaration", ThreatLevelHigh},
	}

	for _, p := range binaryPatterns {
		if p.pattern.MatchString(rawData) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.description,
				Description:    "Content-Type spoofing detected: " + p.description + " in non-executable file",
				Recommendation: "Block file upload; malicious content detected inside file",
			})
		}
	}
}

func (a *FileUploadAnalyzer) analyzeFilenamePatterns(data string, result *AnalysisResult) {
	suspiciousFilenamePatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\.ph[234p]`, "PHP variant extension", ThreatLevelCritical},
		{`(?i)\.phtml`, "PHP embedded HTML", ThreatLevelCritical},
		{`(?i)\.phar`, "PHP archive", ThreatLevelCritical},
		{`(?i)\.phpt`, "PHP test", ThreatLevelCritical},
		{`(?i)\.php[0-9]`, "PHP versioned", ThreatLevelCritical},
		{`(?i)\.htaccess`, "Apache config", ThreatLevelHigh},
		{`(?i)\.htpasswd`, "Password file", ThreatLevelHigh},
		{`(?i)\.user.ini`, "PHP user config", ThreatLevelHigh},
		{`(?i)\.git`, "Git directory", ThreatLevelHigh},
		{`(?i)\.gitignore`, "Git ignore", ThreatLevelMedium},
		{`(?i)\.env`, "Environment file", ThreatLevelCritical},
		{`(?i)\.env\.`, "Hidden env file", ThreatLevelCritical},
		{`(?i)\.ssh`, "SSH directory", ThreatLevelCritical},
		{`(?i)\.bashrc`, "Bash config", ThreatLevelMedium},
		{`(?i)\.bash_history`, "Bash history", ThreatLevelHigh},
		{`(?i)id_rsa`, "SSH private key", ThreatLevelCritical},
		{`(?i)id_dsa`, "DSA private key", ThreatLevelCritical},
		{`(?i)id_ecdsa`, "ECDSA private key", ThreatLevelCritical},
		{`(?i)\.aws[\\/]`, "AWS credentials dir", ThreatLevelCritical},
		{`(?i)aws[\\/].*key`, "AWS key file", ThreatLevelCritical},
		{`(?i)config\.yml`, "Config YAML", ThreatLevelMedium},
		{`(?i)database\.yml`, "Database config", ThreatLevelHigh},
		{`(?i)secrets\.json`, "Secrets JSON", ThreatLevelCritical},
		{`(?i)\.key$`, "Private key file", ThreatLevelCritical},
		{`(?i)\.pem$`, "PEM certificate", ThreatLevelCritical},
		{`(?i)\.crt$`, "Certificate file", ThreatLevelHigh},
		{`(?i)\.csr$`, "Certificate request", ThreatLevelMedium},
		{`(?i)wp-config\.php`, "WordPress config", ThreatLevelCritical},
		{`(?i)configuration\.php`, "Joomla config", ThreatLevelCritical},
		{`(?i)config\.php`, "Generic PHP config", ThreatLevelHigh},
		{`(?i)settings\.py`, "Python settings", ThreatLevelHigh},
		{`(?i)\.log$`, "Log file", ThreatLevelLow},
		{`(?i)\.bak$`, "Backup file", ThreatLevelMedium},
		{`(?i)\.backup$`, "Backup file", ThreatLevelMedium},
		{`(?i)\.old$`, "Old file", ThreatLevelLow},
		{`(?i)\.swp$`, "Vim swap", ThreatLevelLow},
		{`(?i)\.swo$`, "Vim swap", ThreatLevelLow},
		{`(?i)\.tmp$`, "Temp file", ThreatLevelLow},
		{`(?i)\.temp$`, "Temp file", ThreatLevelLow},
	}

	for _, p := range suspiciousFilenamePatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			matches := re.FindAllStringIndex(data, -1)
			for _, match := range matches {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    p.threatLevel,
					Pattern:        p.pattern,
					Position:       match[0],
					Length:         match[1] - match[0],
					Description:    "Suspicious filename pattern: " + p.description,
					Evidence:       data[match[0]:min(match[1], match[0]+50)],
					Recommendation: "Block upload of sensitive/config files; validate against allowlist",
				})
			}
		}
	}
}

func (a *FileUploadAnalyzer) analyzeMagicBytes(data []byte, result *AnalysisResult) {
	if len(data) < 16 {
		return
	}

	magicBytes := []struct {
		magic       []byte
		offset      int
		fileType    string
		description string
		threatLevel ThreatLevel
	}{
		{[]byte{0xFF, 0xD8, 0xFF}, 0, "jpeg", "JPEG image", ThreatLevelLow},
		{[]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, 0, "png", "PNG image", ThreatLevelLow},
		{[]byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61}, 0, "gif89a", "GIF89a image", ThreatLevelLow},
		{[]byte{0x47, 0x49, 0x46, 0x38, 0x37, 0x61}, 0, "gif87a", "GIF87a image", ThreatLevelLow},
		{[]byte{0x42, 0x4D}, 0, "bmp", "BMP image", ThreatLevelLow},
		{[]byte{0x49, 0x49, 0x2A, 0x00}, 0, "tiff-le", "TIFF (little endian)", ThreatLevelLow},
		{[]byte{0x4D, 0x4D, 0x00, 0x2A}, 0, "tiff-be", "TIFF (big endian)", ThreatLevelLow},
		{[]byte{0x00, 0x00, 0x01, 0x00}, 0, "ico", "ICO icon", ThreatLevelLow},
		{[]byte{0x00, 0x00, 0x02, 0x00}, 0, "cur", "CUR cursor", ThreatLevelLow},
		{[]byte{0x25, 0x50, 0x44, 0x46}, 0, "pdf", "PDF document", ThreatLevelMedium},
		{[]byte{0x50, 0x4B, 0x03, 0x04}, 0, "zip", "ZIP archive", ThreatLevelMedium},
		{[]byte{0x50, 0x4B, 0x05, 0x06}, 0, "zip-empty", "ZIP archive (empty)", ThreatLevelMedium},
		{[]byte{0x50, 0x4B, 0x07, 0x08}, 0, "zip-spanned", "ZIP archive (spanned)", ThreatLevelMedium},
		{[]byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01}, 0, "rar", "RAR archive", ThreatLevelMedium},
		{[]byte{0x1F, 0x8B, 0x08}, 0, "gzip", "GZIP archive", ThreatLevelMedium},
		{[]byte{0x42, 0x5A, 0x68}, 0, "bzip2", "BZIP2 archive", ThreatLevelMedium},
		{[]byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, 0, "7z", "7-Zip archive", ThreatLevelMedium},
		{[]byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, 0, "xz", "XZ archive", ThreatLevelMedium},
		{[]byte{0x04, 0x22, 0x4D, 0x18}, 0, "lz4", "LZ4 archive", ThreatLevelMedium},
		{[]byte{0x28, 0xB5, 0x2F, 0xFD}, 0, "zstd", "Zstandard archive", ThreatLevelMedium},
		{[]byte{0xCA, 0xFE, 0xBA, 0xBE}, 0, "macho", "Mach-O binary", ThreatLevelHigh},
		{[]byte{0xFE, 0xED, 0xFA, 0xCE}, 0, "macho32", "Mach-O 32-bit", ThreatLevelHigh},
		{[]byte{0xFE, 0xED, 0xFA, 0xCF}, 0, "macho64", "Mach-O 64-bit", ThreatLevelHigh},
		{[]byte{0x7F, 0x45, 0x4C, 0x46}, 0, "elf", "ELF executable (Linux)", ThreatLevelCritical},
		{[]byte{0x4D, 0x5A}, 0, "exe", "DOS/Windows executable", ThreatLevelCritical},
		{[]byte{0x5A, 0x4D}, 0, "exe-reverse", "Windows executable (reversed)", ThreatLevelCritical},
		{[]byte{0xCF, 0xFA, 0xED, 0xFE}, 0, "macho-fresh", "Mach-O fresh", ThreatLevelHigh},
		{[]byte{0xFF, 0xFE}, 0, "utf16-le", "UTF-16 LE BOM", ThreatLevelLow},
		{[]byte{0xFE, 0xFF}, 0, "utf16-be", "UTF-16 BE BOM", ThreatLevelLow},
		{[]byte{0xEF, 0xBB, 0xBF}, 0, "utf8-bom", "UTF-8 BOM", ThreatLevelLow},
	}

	detectedType := ""
	for _, mb := range magicBytes {
		if len(data) >= mb.offset+len(mb.magic) {
			match := true
			for i, b := range mb.magic {
				if data[mb.offset+i] != b {
					match = false
					break
				}
			}
			if match {
				detectedType = mb.fileType
				if mb.threatLevel >= ThreatLevelHigh {
					result.AddMatch(Match{
						Type:           MatchTypeSemantic,
						ThreatLevel:    mb.threatLevel,
						Pattern:        mb.fileType,
						Position:       mb.offset,
						Length:         len(mb.magic),
						Description:    "Dangerous file magic bytes detected: " + mb.description,
						Evidence:       fmtBytes(data[0:min(16, len(data))]),
						Recommendation: "Block executable file uploads; use whitelist for allowed types",
					})
				}
			}
		}
	}

	if detectedType == "" {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelMedium,
			Pattern:        "unknown",
			Description:    "Unknown file magic bytes - possible obfuscated executable",
			Evidence:       fmtBytes(data[0:min(16, len(data))]),
			Recommendation: "Investigate unknown file type; consider blocking if suspicious",
		})
	}
}

func (a *FileUploadAnalyzer) analyzeEmbeddedScripts(data []byte, result *AnalysisResult) {
	if len(data) < 100 {
		return
	}

	scriptPatterns := []struct {
		pattern     *regexp.Regexp
		description string
		threatLevel ThreatLevel
	}{
		{regexp.MustCompile(`(?i)<\?php`), "PHP opening tag", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)<\?=`), "PHP short echo", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)<\? `), "PHP short open", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)<\?xml`), "XML declaration", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)<script[\s>]`), "Script tag", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)javascript:`), "JavaScript protocol", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)vbscript:`), "VBScript protocol", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)<%@\s*page`), "ASP.NET page directive", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)<%@`), "ASP directive", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)<%=`), "ASP inline response", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)<%`), "ASP code block", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)<jsp:`), "JSP tag", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)<c:if`), "JSTL conditional", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)<c:out`), "JSTL output", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)\$\{.*?}`), "EL expression (Spring/JSP)", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)#\{.*?}`), "Seam expression", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)eval\s*\(`), "Eval function", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)system\s*\(`), "System call", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)exec\s*\(`), "Exec call", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)passthru\s*\(`), "Passthru call", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)shell_exec`), "Shell exec", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)proc_open`), "Process open", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)popen\s*\(`), "Pipe open", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)base64_decode`), "Base64 decode", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)base64_encode`), "Base64 encode", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)str_rot13`), "ROT13 cipher", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)gzip_decode`), "Gzip decode", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)gzinflate`), "Zlib inflate", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)gzuncompress`), "Zlib uncompress", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)mcrypt_`), "MCrypt function", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)mysqli?_`), "MySQL function", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)pg_`), "PostgreSQL function", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)sqlite_`), "SQLite function", ThreatLevelMedium},
		{regexp.MustCompile(`(?i)preg_replace.*e`), "Preg replace eval modifier", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)assert\s*\(`), "Assert function", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)create_function`), "Create function", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)call_user_func`), "Call user function", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)call_user_func_array`), "Call user function array", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)unserialize`), "Unserialize", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)file_get_contents`), "File get contents", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)file_put_contents`), "File put contents", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)fopen\s*\(`), "File open", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)fwrite\s*\(`), "File write", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)include\s*`), "Include statement", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)require\s*`), "Require statement", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)import\s+os`), "Python OS import", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)import\s+sys`), "Python sys import", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)subprocess\.`), "Python subprocess", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)os\.system`), "Python OS system", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)os\.popen`), "Python OS popen", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)exec\s*\(`), "Python exec", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)eval\s*\(`), "Python eval", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)Runtime\.getRuntime`), "Java Runtime exec", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)ProcessBuilder`), "Java ProcessBuilder", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)Class\.forName`), "Java class loading", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)ProcessImpl`), "Java ProcessImpl", ThreatLevelCritical},
	}

	for _, p := range scriptPatterns {
		if p.pattern.Match(data) {
			matches := p.pattern.FindAllIndex(data, -1)
			for _, match := range matches {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    p.threatLevel,
					Pattern:        p.description,
					Position:       match[0],
					Length:         match[1] - match[0],
					Description:    "Embedded script detected: " + p.description,
					Evidence:       string(data[match[0]:min(match[1], match[0]+50)]),
					Recommendation: "Block file upload containing executable code",
				})
			}
		}
	}
}

func (a *FileUploadAnalyzer) analyzeExifData(data []byte, result *AnalysisResult) {
	if len(data) < 2 {
		return
	}

	isJPEG := bytes.HasPrefix(data, []byte{0xFF, 0xD8})
	if !isJPEG {
		return
	}

	exifSuspiciousPatterns := []struct {
		pattern     *regexp.Regexp
		description string
		threatLevel ThreatLevel
	}{
		{regexp.MustCompile(`(?i)php`), "PHP script in EXIF", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)<script`), "Script tag in EXIF", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)eval`), "Eval function in EXIF", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)base64_`), "Base64 in EXIF", ThreatLevelHigh},
		{regexp.MustCompile(`(?i)system\(`), "System call in EXIF", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)exec\(`), "Exec in EXIF", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)shell_exec`), "Shell exec in EXIF", ThreatLevelCritical},
		{regexp.MustCompile(`(?i)passthru`), "Passthru in EXIF", ThreatLevelCritical},
	}

	dataStr := string(data)
	for _, p := range exifSuspiciousPatterns {
		if p.pattern.MatchString(dataStr) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.description,
				Description:    "Malicious EXIF metadata: " + p.description,
				Recommendation: "Strip EXIF data from uploaded images; re-encode to remove metadata",
			})
		}
	}
}

func (a *FileUploadAnalyzer) analyzePolyglotFiles(data []byte, result *AnalysisResult) {
	if len(data) < 50 {
		return
	}

	polyglotSignatures := []struct {
		prefix      []byte
		suffix      []byte
		description string
		threatLevel ThreatLevel
	}{
		{[]byte{0xFF, 0xD8, 0xFF, 0xE0}, []byte("<?php"), "JPEG+PHP polyglot", ThreatLevelCritical},
		{[]byte{0xFF, 0xD8, 0xFF, 0xE0}, []byte("<script"), "JPEG+JS polyglot", ThreatLevelCritical},
		{[]byte{0x89, 0x50, 0x4E, 0x47}, []byte("<?php"), "PNG+PHP polyglot", ThreatLevelCritical},
		{[]byte{0x89, 0x50, 0x4E, 0x47}, []byte("<script"), "PNG+JS polyglot", ThreatLevelCritical},
		{[]byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61}, []byte("<?php"), "GIF+PHP polyglot", ThreatLevelCritical},
		{[]byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61}, []byte("<script"), "GIF+JS polyglot", ThreatLevelCritical},
		{[]byte{0x25, 0x50, 0x44, 0x46}, []byte("<?php"), "PDF+PHP polyglot", ThreatLevelCritical},
		{[]byte{0x25, 0x50, 0x44, 0x46}, []byte("<script"), "PDF+JS polyglot", ThreatLevelCritical},
		{[]byte{0x50, 0x4B, 0x03, 0x04}, []byte("<?php"), "ZIP+PHP polyglot", ThreatLevelCritical},
		{[]byte{0x50, 0x4B, 0x03, 0x04}, []byte("<script"), "ZIP+JS polyglot", ThreatLevelCritical},
	}

	for _, sig := range polyglotSignatures {
		if len(data) < len(sig.prefix)+len(sig.suffix) {
			continue
		}

		prefixMatch := true
		for i, b := range sig.prefix {
			if data[i] != b {
				prefixMatch = false
				break
			}
		}

		suffixMatch := bytes.Contains(data, sig.suffix)

		if prefixMatch && suffixMatch {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    sig.threatLevel,
				Pattern:        sig.description,
				Description:    "Polyglot file detected: " + sig.description,
				Evidence:       fmtBytes(data[0:min(32, len(data))]),
				Recommendation: "Block polyglot files; they can bypass content-type validation",
			})
		}
	}
}

func fmtBytes(data []byte) string {
	var buf bytes.Buffer
	for i, b := range data {
		if i > 15 {
			buf.WriteString("...")
			break
		}
		if i > 0 {
			buf.WriteString(" ")
		}
		buf.WriteString(fmt.Sprintf("%02X", b))
	}
	return buf.String()
}
