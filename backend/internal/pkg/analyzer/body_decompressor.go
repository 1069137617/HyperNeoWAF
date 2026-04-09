package analyzer

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"io"
	"regexp"
	"sync"
	"time"
)

type BodyDecompressor struct {
	name         string
	version      string
	analyzerType string
	enabled      bool
	config       map[string]interface{}
	mu           sync.RWMutex
}

func NewBodyDecompressor() *BodyDecompressor {
	return &BodyDecompressor{
		name:         "body_decompressor",
		version:      "1.0.0",
		analyzerType: "body_decompression",
		enabled:      true,
		config:       make(map[string]interface{}),
	}
}

func (a *BodyDecompressor) Name() string {
	return a.name
}

func (a *BodyDecompressor) Type() string {
	return a.analyzerType
}

func (a *BodyDecompressor) Version() string {
	return a.version
}

func (a *BodyDecompressor) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

func (a *BodyDecompressor) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

func (a *BodyDecompressor) Configure(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = config
	return nil
}

func (a *BodyDecompressor) Analyze(input *AnalysisInput) *AnalysisResult {
	start := time.Now()
	result := NewAnalysisResult(a)

	if input == nil {
		return result
	}

	a.analyzeCompressionHeaders(input, result)
	a.analyzeCompressedBody(input, result)
	a.analyzeCompressionAttacks(input, result)

	result.ProcessingTime = time.Since(start)
	result.ShouldBlock = result.ShouldBlockRequest(0.6)
	if len(result.Matches) > 0 {
		result.ShouldLog = true
		result.ShouldAllow = !result.ShouldBlock
	}

	return result
}

func (a *BodyDecompressor) analyzeCompressionHeaders(input *AnalysisInput, result *AnalysisResult) {
	if input.Headers == nil {
		return
	}

	contentEncoding := input.Headers["Content-Encoding"]
	if contentEncoding != "" {
		a.analyzeContentEncoding(contentEncoding, result)
	}

	transferEncoding := input.Headers["Transfer-Encoding"]
	if transferEncoding != "" {
		a.analyzeTransferEncoding(transferEncoding, result)
	}

	te := input.Headers["TE"]
	if te != "" {
		a.analyzeTEHeader(te, result)
	}

	if input.Headers["X-Content-Encoding"] != "" {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelLow,
			Pattern:        "X-Content-Encoding",
			Description:    "自定义压缩编码头: " + input.Headers["X-Content-Encoding"],
			Recommendation: "验证自定义压缩编码",
		})
	}

	if input.Headers["X-Gzip-Encoding"] != "" {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelLow,
			Pattern:        "X-Gzip-Encoding",
			Description:    "自定义gzip编码头: " + input.Headers["X-Gzip-Encoding"],
			Recommendation: "验证自定义gzip编码",
		})
	}
}

func (a *BodyDecompressor) analyzeContentEncoding(encoding string, result *AnalysisResult) {
	encodings := map[string]ThreatLevel{
		"gzip":": ThreatLevelLow,
		"deflate": ThreatLevelLow,
		"br": ThreatLevelMedium,
		"zstd": ThreatLevelMedium,
		"compress": ThreatLevelMedium,
		"identity": ThreatLevelLow,
		"xz": ThreatLevelMedium,
		"lzma": ThreatLevelMedium,
		"lz4": ThreatLevelMedium,
	}

	encodingLower := encoding
	for _, enc := range encodings {
		if encodingLower == enc {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    encodings[enc],
				Pattern:        "Content-Encoding",
				Description:    "Content-Encoding: " + encoding,
				Recommendation: "支持" + encoding + "压缩格式",
			})
			return
		}
	}

	result.AddMatch(Match{
		Type:           MatchTypeSemantic,
		ThreatLevel:    ThreatLevelMedium,
		Pattern:        "Content-Encoding",
		Description:    "未知Content-Encoding: " + encoding,
		Recommendation: "验证压缩格式",
	})
}

func (a *BodyDecompressor) analyzeTransferEncoding(te string, result *AnalysisResult) {
	teLower := te
	if teLower == "chunked" {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelLow,
			Pattern:        "Transfer-Encoding",
			Description:    "分块传输编码",
			Recommendation: "正常分块传输",
		})
	} else {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelMedium,
			Pattern:        "Transfer-Encoding",
			Description:    "自定义Transfer-Encoding: " + te,
			Recommendation: "验证分块编码",
		})
	}
}

func (a *BodyDecompressor) analyzeTEHeader(te string, result *AnalysisResult) {
	teLower := te
	if teLower == "trailers" {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelLow,
			Pattern:        "TE",
			Description:    "TE: trailers (gRPC支持)",
			Recommendation: "正常gRPC传输",
		})
	} else {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelMedium,
			Pattern:        "TE",
			Description:    "自定义TE头: " + te,
			Recommendation: "验证TE头",
		})
	}
}

func (a *BodyDecompressor) analyzeCompressedBody(input *AnalysisInput, result *AnalysisResult) {
	if input.Body == "" {
		return
	}

	body := input.Body
	encoding := ""
	if input.Headers != nil {
		encoding = input.Headers["Content-Encoding"]
	}

	a.analyzeGzipCompression(body, result)
	a.analyzeDeflateCompression(body, result)
	a.analyzeBrotliCompression(body, result)
	a.analyzeZlibCompression(body, result)

	a.detectCompressionFormat(body, result)
}

func (a *BodyDecompressor) analyzeGzipCompression(body string, result *AnalysisResult) {
	bodyBytes := []byte(body)
	if len(bodyBytes) < 2 {
		return
	}

	if bodyBytes[0] == 0x1F && bodyBytes[1] == 0x8B {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelLow,
			Pattern:        "gzip-magic",
			Description:    "检测到Gzip压缩数据",
			Recommendation: "解压后检测内容",
		})

		if len(bodyBytes) >= 10 {
			compressionMethod := bodyBytes[2]
			if compressionMethod != 8 {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    ThreatLevelMedium,
					Pattern:        "gzip-method",
					Description:    "非标准Gzip压缩方法: " + string(rune(compressionMethod)),
					Recommendation: "验证Gzip压缩方法",
				})
			}

			flags := bodyBytes[3]
			if flags&0x04 != 0 {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    ThreatLevelLow,
					Pattern:        "gzip-ftext",
					Description:    "Gzip FEXTRA标志",
					Recommendation: "正常扩展字段",
				})
			}
			if flags&0x08 != 0 {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    ThreatLevelLow,
					Pattern:        "gzip-fname",
					Description:    "Gzip FNAME标志(包含文件名)",
					Recommendation: "检查文件名安全性",
				})
			}
			if flags&0x10 != 0 {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    ThreatLevelLow,
					Pattern:        "gzip-fcomment",
					Description:    "Gzip FCOMMENT标志(包含注释)",
					Recommendation: "检查注释内容",
				})
			}
			if flags&0x02 != 0 {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    ThreatLevelMedium,
					Pattern:        "gzip-fhcrc",
					Description:    "Gzip FHCRC标志",
					Recommendation: "验证CRC校验",
				})
			}
		}
	}
}

func (a *BodyDecompressor) analyzeDeflateCompression(body string, result *AnalysisResult) {
	bodyBytes := []byte(body)
	if len(bodyBytes) < 2 {
		return
	}

	if bodyBytes[0] == 0x78 && (bodyBytes[1] == 0x9C || bodyBytes[1] == 0x01 || bodyBytes[1] == 0xDA || bodyBytes[1] == 0x01) {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelLow,
			Pattern:        "deflate-magic",
			Description:    "检测到Deflate压缩数据",
			Recommendation: "解压后检测内容",
		})
	}
}

func (a *BodyDecompressor) analyzeBrotliCompression(body string, result *AnalysisResult) {
	bodyBytes := []byte(body)
	if len(bodyBytes) < 6 {
		return
	}

	if bodyBytes[0] == 0xCE && bodyBytes[1] == 0x48 && bodyBytes[2] == 0x2F && bodyBytes[3] == 0x2B && bodyBytes[4] == 0x49 && bodyBytes[5] == 0x55 {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelMedium,
			Pattern:        "brotli-magic",
			Description:    "检测到Brotli压缩数据",
			Recommendation: "解压后检测内容",
		})
	}

	if bodyBytes[0] == 0xCB && bodyBytes[1] == 0x48 && bodyBytes[2] == 0x2D && bodyBytes[3] == 0x4F && bodyBytes[4] == 0x54 {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelMedium,
			Pattern:        "brotli-magic2",
			Description:    "检测到Brotli压缩数据(变体)",
			Recommendation: "解压后检测内容",
		})
	}
}

func (a *BodyDecompressor) analyzeZlibCompression(body string, result *AnalysisResult) {
	bodyBytes := []byte(body)
	if len(bodyBytes) < 2 {
		return
	}

	if bodyBytes[0] == 0x78 {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelLow,
			Pattern:        "zlib-magic",
			Description:    "检测到Zlib压缩数据",
			Recommendation: "解压后检测内容",
		})

		compressionLevel := ""
		switch bodyBytes[1] {
		case 0x01:
			compressionLevel = "最快压缩"
		case 0x5E:
			compressionLevel = "最快压缩"
		case 0x9C:
			compressionLevel = "默认压缩"
		case 0xDA:
			compressionLevel = "最大压缩"
		}

		if compressionLevel != "" {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelLow,
				Pattern:        "zlib-level",
				Description:    "Zlib压缩级别: " + compressionLevel,
				Recommendation: "正常Zlib压缩",
			})
		}
	}
}

func (a *BodyDecompressor) detectCompressionFormat(body string, result *AnalysisResult) {
	bodyBytes := []byte(body)

	formats := []struct {
		detector func([]byte) bool
		name     string
		threat   ThreatLevel
	}{
		{a.isGzipFormat, "Gzip", ThreatLevelLow},
		{a.isDeflateFormat, "Deflate", ThreatLevelLow},
		{a.isBrotliFormat, "Brotli", ThreatLevelMedium},
		{a.isZlibFormat, "Zlib", ThreatLevelLow},
		{a.isLZMAFormat, "LZMA", ThreatLevelMedium},
		{a.isXZFormat, "XZ", ThreatLevelMedium},
		{a.isLZ4Format, "LZ4", ThreatLevelMedium},
		{a.isZstdFormat, "Zstandard", ThreatLevelMedium},
	}

	detectedFormats := make([]string, 0)
	for _, format := range formats {
		if format.detector(bodyBytes) {
			detectedFormats = append(detectedFormats, format.name)
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    format.threat,
				Pattern:        format.name + "-detected",
				Description:    "检测到" + format.name + "压缩格式",
				Recommendation: "解压后进行内容检测",
			})
		}
	}

	if len(detectedFormats) > 1 {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelHigh,
			Pattern:        "multiple-formats",
			Description:    "检测到多种压缩格式: " + joinStrings(detectedFormats, ", "),
			Recommendation: "验证压缩数据完整性",
		})
	}

	if len(detectedFormats) == 0 && len(bodyBytes) > 10 {
		result.AddMatch(Match{
			Type:           MatchTypeSemantic,
			ThreatLevel:    ThreatLevelLow,
			Pattern:        "no-compression",
			Description:    "未检测到压缩格式(明文数据)",
			Recommendation: "正常明文数据",
		})
	}
}

func (a *BodyDecompressor) isGzipFormat(data []byte) bool {
	return len(data) >= 2 && data[0] == 0x1F && data[1] == 0x8B
}

func (a *BodyDecompressor) isDeflateFormat(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	return (data[0] == 0x78 && (data[1] == 0x9C || data[1] == 0x01 || data[1] == 0xDA || data[1] == 0x5E))
}

func (a *BodyDecompressor) isBrotliFormat(data []byte) bool {
	if len(data) < 6 {
		return false
	}
	return (data[0] == 0xCE && data[1] == 0x48 && data[2] == 0x2F && data[3] == 0x2B && data[4] == 0x49 && data[5] == 0x55) ||
		(data[0] == 0xCB && data[1] == 0x48 && data[2] == 0x2D && data[3] == 0x4F && data[4] == 0x54)
}

func (a *BodyDecompressor) isZlibFormat(data []byte) bool {
	return len(data) >= 2 && data[0] == 0x78
}

func (a *BodyDecompressor) isLZMAFormat(data []byte) bool {
	if len(data) < 3 {
		return false
	}
	return data[0] == 0x5D && data[1] == 0x00 && data[2] == 0x00
}

func (a *BodyDecompressor) isXZFormat(data []byte) bool {
	if len(data) < 6 {
		return false
	}
	return data[0] == 0xFD && data[1] == 0x37 && data[2] == 0x7A && data[3] == 0x58 && data[4] == 0x5A && data[5] == 0x00
}

func (a *BodyDecompressor) isLZ4Format(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return data[0] == 0x04 && data[1] == 0x22 && data[2] == 0x4D && data[3] == 0x18
}

func (a *BodyDecompressor) isZstdFormat(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return (data[0] == 0x28 && data[1] == 0xB5 && data[2] == 0x2F && data[3] == 0xFD) ||
		(bytes.HasPrefix(data, []byte{0xFB, 0xBF}))
}

func (a *BodyDecompressor) analyzeCompressionAttacks(input *AnalysisInput, result *AnalysisResult) {
	if input.Body == "" {
		return
	}

	data := input.Raw + " " + input.QueryString + " " + input.Body

	a.analyzeZipBomb(data, result)
	a.analyzeDecompressionBypass(data, result)
	a.analyzeCompressionSideChannel(data, result)
}

func (a *BodyDecompressor) analyzeZipBomb(data string, result *AnalysisResult) {
	zipBombPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)zip\s*bomb`, "Zip炸弹标识", ThreatLevelCritical},
		{`(?i)deflate\s*bomb`, "Deflate炸弹标识", ThreatLevelCritical},
		{`(?i)gzip\s*bomb`, "Gzip炸弹标识", ThreatLevelCritical},
		{`(?i)compression\s*bomb`, "压缩炸弹标识", ThreatLevelCritical},
		{`[\x00]{100,}`, "大量空字节", ThreatLevelMedium},
		{`[\xFF]{100,}`, "大量0xFF字节", ThreatLevelMedium},
		{`(?i)recursive\s*compression`, "递归压缩", ThreatLevelCritical},
		{`(?i)nested\s*compression`, "嵌套压缩", ThreatLevelCritical},
	}

	for _, p := range zipBombPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "压缩炸弹攻击: " + p.description,
				Recommendation: "限制解压大小和递归深度",
			})
		}
	}
}

func (a *BodyDecompressor) analyzeDecompressionBypass(data string, result *AnalysisResult) {
	bypassPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)bypass\s*compression`, "压缩绕过尝试", ThreatLevelHigh},
		{`(?i)evade\s*filter`, "过滤器规避", ThreatLevelHigh},
		{`(?i) smuggling`, "数据走私", ThreatLevelHigh},
		{`(?i)split\s*payload`, "分片载荷", ThreatLevelMedium},
		{`(?i)fragmented`, "分片数据", ThreatLevelMedium},
		{`(?i)partial\s*compression`, "部分压缩", ThreatLevelMedium},
		{`(?i)corrupt\s*header`, "损坏的压缩头", ThreatLevelHigh},
		{`(?i)truncated\s*data`, "截断数据", ThreatLevelMedium},
		{`(?i)malformed\s*stream`, "畸形数据流", ThreatLevelHigh},
	}

	for _, p := range bypassPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "解压绕过攻击: " + p.description,
				Recommendation: "严格验证压缩数据格式",
			})
		}
	}
}

func (a *BodyDecompressor) analyzeCompressionSideChannel(data string, result *AnalysisResult) {
	sideChannelPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)BREACH`, "BREACH攻击", ThreatLevelHigh},
		{`(?i)CRIME`, "CRIME攻击", ThreatLevelHigh},
		{`(?i)ZOOM`, "ZOOM攻击", ThreatLevelHigh},
		{`(?i)HEIST`, "HEIST攻击", ThreatLevelHigh},
		{`(?i)TIME`, "TIME攻击", ThreatLevelHigh},
		{`(?i)oracle`, "Oracle攻击", ThreatLevelCritical},
		{`(?i)compression\s*oracle`, "压缩Oracle", ThreatLevelCritical},
		{`(?i)side\s*channel`, "侧信道攻击", ThreatLevelHigh},
		{`(?i)timing\s*attack`, "时序攻击", ThreatLevelMedium},
	}

	for _, p := range sideChannelPatterns {
		re := regexp.MustCompile(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    "压缩侧信道攻击: " + p.description,
				Recommendation: "禁用敏感数据压缩",
			})
		}
	}
}

func DecompressGzip(data []byte) ([]byte, error) {
	reader, err := NewGzipDecompressor(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(reader)
}

func DecompressDeflate(data []byte) ([]byte, error) {
	reader, err := NewDeflateDecompressor(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(reader)
}

func DecompressZlib(data []byte) ([]byte, error) {
	reader, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

func DecompressBrotli(data []byte) ([]byte, error) {
	return nil, nil
}

func DecompressLZ4(data []byte) ([]byte, error) {
	return nil, nil
}

func DecompressZstd(data []byte) ([]byte, error) {
	return nil, nil
}

type GzipDecompressor struct {
	reader io.Reader
	header []byte
}

func NewGzipDecompressor(r io.Reader) (*GzipDecompressor, error) {
	header := make([]byte, 10)
	n, err := r.Read(header)
	if err != nil && n < 10 {
		return nil, err
	}

	if header[0] != 0x1F || header[1] != 0x8B {
		return nil, err
	}

	return &GzipDecompressor{
		reader: r,
		header: header[:n],
	}, nil
}

func (g *GzipDecompressor) Read(p []byte) (int, error) {
	return 0, nil
}

type DeflateDecompressor struct {
	reader io.Reader
}

func NewDeflateDecompressor(r io.Reader) (*DeflateDecompressor, error) {
	return &DeflateDecompressor{reader: r}, nil
}

func (d *DeflateDecompressor) Read(p []byte) (int, error) {
	return 0, nil
}

func DetectAndDecompress(data []byte, encoding string) ([]byte, string, error) {
	switch encoding {
	case "gzip":
		decompressed, err := DecompressGzip(data)
		if err == nil {
			return decompressed, "gzip", nil
		}
	case "deflate":
		decompressed, err := DecompressDeflate(data)
		if err == nil {
			return decompressed, "deflate", nil
		}
		decompressed, err = DecompressZlib(data)
		if err == nil {
			return decompressed, "zlib", nil
		}
	case "br":
		decompressed, err := DecompressBrotli(data)
		if err == nil {
			return decompressed, "brotli", nil
		}
	case "zstd":
		decompressed, err := DecompressZstd(data)
		if err == nil {
			return decompressed, "zstd", nil
		}
	case "lz4":
		decompressed, err := DecompressLZ4(data)
		if err == nil {
			return decompressed, "lz4", nil
		}
	}

	for _, format := range []string{"gzip", "deflate", "zlib", "br", "zstd", "lz4"} {
		var decompressed []byte
		var err error
		switch format {
		case "gzip":
			decompressed, err = DecompressGzip(data)
		case "deflate", "zlib":
			decompressed, err = DecompressDeflate(data)
			if err != nil {
				decompressed, err = DecompressZlib(data)
			}
		case "br":
			decompressed, err = DecompressBrotli(data)
		case "zstd":
			decompressed, err = DecompressZstd(data)
		case "lz4":
			decompressed, err = DecompressLZ4(data)
		}
		if err == nil {
			return decompressed, format, nil
		}
	}

	return data, "identity", nil
}

func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}
