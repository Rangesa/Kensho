// Kensho MCP Go実装（簡易版 - Capstoneなし）
package main

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// MCPRequest はMCPプロトコルのリクエスト
type MCPRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

// MCPResponse はMCPプロトコルのレスポンス
type MCPResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *MCPError   `json:"error,omitempty"`
}

// MCPError はエラー情報
type MCPError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// BinaryAnalyzer はバイナリ解析器
type BinaryAnalyzer struct{}

func NewBinaryAnalyzer() *BinaryAnalyzer {
	return &BinaryAnalyzer{}
}

// AnalyzeBinary はバイナリファイルを解析
func (ba *BinaryAnalyzer) AnalyzeBinary(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// ELFチェック
	if elfFile, err := elf.NewFile(file); err == nil {
		return ba.analyzeELF(elfFile), nil
	}

	// PEチェック
	file.Seek(0, 0)
	if peFile, err := pe.NewFile(file); err == nil {
		return ba.analyzePE(peFile), nil
	}

	// Mach-Oチェック
	file.Seek(0, 0)
	if machoFile, err := macho.NewFile(file); err == nil {
		return ba.analyzeMachO(machoFile), nil
	}

	return "Unknown binary format", nil
}

func (ba *BinaryAnalyzer) analyzeELF(elfFile *elf.File) string {
	output := "Format: ELF (Executable and Linkable Format)\n"

	// アーキテクチャ
	arch := "Unknown"
	switch elfFile.Machine {
	case elf.EM_386:
		arch = "x86 (32-bit)"
	case elf.EM_X86_64:
		arch = "x86-64 (64-bit)"
	case elf.EM_ARM:
		arch = "ARM"
	case elf.EM_AARCH64:
		arch = "AArch64 (ARM64)"
	}
	output += fmt.Sprintf("Architecture: %s\n", arch)

	// エントリポイント
	output += fmt.Sprintf("Entry Point: 0x%x\n", elfFile.Entry)

	// セクション
	output += fmt.Sprintf("\nSections: %d\n", len(elfFile.Sections))
	for i, section := range elfFile.Sections {
		if i >= 10 {
			break
		}
		output += fmt.Sprintf("  [%d] %s (0x%x, size: %d bytes)\n",
			i, section.Name, section.Addr, section.Size)
	}

	// シンボル
	symbols, _ := elfFile.Symbols()
	output += fmt.Sprintf("\nSymbols: %d\n", len(symbols))
	for i, sym := range symbols {
		if i >= 10 {
			break
		}
		if sym.Name != "" {
			output += fmt.Sprintf("  [%d] %s (0x%x)\n", i, sym.Name, sym.Value)
		}
	}

	return output
}

func (ba *BinaryAnalyzer) analyzePE(peFile *pe.File) string {
	output := "Format: PE (Portable Executable)\n"

	// アーキテクチャ
	arch := "Unknown"
	switch peFile.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		arch = "x86 (32-bit)"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		arch = "x86-64 (64-bit)"
	case pe.IMAGE_FILE_MACHINE_ARMNT:
		arch = "ARM"
	}
	output += fmt.Sprintf("Architecture: %s\n", arch)

	// セクション
	output += fmt.Sprintf("\nSections: %d\n", len(peFile.Sections))
	for i, section := range peFile.Sections {
		output += fmt.Sprintf("  [%d] %s (0x%x, size: %d bytes)\n",
			i, section.Name, section.VirtualAddress, section.VirtualSize)
	}

	return output
}

func (ba *BinaryAnalyzer) analyzeMachO(machoFile *macho.File) string {
	output := "Format: Mach-O (macOS/iOS)\n"

	// アーキテクチャ
	arch := "Unknown"
	switch machoFile.Cpu {
	case macho.Cpu386:
		arch = "x86 (32-bit)"
	case macho.CpuAmd64:
		arch = "x86-64 (64-bit)"
	case macho.CpuArm:
		arch = "ARM"
	case macho.CpuArm64:
		arch = "ARM64"
	}
	output += fmt.Sprintf("Architecture: %s\n", arch)

	// セグメント
	output += fmt.Sprintf("\nSegments: %d\n", len(machoFile.Loads))

	return output
}

func main() {
	analyzer := NewBinaryAnalyzer()
	decoder := json.NewDecoder(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)

	for {
		var req MCPRequest
		if err := decoder.Decode(&req); err != nil {
			if err == io.EOF {
				break
			}
			continue
		}

		var resp MCPResponse
		resp.JSONRPC = "2.0"
		resp.ID = req.ID

		switch req.Method {
		case "initialize":
			resp.Result = map[string]interface{}{
				"protocolVersion": "2024-11-05",
				"capabilities": map[string]interface{}{
					"tools": map[string]interface{}{},
				},
				"serverInfo": map[string]interface{}{
					"name":    "kensho-mcp-go-simple",
					"version": "0.1.0",
				},
			}

		case "tools/list":
			resp.Result = map[string]interface{}{
				"tools": []map[string]interface{}{
					{
						"name":        "analyze_binary",
						"description": "バイナリファイルの基本情報を解析（ELF/PE/Mach-O対応）",
						"inputSchema": map[string]interface{}{
							"type": "object",
							"properties": map[string]interface{}{
								"path": map[string]interface{}{
									"type":        "string",
									"description": "解析対象のバイナリファイルパス",
								},
							},
							"required": []string{"path"},
						},
					},
				},
			}

		case "tools/call":
			// ツール呼び出し処理
			var params struct {
				Name      string                 `json:"name"`
				Arguments map[string]interface{} `json:"arguments"`
			}
			json.Unmarshal(req.Params, &params)

			var result string
			var err error

			switch params.Name {
			case "analyze_binary":
				path := params.Arguments["path"].(string)
				result, err = analyzer.AnalyzeBinary(path)
			}

			if err != nil {
				resp.Error = &MCPError{
					Code:    -32603,
					Message: err.Error(),
				}
			} else {
				resp.Result = map[string]interface{}{
					"content": []map[string]interface{}{
						{
							"type": "text",
							"text": result,
						},
					},
				}
			}
		}

		encoder.Encode(resp)
	}
}
