// question.exe専用解析プログラム
use anyhow::Result;
use kensho_mcp::analyzer::BinaryAnalyzer;
use kensho_mcp::decompiler_prototype::{
    ParallelDecompiler, HashStrategy, ObfuscationDetector
};
use std::path::Path;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let binary_path = "D:\\Programming\\MCP\\question.exe";
    let cache_dir = "D:\\Programming\\MCP\\cache";

    println!("========================================");
    println!("   Question.exe 詳細解析");
    println!("========================================\n");

    // Step 1: 基本情報取得
    println!("📋 Step 1: バイナリ基本情報");
    println!("----------------------------------------");
    let analyzer = BinaryAnalyzer::new(binary_path)?;
    let summary = analyzer.get_summary()?;

    println!("ファイルサイズ: {} bytes", summary.file_size);
    println!("フォーマット: {}", summary.format);
    println!("アーキテクチャ: {}", summary.architecture);
    println!("エントリポイント: 0x{:X}", summary.entry_point);

    if let Some(stats) = &summary.stats {
        println!("\n統計情報:");
        println!("  セクション数: {}", stats.section_count);
        println!("  関数数: {}", stats.function_count);
        println!("  インポート数: {}", stats.import_count);
        println!("  エクスポート数: {}", stats.export_count);
        println!("  文字列数（推定）: {}", stats.string_count_estimate);
    }

    // Step 2: セクション一覧
    println!("\n📂 Step 2: セクション一覧");
    println!("----------------------------------------");
    let sections = analyzer.list_sections(0, 20)?;
    for section in &sections.sections {
        println!("  {} - 0x{:08X} ({} bytes) - Perms: {}",
            section.name,
            section.virtual_address,
            section.size,
            section.permissions
        );
    }

    // Step 3: インポート関数（興味深いものを抽出）
    println!("\n🔗 Step 3: インポート関数（セキュリティ関連）");
    println!("----------------------------------------");
    let imports = analyzer.list_imports()?;
    let security_keywords = vec![
        "Crypt", "Hash", "Random", "Security", "Protect", "Virtual",
        "Process", "Thread", "Debug", "Anti"
    ];

    for import in &imports.imports {
        for keyword in &security_keywords {
            if import.name.contains(keyword) {
                println!("  {} (from {})", import.name, import.library);
            }
        }
    }

    // Step 4: 文字列抽出（興味深いものを探す）
    println!("\n🔤 Step 4: 興味深い文字列");
    println!("----------------------------------------");
    let strings = analyzer.list_strings(0, 200)?;
    let interesting_keywords = vec![
        "flag", "key", "password", "secret", "admin", "root",
        "correct", "wrong", "success", "fail", "check", "verify"
    ];

    let mut found_strings = Vec::new();
    for string in &strings.strings {
        let lower = string.content.to_lowercase();
        for keyword in &interesting_keywords {
            if lower.contains(keyword) {
                found_strings.push(string.clone());
                break;
            }
        }
    }

    for (i, string) in found_strings.iter().take(20).enumerate() {
        println!("  [{}] 0x{:08X}: \"{}\"",
            i + 1,
            string.address,
            string.content.chars().take(60).collect::<String>()
        );
    }

    // Step 5: 関数一覧（main関連を探す）
    println!("\n🎯 Step 5: 重要な関数を検索");
    println!("----------------------------------------");

    // mainやcheck、verifyなどの関数を探す
    let function_keywords = vec!["main", "check", "verify", "validate", "compare"];
    for keyword in &function_keywords {
        let functions = analyzer.list_functions(0, 50, Some(keyword))?;
        if !functions.functions.is_empty() {
            println!("\n\"{}\"を含む関数 ({} 個):", keyword, functions.total_count);
            for func in &functions.functions {
                println!("  0x{:08X} - {} ({} bytes)",
                    func.address,
                    func.name,
                    func.size.unwrap_or(0)
                );
            }
        }
    }

    // Step 6: エントリポイントをデコンパイル
    println!("\n⚙️ Step 6: エントリポイント解析");
    println!("----------------------------------------");
    let decompiler = ParallelDecompiler::with_strategy(
        Path::new(cache_dir),
        HashStrategy::Metadata
    )?;

    let entry_result = decompiler.decompile_function(
        binary_path,
        summary.entry_point as usize,
        None,
        1000
    );

    match entry_result {
        Ok(result) => {
            println!("デコンパイル成功！");
            println!("\nC疑似コード:");
            println!("{}", result.decompiled);

            // 難読化検出
            if let Some(cfg) = result.cfg {
                let mut detector = ObfuscationDetector::new();
                let obfuscation_data = detector.analyze(&cfg);

                println!("\n🔍 難読化解析結果:");
                println!("  難読化スコア: {:.2}", obfuscation_data.obfuscation_score);
                println!("  検出されたパターン: {} 個", obfuscation_data.patterns.len());

                for (i, pattern) in obfuscation_data.patterns.iter().take(5).enumerate() {
                    println!("\n  パターン {} - {:?}", i + 1, pattern.pattern_type);
                    println!("    信頼度: {:.2}", pattern.confidence);
                    println!("    説明: {}", pattern.description);
                }

                if let Some(stats) = &obfuscation_data.mba_statistics {
                    println!("\n  MBA統計:");
                    println!("    検出数: {}", stats.total_detected);
                    println!("    簡約成功: {}", stats.simplified_count);
                }
            }
        }
        Err(e) => {
            println!("デコンパイルエラー: {}", e);
        }
    }

    println!("\n========================================");
    println!("解析完了！");
    println!("========================================");

    Ok(())
}
