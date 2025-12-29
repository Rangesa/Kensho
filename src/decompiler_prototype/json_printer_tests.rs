

#[cfg(test)]
mod tests {
    use super::super::json_printer::*;
    use super::super::cfg::ControlFlowGraph;
    use super::super::test_utils::example_translation;

    #[test]
    fn test_json_serialization_format() {
        // Use example_translation to generate JSON output        let pcodes = example_translation();
        let cfg = ControlFlowGraph::from_pcodes(pcodes);

        let printer = JsonPrinter::new();
        let result = printer.print(&cfg, "test.exe", 0x140001000);

        // Output in JSON format
        let json = serde_json::to_string(&result).unwrap();

        // Check for required fields
        assert!(json.contains("format_version"));
        assert!(json.contains("binary"));
        assert!(json.contains("function"));
        assert!(json.contains("cfg"));
        assert!(json.contains("confidence"));
    }

    #[test]
    fn test_confidence_scores_range() {
        // Confidence score should be between 0.0 and 1.0
        let pcodes = example_translation();
        let cfg = ControlFlowGraph::from_pcodes(pcodes);

        let printer = JsonPrinter::new();
        let result = printer.print(&cfg, "test.exe", 0x140001000);

        assert!(result.confidence.control_flow >= 0.0);
        assert!(result.confidence.control_flow <= 1.0);
        assert!(result.confidence.data_types >= 0.0);
        assert!(result.confidence.data_types <= 1.0);
    }

    #[test]
    fn test_json_schema_compliance() {
        // Check if matches JSON Schema example        let pcodes = example_translation();
        let cfg = ControlFlowGraph::from_pcodes(pcodes);

        let printer = JsonPrinter::new();
        let result = printer.print(&cfg, "test.exe", 0x140001000);

        // format_version is "1.0"
        assert_eq!(result.format_version, "1.0");

        // architecture is "x86-64"
        assert_eq!(result.binary.architecture, "x86-64");

        // address starts with "0x"        assert!(result.function.address.starts_with("0x"));
    }
}
