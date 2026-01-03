/// Function detection and call graph analysis
/// Identifies functions and builds call relationships

use super::pcode::*;
use anyhow::Result;
use goblin::pe::PE;
use std::collections::HashMap;

/// Function information
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    /// Function name (if known)
    pub name: Option<String>,
    /// Start address
    pub start_address: u64,
    /// End address
    pub end_address: Option<u64>,
    /// Function size in bytes
    pub size: Option<usize>,
    /// Is this an exported function
    pub is_export: bool,
    /// Functions called by this function
    pub callees: Vec<u64>,
    /// Functions calling this function
    pub callers: Vec<u64>,
}

/// Function detector
pub struct FunctionDetector {
    /// Detected functions
    functions: HashMap<u64, FunctionInfo>,
    /// Call graph (caller -> callees)
    call_graph: HashMap<u64, Vec<u64>>,
}

impl FunctionDetector {
    pub fn new() -> Self {
        Self {
            functions: HashMap::new(),
            call_graph: HashMap::new(),
        }
    }

    /// Detect exported functions from PE
    pub fn detect_exports(&mut self, pe: &PE, image_base: u64) -> Result<()> {
        for export in &pe.exports {
            if let Some(name) = export.name {
                let va = image_base + export.rva as u64;

                let func = FunctionInfo {
                    name: Some(name.to_string()),
                    start_address: va,
                    end_address: None,
                    size: None,
                    is_export: true,
                    callees: Vec::new(),
                    callers: Vec::new(),
                };

                self.functions.insert(va, func);
            }
        }

        Ok(())
    }

    /// Detect function prologues in P-code
    /// TODO: More sophisticated pattern matching
    pub fn detect_function_prologues(&mut self, pcodes: &[PcodeOp]) {
        let mut i = 0;
        while i < pcodes.len() {
            let op = &pcodes[i];

            if matches!(op.opcode, OpCode::Call) {
                if !op.inputs.is_empty() {
                    if let Some(target_addr) = self.extract_call_target(&op.inputs[0]) {
                        self.add_function_if_new(target_addr, None, false);
                        self.call_graph.entry(op.address).or_default().push(target_addr);
                    }
                }
            }

            i += 1;
        }
    }

    /// Extract call target address from varnode
    fn extract_call_target(&self, input: &Varnode) -> Option<u64> {
        if input.space == AddressSpace::Const {
            Some(input.offset)
        } else {
            None
        }
    }

    /// Add function if not already present
    fn add_function_if_new(&mut self, address: u64, name: Option<String>, is_export: bool) {
        self.functions.entry(address).or_insert(FunctionInfo {
            name,
            start_address: address,
            end_address: None,
            size: None,
            is_export,
            callees: Vec::new(),
            callers: Vec::new(),
        });
    }

    /// Update function boundaries from return instructions
    pub fn update_function_boundaries(&mut self, pcodes: &[PcodeOp]) {
        for op in pcodes {
            if matches!(op.opcode, OpCode::Return) {

                for (_, func) in self.functions.iter_mut() {
                    if func.start_address <= op.address && func.end_address.is_none() {
                        func.end_address = Some(op.address);
                        if let Some(size) = op.address.checked_sub(func.start_address) {
                            func.size = Some(size as usize);
                        }
                    }
                }
            }
        }
    }

    /// Update call graph edges
    pub fn update_call_graph(&mut self) {
        for (&caller_addr, callees) in &self.call_graph {
            let caller_func = self.find_function_containing(caller_addr);

            for &callee_addr in callees {
                if let Some(callee_func) = self.functions.get_mut(&callee_addr) {
                    if let Some(caller_func_addr) = caller_func {
                        if !callee_func.callers.contains(&caller_func_addr) {
                            callee_func.callers.push(caller_func_addr);
                        }
                    }
                }

                if let Some(caller_func_addr) = caller_func {
                    if let Some(caller_func) = self.functions.get_mut(&caller_func_addr) {
                        if !caller_func.callees.contains(&callee_addr) {
                            caller_func.callees.push(callee_addr);
                        }
                    }
                }
            }
        }
    }

    /// Find function containing an address
    fn find_function_containing(&self, address: u64) -> Option<u64> {
        for (&func_addr, func) in &self.functions {
            if func.start_address <= address {
                if let Some(end_addr) = func.end_address {
                    if address <= end_addr {
                        return Some(func_addr);
                    }
                } else {
                    return Some(func_addr);
                }
            }
        }
        None
    }

    /// Get all functions
    pub fn get_functions(&self) -> &HashMap<u64, FunctionInfo> {
        &self.functions
    }

    /// Get function by address
    pub fn get_function(&self, address: u64) -> Option<&FunctionInfo> {
        self.functions.get(&address)
    }

    /// Get exported functions
    pub fn get_export_functions(&self) -> Vec<&FunctionInfo> {
        self.functions
            .values()
            .filter(|f| f.is_export)
            .collect()
    }

    /// Get call graph
    pub fn get_call_graph(&self) -> &HashMap<u64, Vec<u64>> {
        &self.call_graph
    }

    /// Get function statistics
    pub fn get_statistics(&self) -> FunctionStatistics {
        FunctionStatistics {
            total_functions: self.functions.len(),
            export_functions: self.functions.values().filter(|f| f.is_export).count(),
            total_calls: self.call_graph.values().map(|v| v.len()).sum(),
        }
    }
}

/// Function statistics
#[derive(Debug, Clone)]
pub struct FunctionStatistics {
    pub total_functions: usize,
    pub export_functions: usize,
    pub total_calls: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_detector() {
        let mut detector = FunctionDetector::new();

        detector.add_function_if_new(0x1000, Some("main".to_string()), true);
        detector.add_function_if_new(0x2000, Some("helper".to_string()), false);

        assert_eq!(detector.functions.len(), 2);
        assert_eq!(detector.get_export_functions().len(), 1);
    }
}
