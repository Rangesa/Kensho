/// 繧ｻ繝槭Φ繝・ぅ繝・け繝・・繝悶Ν縺ｮ繧ｹ繧ｭ繝ｼ繝槫ｮ夂ｾｩ
/// build.rs縺ｧ菴ｿ逕ｨ

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize, Serialize)]
pub struct SemanticRules {
    pub metadata: Metadata,
    #[serde(default)]
    pub instruction_classes: HashMap<String, InstructionClass>,
    pub instructions: HashMap<String, InstructionRule>,
    #[serde(default)]
    pub instruction_patterns: HashMap<String, InstructionPattern>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Metadata {
    pub architecture: String,
    pub version: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct InstructionClass {
    pub description: String,
    pub instructions: Vec<String>,
    pub pattern: OperandPattern,
    pub semantics: SemanticTemplate,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OperandPattern {
    pub operands: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SemanticTemplate {
    pub pcode: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct InstructionRule {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pcode: Option<String>,
    #[serde(default)]
    pub variants: Vec<InstructionVariant>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct InstructionVariant {
    pub operands: Vec<String>,
    pub pcode: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct InstructionPattern {
    pub pattern: String,
    pub conditions: Vec<Condition>,
    pub pcode: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Condition {
    pub name: String,
    pub flag_expr: String,
}
