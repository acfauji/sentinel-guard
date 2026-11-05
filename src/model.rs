use serde::{Deserialize, Serialize};

/// Severity rating for an action or finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

/// A single action an agent attempted, as observed from the agent stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAction {
    /// e.g. "read_file", "write_file", "run_command", "network", "delete"
    pub kind: String,
    /// Target path, URL, command, etc.
    pub target: String,
    /// Optional content or args (truncated for safety).
    #[serde(default)]
    pub content: String,
    /// Session / agent identifier.
    #[serde(default)]
    pub agent: String,
}

/// The risk verdict for one action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskVerdict {
    pub severity: Severity,
    /// Short reason, e.g. "credential file accessed".
    pub reason: String,
    /// Matched indicators.
    #[serde(default)]
    pub indicators: Vec<String>,
}
