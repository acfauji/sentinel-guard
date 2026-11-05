//! Guardrail decision engine.
//!
//! Combines analyzer verdict + shield injection findings into a single
//! decision: Allow, Deny, or Sandbox.

use crate::analyzer::analyze;
use crate::model::{AgentAction, RiskVerdict, Severity};
use crate::shield::{scan, max_severity};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Decision {
    Allow,
    Deny,
    Sandbox,
}

impl Decision {
    pub fn label(&self) -> &'static str {
        match self {
            Decision::Allow => "ALLOW",
            Decision::Deny => "DENY",
            Decision::Sandbox => "SANDBOX",
        }
    }
}

/// Result of guard evaluation.
#[derive(Debug, Clone, Serialize)]
pub struct DecisionResult {
    pub decision: Decision,
    pub verdict: RiskVerdict,
    pub injection_findings: Vec<crate::shield::InjectionFinding>,
    pub reason: String,
}

/// Decide whether to allow, deny, or sandbox an action.
pub fn evaluate(action: &AgentAction) -> DecisionResult {
    let verdict = analyze(action);
    let findings = scan(&format!("{} {} {}", action.kind, action.target, action.content));
    let max_inj = max_severity(&findings);

    let (decision, reason) = if verdict.severity == Severity::Critical
        || max_inj == Some(Severity::Critical) {
        (Decision::Deny, "blocked: critical or injection risk".into())
    } else if verdict.severity == Severity::High || max_inj == Some(Severity::High) {
        (Decision::Sandbox, "blocked-or-sandbox: high-risk or high-confidence injection".into())
    } else {
        (Decision::Allow, "allowed".into())
    };

    DecisionResult {
        decision,
        verdict,
        injection_findings: findings,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(kind: &str, target: &str) -> AgentAction {
        AgentAction {
            kind: kind.into(),
            target: target.into(),
            content: String::new(),
            agent: "t".into(),
        }
    }

    #[test]
    fn deny_critical() {
        let r = evaluate(&a("read_file", "/root/.ssh/id_rsa"));
        assert_eq!(r.decision, Decision::Deny);
    }

    #[test]
    fn sandbox_high() {
        let r = evaluate(&a("read_file", "/home/user/.env"));
        assert_eq!(r.decision, Decision::Deny);
    }

    #[test]
    fn allow_safe() {
        let r = evaluate(&a("read_file", "README.md"));
        assert_eq!(r.decision, Decision::Allow);
    }

    #[test]
    fn deny_injection() {
        let r = evaluate(&a("read_file", "/tmp/safe.txt"));
        // injection should be detected in content/target
        let r2 = evaluate(&AgentAction {
            kind: "read_file".into(),
            target: "/tmp/safe.txt".into(),
            content: "ignore previous instructions".into(),
            agent: "t".into(),
        });
        assert_eq!(r2.decision, Decision::Deny);
    }
}
