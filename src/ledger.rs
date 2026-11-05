//! Tamper-evident, hash-chained audit ledger.
//!
//! Each entry commits to the previous entry's hash. Retroactive tampering
//! invalidates the chain.

use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

use crate::model::{AgentAction, RiskVerdict};

/// The full ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ledger {
    pub entries: Vec<LedgerEntry>,
}

/// One immutable entry in the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub index: u64,
    pub timestamp: String,
    pub action: AgentAction,
    pub verdict: RiskVerdict,
    pub prev_hash: String,
    pub hash: String,
}

impl Ledger {
    /// Start a new ledger.
    pub fn new() -> Self {
        Ledger { entries: Vec::new() }
    }

    /// Append an entry; computes its hash from (index, timestamp, action,
    /// verdict, previous hash).
    pub fn append(&mut self, action: AgentAction, verdict: RiskVerdict) -> LedgerEntry {
        let index = self.entries.len() as u64;
        let timestamp = chrono::Utc::now().to_rfc3339();
        let prev_hash = match self.entries.last() {
            Some(prev) => prev.hash.clone(),
            None => "0".repeat(64),
        };

        let hash = LedgerEntry::hash_entry(index, &timestamp, &action, &verdict, &prev_hash);

        let entry = LedgerEntry {
            index,
            timestamp,
            action,
            verdict,
            prev_hash,
            hash,
        };
        self.entries.push(entry.clone());
        entry
    }

    /// Verify the chain: every entry's hash matches recomputation.
    pub fn verify(&self) -> Result<(), VerifyError> {
        let mut prev_hash = "0".repeat(64);
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.index != i as u64 {
                return Err(VerifyError::OutOfOrder(entry.index));
            }
            // verify hash
            let hash = LedgerEntry::hash_entry(
                entry.index,
                &entry.timestamp,
                &entry.action,
                &entry.verdict,
                &prev_hash,
            );
            if entry.hash != hash {
                return Err(VerifyError::HashMismatch(entry.index));
            }
            // verify chain linkage
            if entry.prev_hash != prev_hash {
                return Err(VerifyError::ChainMismatch(entry.index));
            }
            prev_hash = entry.hash.clone();
        }
        Ok(())
    }

    pub fn entries(&self) -> Vec<LedgerEntry> {
        self.entries.clone()
    }
}

impl LedgerEntry {
    /// Compute SHA256 over the canonical serialization.
    pub fn hash_entry(
        index: u64,
        timestamp: &str,
        action: &AgentAction,
        verdict: &RiskVerdict,
        prev_hash: &str,
    ) -> String {
        let payload = serde_json::json!({
            "index": index,
            "timestamp": timestamp,
            "kind": action.kind,
            "target": action.target,
            "content": action.content,
            "agent": action.agent,
            "severity": verdict.severity.label(),
            "reason": verdict.reason,
            "indicators": verdict.indicators,
            "prev_hash": prev_hash,
        });
        let payload = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string());
        let mut hasher = Sha256::new();
        hasher.update(payload.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

#[derive(Debug, Clone)]
pub enum VerifyError {
    HashMismatch(u64),
    ChainMismatch(u64),
    OutOfOrder(u64),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::HashMismatch(i) => write!(f, "hash mismatch at entry {}", i),
            VerifyError::ChainMismatch(i) => write!(f, "chain mismatch at entry {}", i),
            VerifyError::OutOfOrder(i) => write!(f, "entries out of order at index {}", i),
        }
    }
}

impl std::error::Error for VerifyError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    fn dummy_action() -> AgentAction {
        AgentAction {
            kind: "read_file".into(),
            target: "/etc/passwd".into(),
            content: String::new(),
            agent: "test".into(),
        }
    }

    #[test]
    fn append_and_verify() {
        let mut l = Ledger::new();
        let v = RiskVerdict {
            severity: Severity::High,
            reason: "read /etc/passwd".into(),
            indicators: vec!["password-file".into()],
        };
        l.append(dummy_action(), v.clone());
        assert!(l.verify().is_ok());
    }

    #[test]
    fn tamper_detected() {
        let mut l = Ledger::new();
        let v = RiskVerdict {
            severity: Severity::Low,
            reason: "ok".into(),
            indicators: vec![],
        };
        l.append(dummy_action(), v.clone());
        // Mutate the entry directly (simulating tampering).
        l.entries[0].action.target = "/etc/shadow".into();
        assert!(l.verify().is_err());
    }

    #[test]
    fn empty_ledger_verify_ok() {
        let l = Ledger::new();
        assert!(l.verify().is_ok());
    }

}
