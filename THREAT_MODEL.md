# Threat Model

## Overview

SENTINEL-GUARD is a local-first security tool that monitors AI-agent actions for risk. It operates on a **trust-but-verify** model: the agent's actions are observed, analyzed, and logged, but the tool itself does not execute or block actions at the OS level.

## Trust boundaries

```
┌─────────────────────────────────────────────────┐
│  Agent (untrusted)                              │
│  ┌───────────────────────────────────────────┐   │
│  │  Action stream (JSONL)                    │   │
│  └──────────────┬────────────────────────────┘   │
│                 │                                │
│  ┌──────────────▼────────────────────────────┐   │
│  │  SENTINEL-GUARD (trusted, local)          │   │
│  │  ├── Analyzer (rule-based risk scoring)   │   │
│  │  ├── Shield (injection detection)         │   │
│  │  ├── Guardrail (Allow/Deny/Sandbox)       │   │
│  │  └── Ledger (hash-chained audit log)      │   │
│  └───────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
```

## Threats addressed

### T1: Credential exfiltration
- **Attack:** Agent reads SSH keys, cloud credentials, `.env` files, tokens, certificates.
- **Mitigation:** `SECRET_PATTERNS` in `analyzer.rs` detects 35+ credential path patterns. Severity: High–Critical. Decision: Sandbox–Deny.
- **Residual risk:** Novel credential file names not in the pattern list.

### T2: Destructive commands
- **Attack:** Agent runs `rm -rf`, `mkfs`, fork bombs, shutdown, reverse shells.
- **Mitigation:** `DESTRUCTIVE_PATTERNS` in `analyzer.rs` detects 40+ destructive command patterns. Severity: High–Critical. Decision: Sandbox–Deny.
- **Residual risk:** Obfuscated commands (e.g., base64-encoded payloads) may evade pattern matching.

### T3: Prompt injection
- **Attack:** Malicious file or webpage content steers the agent to perform unauthorized actions.
- **Mitigation:** `shield.rs` scans text for 60+ injection patterns including instruction overrides, role takeovers, jailbreaks, fake system tags, and suspicious encodings.
- **Residual risk:** Novel injection phrasings not in the pattern list; adversarial evasion.

### T4: Audit log tampering
- **Attack:** Attacker modifies historical audit entries to hide malicious actions.
- **Mitigation:** `ledger.rs` uses SHA-256 hash chaining — each entry includes the hash of the previous entry. `ledger verify` detects any modification.
- **Residual risk:** If the attacker controls the machine, they can regenerate the entire chain. Mitigation: store ledger on append-only media or remote.

### T5: Unknown/unrecognized actions
- **Attack:** Agent performs an action type not covered by existing rules.
- **Mitigation:** Default severity is Medium (caution), not Low. The guardrail returns Allow for Medium, but the ledger records the uncertainty.
- **Residual risk:** Medium-severity actions are allowed, not sandboxed. Operators should review the ledger periodically.

## Threats NOT addressed

| Threat | Why not addressed | Mitigation |
|--------|-------------------|------------|
| Network-level attacks | Out of scope | Use firewall/IDS |
| Zero-day in dependencies | Out of scope | Run `cargo audit` |
| Social engineering | Human problem | Training |
| Host OS compromise | Out of scope | OS hardening |
| Actions outside observed stream | Cannot observe what isn't sent | Instrument all agent I/O |
| Adversarial ML attacks on LLM | No LLM in v0.1 | Future: LLM-based scoring |

## Assumptions

1. The agent's action stream is complete and accurate (no dropped events).
2. The host machine is not compromised.
3. The operator reviews the ledger and acts on Deny/Sandbox decisions.
4. Pattern lists are kept up to date with new attack vectors.

## Security properties

- **Confidentiality:** No data leaves the machine. No telemetry, no network calls.
- **Integrity:** Hash-chained ledger provides tamper evidence.
- **Availability:** Offline-first; no external dependencies at runtime.
- **Fail-closed:** Unrecognized actions default to Medium, not Low.
