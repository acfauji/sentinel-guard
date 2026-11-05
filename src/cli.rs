use crate::guardrail::{evaluate, Decision};
use crate::ledger::{Ledger, LedgerEntry};
use crate::model::AgentAction;
use crate::shield::scan;
use clap::Parser;
use std::fs;
use std::io::{self, Read, BufRead};

#[derive(Parser, Debug)]
#[command(name = "sentinel-guard")]
#[command(about = "Security-first AI-agent governance: inspect, judge, sandbox, audit")]
enum Cli {
    /// Watch stdin (JSONL of AgentAction) and judge each line.
    Watch {
        /// Stop at first Deny
        #[arg(short, long)]
        stop_on_deny: bool,
    },
    /// Analyze a single action JSON object from stdin or argument.
    Analyze {
        #[arg(short, long)]
        input: Option<String>,
    },
    /// Scan a string for injection.
    Shield {
        #[arg(short, long)]
        input: Option<String>,
    },
    /// Ledger commands.
    Ledger {
        #[command(subcommand)]
        cmd: LedgerCmd,
    },
}

#[derive(clap::Subcommand, Debug)]
enum LedgerCmd {
    /// Verify the ledger chain.
    Verify { file: String },
    /// Append an action JSON to the ledger.
    Append { file: String, action: String },
}

pub fn run() {
    let cli = Cli::parse();

    match cli {
        Cli::Watch { stop_on_deny } => run_watch(stop_on_deny),
        Cli::Analyze { input } => run_analyze(input),
        Cli::Shield { input } => run_shield(input),
        Cli::Ledger { cmd } => match cmd {
            LedgerCmd::Verify { file } => run_ledger_verify(&file),
            LedgerCmd::Append { file, action } => run_ledger_append(&file, &action),
        },
    }
}

fn run_watch(stop_on_deny: bool) {
    let mut ledger = Ledger::new();
    let mut stdin = io::stdin().lock();

    loop {
        let mut line = String::new();
        match stdin.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                eprintln!("read error: {}", e);
                break;
            }
        }

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let action: AgentAction = match serde_json::from_str::<AgentAction>(line) {
            Ok(a) => a,
            Err(_) => {
                eprintln!("skip invalid JSON: {}", line);
                continue;
            }
        };

        let decision = evaluate(&action);
        ledger.append(action.clone(), decision.verdict.clone());

        println!(
            "[{}] {} | severity={} | reason='{}' | injection={}",
            action.kind,
            action.target,
            decision.verdict.severity.label(),
            decision.reason,
            decision
                .injection_findings
                .iter()
                .map(|f| f.pattern.as_str())
                .collect::<Vec<_>>()
                .join(",")
        );

        if decision.decision == Decision::Deny && stop_on_deny {
            break;
        }
    }

    match ledger.verify() {
        Ok(()) => eprintln!("[ledger] verified: {} entries intact", ledger.entries().len()),
        Err(e) => eprintln!("[ledger] CORRUPT: {}", e),
    }
}

fn run_analyze(input: Option<String>) {
    let text = match input {
        Some(s) => s,
        None => {
            let mut s = String::new();
            io::stdin().read_to_string(&mut s).unwrap_or_default();
            s.trim().to_string()
        }
    };

    let action: AgentAction = match serde_json::from_str(&text) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("invalid JSON: {}", e);
            std::process::exit(1);
        }
    };

    let decision = evaluate(&action);
    println!("{}", serde_json::to_string_pretty(&decision).unwrap());
}

fn run_shield(input: Option<String>) {
    let text = match input {
        Some(s) => s,
        None => {
            let mut s = String::new();
            io::stdin().read_to_string(&mut s).unwrap_or_default();
            s.trim().to_string()
        }
    };

    let findings = scan(&text);
    if findings.is_empty() {
        println!("clean (no injection patterns)");
    } else {
        for f in findings {
            println!("{:?} | {}", f.severity, f.pattern);
        }
    }
}

fn run_ledger_verify(file: &str) {
    let text = match fs::read_to_string(file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("read ledger file: {}", e);
            std::process::exit(1);
        }
    };
    let entries: Vec<LedgerEntry> = match serde_json::from_str(&text) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("parse ledger file: {}", e);
            std::process::exit(1);
        }
    };
    let l = Ledger { entries };
    match l.verify() {
        Ok(()) => println!("ledger OK: {} entries verified", l.entries().len()),
        Err(e) => {
            eprintln!("ledger corrupt: {}", e);
            std::process::exit(1);
        }
    }
}

fn run_ledger_append(file: &str, action: &str) {
    let text = fs::read_to_string(file).unwrap_or_default();
    let mut l: Ledger = if text.trim().is_empty() {
        Ledger { entries: Vec::new() }
    } else {
        match serde_json::from_str(&text) {
            Ok(entries) => Ledger { entries },
            Err(e) => {
                eprintln!("parse ledger file: {}", e);
                std::process::exit(1);
            }
        }
    };
    let action: AgentAction = match serde_json::from_str(action) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("invalid action JSON: {}", e);
            std::process::exit(1);
        }
    };
    let verdict = evaluate(&action);
    l.append(action, verdict.verdict);
    let out = serde_json::to_string_pretty(&l.entries()).unwrap();
    // Atomic write: write to temp file, then rename
    let tmp_path = format!("{}.tmp", file);
    if let Err(e) = fs::write(&tmp_path, &out) {
        eprintln!("write ledger file: {}", e);
        std::process::exit(1);
    }
    if let Err(e) = fs::rename(&tmp_path, file) {
        eprintln!("rename ledger file: {}", e);
        let _ = fs::remove_file(&tmp_path);
        std::process::exit(1);
    }
    println!("appended");
}
