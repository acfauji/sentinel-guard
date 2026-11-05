# Contributing to SENTINEL-GUARD

## Getting started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/sentinel-guard.git`
3. Build: `cargo build`
4. Run tests: `cargo test`
5. Create a branch: `git checkout -b feat/your-feature`

## Development workflow

### Adding a new risk pattern

1. Add the pattern to the appropriate constant in `src/analyzer.rs`:
   - `SECRET_PATTERNS` for credential/secret paths
   - `DESTRUCTIVE_PATTERNS` for dangerous commands
   - `SAFE_PATTERNS` for recognized benign operations

2. Add a test in the `#[cfg(test)]` module of `analyzer.rs`.

3. Run `cargo test` to verify.

### Adding a new injection pattern

1. Add the pattern to `INJECTION_PATTERNS` in `src/shield.rs`.

2. Add a test in the `#[cfg(test)]` module of `shield.rs`.

3. Run `cargo test` to verify.

### Code style

- Use `cargo fmt` if available (rustfmt).
- Use `cargo clippy` if available.
- Keep functions small and focused.
- Add doc comments to public items.
- Prefer `&str` over `String` in function parameters.

### Testing

- Every new pattern must have a corresponding test.
- Tests should be in the same file as the code they test.
- Use descriptive test names: `flags_<what>` or `detects_<what>`.
- Run the full suite before submitting: `cargo test`.

### Pull requests

1. Ensure all tests pass: `cargo test`
2. Ensure the build succeeds: `cargo build --release`
3. Write a clear PR description explaining what and why.
4. Reference any related issues.

## Architecture

```
src/
├── model.rs      # Data types (Severity, AgentAction, RiskVerdict, LedgerEntry)
├── analyzer.rs   # Risk analysis (rule-based, offline-first)
├── shield.rs     # Prompt-injection detection
├── guardrail.rs  # Decision engine (Allow/Deny/Sandbox)
├── ledger.rs     # Hash-chained audit log
├── cli.rs        # CLI interface (clap)
└── main.rs       # Entry point
```

### Data flow

```
AgentAction → analyzer::analyze() → RiskVerdict
                                    ↓
AgentAction → shield::scan() → Vec<InjectionFinding>
                                    ↓
            guardrail::evaluate() → DecisionResult (Allow/Deny/Sandbox)
                                    ↓
            ledger.append() → hash-chained entry
```

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
