# Security policy

ContextSec processes untrusted repositories and influences security decisions, so vulnerabilities in its profiler, routing, skill instructions, evidence model, and supply chain are in scope.

Please use GitHub private vulnerability reporting in the repository's **Security** tab. If private reporting is unavailable, open a public issue requesting a private contact channel without including exploit details, repository secrets, personal data, or a live vulnerable target.

Useful reports include:

- path or symlink escape;
- target-code execution or unexpected network access;
- secret, PII, or source leakage in profile/evidence output;
- repository prompt injection that changes deterministic routing;
- a reliable false `inactive` result for a supported safety-critical context;
- stale or forged evidence accepted as current;
- a malicious pack/reference that gains undeclared privileges.

Do not test against systems you do not own or control. Use minimal synthetic fixtures and redact sensitive data.

The current profiler, checker, benchmark, and ledger are designed to be local, read-only by default, bounded, offline, and non-executing. A report showing a violation of one of those guarantees is high priority.
