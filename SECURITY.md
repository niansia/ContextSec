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

The current profiler, checker, benchmark, and ledger are designed to be local, read-only by default, bounded, offline, and non-executing. Repository files are read through descriptors with pre-open/opened identity comparison and post-read stability checks. A report showing a bypass, including a symlink/reparse or concurrent replacement that escapes the selected root, is high priority.

ContextSec does not create a system-wide atomic snapshot. For hostile local multi-process scenarios, evaluate an immutable checkout in an isolated environment in addition to relying on the built-in race-resistant reads.
