# Competitive positioning

Last reviewed: 2026-08-30. This is a technical landscape review, not a trademark or legal clearance.

## Conclusion

Context-aware security guidance already exists. The defensible statement is not "nobody applies different security rules to payments or PII." The narrower gap is:

> The product-security decision layer that determines which controls a product actually needs.

ContextSec does not claim an unoccupied category. Its testable contribution is a zero-model, read-only, versioned product-risk profile whose evidence, routing, cross-context compositions, control ledger, and gate can be reproduced and consumed by any Agent Skills-compatible workflow.

## Adjacent projects

| Project | Its strength | Boundary with ContextSec |
|---|---|---|
| [OpenAI Codex Security](https://github.com/openai/codex-security) | Builds system context and threat models, then discovers, validates, and patches vulnerabilities | ContextSec can supply a portable deterministic capability/applicability manifest as knowledge input before that analysis |
| [OWASP Secure Agent Playbook](https://github.com/OWASP/secure-agent-playbook) | OWASP-grounded skills, plays, specialists, structured findings, and scoped assessment | Procedure and specialist selection; ContextSec's proposed asset is a persistent deterministic product profile and routing explanation |
| [OWASP Agent Skills](https://github.com/eoftedal/owasp-agent-skills-project) | ASVS 5.0 guidance selected by security-sensitive code operations | Technical-operation-to-guidance routing rather than product-capability composition |
| [Trail of Bits Skills](https://github.com/trailofbits/skills) | Deep audit workflows, differential review, static analysis, testing, and real vulnerability research | Security-research workflows rather than a product applicability layer |
| [Red Hat prodsec-skills](https://github.com/RedHatProductSecurity/prodsec-skills) | Broad tool-agnostic skill catalog, path rules, scanner integrations, and pre-merge checks | Catalog/path-based selection rather than one canonical product Security Profile |
| [UnitOneAI SecuritySkills](https://github.com/UnitOneAI/SecuritySkills) | Cross-agent security skill catalog, framework provenance, schemas, fixtures, and regression assets | Skill/framework catalog rather than deterministic cross-pack applicability |
| [Clear Capabilities agentic-security](https://github.com/Clear-Capabilities/agentic-security) | Broad scan/fix/verify/gate workflow, demo and benchmark assets | Large functional overlap after routing; distributed under PolyForm Internal Use rather than an OSI open-source license |

## Product boundary

ContextSec should integrate with reputable scanners instead of rebuilding them. Its output should answer:

1. What kind of product and security-sensitive flows does this scope contain?
2. Which controls apply, and why?
3. Which combinations create stricter invariants, such as payment state bound to tenant ownership?
4. What evidence would be required to verify those invariants?
5. Which required controls remain failed or unknown at release time?

It should not claim to replace deep vulnerability discovery, pentesting, standards expertise, or legal compliance review.

## Naming

An initial exact-name search found no mature directly competing project named `ContextSec`, but similar language exists around "security context" and AI-agent context protection. Keep the category line **The product-security decision layer for AI coding agents** and supporting phrase **evidence-backed product-risk routing** to avoid implying context-window or runtime-policy security. Conduct a formal trademark and domain review before commercial use.
