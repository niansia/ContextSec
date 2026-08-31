# Source and standards registry

Last reviewed: 2026-08-31.

ContextSec control language is original. The following primary sources inform terminology and standards navigation; they are not fetched as runtime instructions and their presence does not establish compliance.

| Source | Reviewed version/status | Use |
|---|---|---|
| [Agent Skills specification and reference validator](https://github.com/agentskills/agentskills/tree/69ef37e9424c0a7ea9dd2293b559e43ec8176379) | Commit `69ef37e9424c0a7ea9dd2293b559e43ec8176379` | Skill structure, frontmatter, progressive disclosure, pinned CI validation |
| [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) | 5.0.0 stable | Web/application control navigation |
| [OWASP API Security Top 10](https://owasp.org/API-Security/) | 2023 edition | Inbound and unsafe third-party API risk navigation |
| [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) | Current on review date | Focused implementation guidance |
| [PCI DSS](https://www.pcisecuritystandards.org/standards/pci-dss/) | 4.0.1 baseline used by this preview | Payment-data scope navigation only |
| [NIST Privacy Framework](https://www.nist.gov/privacy-framework) | 1.0 baseline used by this preview | Privacy-risk and data-lifecycle navigation |
| [NIST SSDF SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final) | 1.1 final | Secure development and provenance navigation |
| [SLSA](https://slsa.dev/spec/v1.2/) | 1.2 | Supply-chain provenance navigation |
| [OWASP Top 10 for Agentic Applications](https://owasp.org/www-project-top-10-for-agentic-applications/) | Current on review date | Agent autonomy and tool-risk navigation |
| [OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/top10) | Current on review date | Security of ContextSec itself and untrusted skill instructions |
| [Zeabur incident update](https://status.zeabur.com/incident/1037896?mp=true) | Ongoing investigation, update dated 2026-08-29 | Confirmed facts for secret-plane and cloud-control-plane incident mapping; unconfirmed root-cause conclusions excluded |
| [GitHub Advisory GHSA-mrrh-fwg8-r2c3](https://github.com/advisories/ghsa-mrrh-fwg8-r2c3) | GitHub-reviewed advisory, updated 2025-10-22 | CI action mutability, runner secret exposure, and rotation incident mapping |
| [Coinbase support insider disclosure](https://www.coinbase.com/en-nl/blog/protecting-our-customers-standing-up-to-extortionists) | First-party disclosure dated 2025-05-15 | Support/admin data access and high-impact transaction incident mapping |
| [Google Cloud Threat Horizons H1 2026](https://cloud.google.com/security/report/resources/cloud-threat-horizons-report-h1-2026) | Google Cloud/Mandiant report reviewed 2026-08-31 | SaaS OAuth bulk export and CI OIDC-to-cloud-control-plane incident mapping |

Future control-to-standard mappings must record a versioned source identifier and review date. Mappings never replace a qualified assessor or legal analysis.

The public repositories used as v0.3 profile case studies, including full commit IDs and license labels, are recorded separately in [`benchmarks/real-repos.json`](benchmarks/real-repos.json). They inform detector regressions but are not control-language authorities.
