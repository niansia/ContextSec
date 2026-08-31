# Privacy and PII pack

Apply when the product collects, stores, logs, exports, deletes, analyzes, or sends identifiable personal data to another processor.

| ID | Invariant | Minimum verification evidence |
|---|---|---|
| `PII-INV-001` | Personal data fields have an inventory covering collection source, purpose, store, access, processor/egress, retention, and deletion path. | Data-flow artifact tied to schema/routes/config, not prose alone. |
| `PII-MIN-001` | Each collected, returned, logged, or transmitted field has a necessary product purpose and the narrowest viable audience. | Request/response/log/egress projection tests. |
| `PII-ACCESS-001` | Read, search, export, update, and deletion operations enforce subject/tenant/role authorization consistently. | Wrong-subject and wrong-role negative tests. |
| `PII-RET-001` | Retention and deletion cover databases, caches, object storage, search/vector stores, backups as applicable, and third-party processors. | Lifecycle test or evidence-backed procedure; absence of code is not proof. |
| `PII-LOG-001` | Logs, analytics, tracing, crash reporting, support tools, and model prompts exclude or redact unnecessary PII. | Representative success/failure-path sink inspection. |
| `PII-PROC-001` | Data sent to third parties is minimized, intentionally configured, access-controlled, and represented in the inventory. | Outbound payload/config inspection and processor list. |
| `PII-RIGHTS-001` | Export and deletion are complete, authorized, and do not expose other subjects' data. | Cross-user export/delete negative tests plus lifecycle coverage. |
| `PII-FANOUT-001` | Relationship, sharing, and discovery graphs cannot amplify one compromised account into unauthorized bulk access to other people. | Graph-neighbor authorization, response-minimization, rate, and anomaly tests. |

Legal basis, jurisdiction, consent, DPIA, and regulatory applicability require qualified human/legal input. Report them as unresolved governance questions rather than inferring compliance.

Standards navigation: NIST Privacy Framework and jurisdiction-specific requirements selected by the project. This pack does not determine GDPR, HIPAA, or other legal applicability.
