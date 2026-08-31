# AI, RAG, and agent pack

Apply to model inference, prompt construction, retrieval, vector stores, tool/MCP calls, memory, or autonomous actions.

| ID | Invariant | Minimum verification evidence |
|---|---|---|
| `AIR-DATA-001` | Prompts, context, training/fine-tuning data, traces, and provider requests exclude unnecessary secrets and PII. | Representative egress and observability inspection. |
| `AIR-INJECT-001` | Retrieved documents, web content, tool output, and model output are untrusted data; embedded instructions cannot change system authority or policy. | Indirect-injection tests through each active untrusted channel. |
| `AIR-RAG-001` | Retrieval enforces source/tenant/subject authorization before ranking and preserves source provenance. | Cross-tenant/subject retrieval and poisoned-document tests. |
| `AIR-TOOL-001` | Tools use explicit schemas, least privilege, server-side authorization, bounded arguments, and approval for high-impact actions. | Unauthorized, extra-argument, and approval-bypass tests. |
| `AIR-MEM-001` | Memory is scoped, integrity-protected, retention-bounded, and cannot leak or persist attacker instructions across users/tenants. | Cross-user/tenant and persistence-poisoning tests. |
| `AIR-OUT-001` | Model output is validated and encoded before it becomes code, queries, HTML, paths, tool arguments, or trusted decisions. | Malicious structured-output and rendering/tool-call tests. |
| `AIR-AUTO-001` | Autonomous actions have budgets, transaction/value limits, checkpoints, audit, rollback where feasible, and human approval at irreversible boundaries. | Budget/limit/approval/rollback behavior tests. |

Model self-evaluation is not verification. Prefer deterministic policy checks and end-to-end negative tests around model-controlled boundaries.

Standards navigation: OWASP Top 10 for LLM Applications, OWASP Top 10 for Agentic Applications, and the OWASP AISVS version selected by the project. Mappings are guidance only.
