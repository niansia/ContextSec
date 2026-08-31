# Pinned real-repository cases

The v0.3 case studies were reviewed and profiled on 2026-08-31. Source is not vendored. Each case is identified by its upstream URL and immutable commit.

| Repository | Commit | Coverage | Expected routing |
|---|---|---|---|
| [niansia/Merriv](https://github.com/niansia/Merriv/tree/2fed8dc98273bb838920a0b5f06a79222f051e16) | `2fed8dc…` | complete | foundation, external API, AI, CI/CD; PII candidate |
| [fastapi/full-stack-fastapi-template](https://github.com/fastapi/full-stack-fastapi-template/tree/486f054cc8d1aead59ec96cc0a16933d06c10e0d) | `486f054…` | complete | web, auth, PII, API, upload, CI/CD, account deletion/high-impact |
| [stripe-samples/accept-a-payment](https://github.com/stripe-samples/accept-a-payment/tree/1a57c3b2f5aaf4ecd8de59ab0b1c3c5638827625) | `1a57c3b…` | partial | web, payments, API, external API, CI/CD; PII candidate |
| [openai/openai-quickstart-node](https://github.com/openai/openai-quickstart-node/tree/6e6e03496440913a82ccba6f17c2f41caa948c58) | `6e6e034…` | complete | foundation, external API, AI |

All four reproduced the reviewed required and candidate sets. This is useful evidence that the profiler handles Python, Node.js, CI workflows, multi-language samples, and noisy public layouts without executing them. It is still only four selected repositories.

The Stripe samples case intentionally remains `partial`: one supported production file exceeds the default 512 KiB single-file bound. ContextSec preserves that limitation rather than converting a large-repository result into a false complete profile.

The first real-repository pass exposed two v0.3 changes:

- production Python dependency manifests needed first-class evidence while test/example manifests still had to remain excluded;
- generic payment `retrieve` names were too broad for an AI RAG sub-capability and were narrowed to RAG-specific terms.

This feedback loop is the purpose of the case-study suite: discover classifier errors that small fixtures do not reveal, then retain exact commits and negative regressions.
