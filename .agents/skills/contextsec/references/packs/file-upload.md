# File upload pack

Apply to user-controlled files, archives, media, documents, presigned uploads, import jobs, or object storage ingestion.

| ID | Invariant | Minimum verification evidence |
|---|---|---|
| `UPL-TYPE-001` | Allowed types are explicit and verified using extension, declared type, and content signature as appropriate; mismatches fail closed. | Mismatch and disallowed-type tests. |
| `UPL-NAME-001` | Server-generated storage names prevent traversal, overwrite, reserved-name, and normalization attacks. | Traversal/collision/Unicode normalization tests. |
| `UPL-SIZE-001` | Compressed and uncompressed sizes, file counts, nesting, dimensions, and processing time are bounded before expensive work. | Oversize, archive-bomb, and timeout tests. |
| `UPL-STORE-001` | New uploads are non-public, isolated from executable/web roots, and inaccessible until policy checks complete. | Public ACL/direct URL negative test. |
| `UPL-PROC-001` | Parsers/converters run with least privilege and isolation proportional to file risk; active content is removed or rejected where required. | Malformed parser input and sandbox/config assertion. |
| `UPL-DOWN-001` | Every download and presigned operation rechecks authorization and ownership; knowing an object key is insufficient. | Wrong-user and wrong-tenant download tests. |
| `UPL-SCAN-001` | Malware/CDR scanning is used where the product threat model requires it, and scanner error/timeout never becomes approval. | Scanner positive, error, and timeout path tests. |

Standards navigation: OWASP File Upload Cheat Sheet and relevant parser/sandbox vendor guidance selected by the project. Mappings are guidance only.
