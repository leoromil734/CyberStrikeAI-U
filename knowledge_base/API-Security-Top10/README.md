# OWASP API Security Top 10 (2023) — Testing Notes

Source: [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)

Use as a **checklist** during API engagements. Each item needs evidence; inventory/docs gaps are often info/medium unless exploitable.

| ID | Risk | What to test | Positive evidence |
|----|------|--------------|-------------------|
| API1 | BOLA / object authz | Change object IDs across users | Peer data or unauthorized write |
| API2 | Broken authentication | Token handling, reset, MFA skip, JWT flaws | Session as victim / auth bypass |
| API3 | Object property authz | Mass assignment, excess fields in response | Read/write forbidden properties |
| API4 | Resource consumption | Heavy endpoints without rate limit | Cost/DoS proof (careful in prod) |
| API5 | Function level authz | Call admin routes as low-priv | Admin action succeeds |
| API6 | Business flow abuse | Book/buy/comment without anti-automation | Business harm via automation |
| API7 | SSRF | URL fetchers, webhooks | OOB or internal content |
| API8 | Misconfiguration | Verbose errors, CORS, open swagger, TRACE | Sensitive config/data exposure |
| API9 | Inventory | Shadow/deprecated APIs, debug hosts | Reachable undocumented sensitive API |
| API10 | Unsafe third-party APIs | Trust of upstream data | Inject via third party into core |

## Workflow

1. Inventory: OpenAPI/Swagger/GraphQL introspection, mobile/JS endpoints (`katana`, `gau`, `api-schema-analyzer`)  
2. **Only after controlled diagnosis confirms non-browser TLS blocking**: use **curl_cffi** (`impersonate=chrome`) for the affected requests — a CDN header or ordinary 403 is not sufficient; see `CDN-TLS-Fingerprint/` and skill `cdn-tls-fingerprint`
3. Auth matrix: anonymous / user / admin (same client Session)  
4. For each resource type: BOLA + property tests  
5. SSRF/JWT/injection as applicable  
6. Record only verified items; tentative for inventory-only; do not call edge blocks "missing API"  

## Tools (CyberStrikeAI)

`httpx`, `arjun`, `x8`, `jwt-analyzer`, `graphql-scanner`, `api-schema-analyzer`, `nuclei` (clues), `sqlmap`, `interactsh-client`。仅在 TLS 指纹已确认时按需使用 `install-python-package` + `execute-python-script`（**curl_cffi**）。

## Skill

See `api-security-testing` and `cdn-tls-fingerprint`.