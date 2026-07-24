# IDOR / BOLA (Broken Object Level Authorization)

> Insecure Direct Object Reference / BOLA: accessing objects by ID without proving the caller is allowed. Often the highest ROI API finding.

## Summary

* OWASP API1:2023 Broken Object Level Authorization  
* Horizontal: user A reads user B resource  
* Vertical: user accesses admin-only object  
* Related: BFLA (function level), property-level authz (API3)

## Testing method

1. Map object IDs (numeric, UUID, sequential) from own account  
2. Replay request as other role / other user token; change only object ID  
3. Observe **data of peer** or successful mutation  
4. Batch/export endpoints and GraphQL node IDs often weaker  

## Verification (min evidence)

1. Two identities (or anonymous vs auth)  
2. Same endpoint, different object ID  
3. Response proves unauthorized data or action  
4. No CSRF-only confusion: must be authorization failure  

Negative: consistent 403/404 with no body leak; server-side ownership checks.

## Tools mapping

* Manual + `execute-python-script` / httpx  
* `api-schema-analyzer`, `graphql-scanner`, `arjun` for surface  
* Not well covered by generic nuclei alone  

## References

* [OWASP API1:2023 BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)  
* [WSTG API BOLA](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/02-API_Broken_Object_Level_Authorization)