# Server-Side Request Forgery (SSRF)

> SSRF forces the server to request attacker-controlled or internal resources. High impact on cloud metadata, internal admin, and network pivots.

## Summary

* Classic: URL parameter, webhook, import-from-URL, PDF/preview fetchers  
* Blind SSRF: only timing or OOB (DNS/HTTP to Interactsh)  
* OWASP API7:2023 aligns with API-side SSRF  

## Detection

* Inject external Interactsh/DNS callback URL; observe DNS/HTTP interaction  
* Compare responses for internal IPs vs public  
* Redirect chains, DNS rebinding, alternate IP encodings (decimal, IPv6, DNS to 127.0.0.1)

## Verification (min evidence)

1. Controlled input that becomes server-side request  
2. Proof: OOB hit **or** internal content/metadata snippet **or** clear differential error  
3. Impact: which network zone / data obtained  

Negative: egress allowlist blocks all non-approved hosts; no DNS side channel.

## High-value targets (authorized only)

* Cloud metadata (IMDSv1 style endpoints — note IMDSv2 needs tokens)  
* Internal HTTP admin, redis/gopher schemes where applicable  
* File handlers (`file://`) if scheme allowed  

## Tools mapping

* `interactsh-client`, `dnslog`, manual `httpx`/curl via exec  
* nuclei SSRF templates = **线索 only**  

## References

* [OWASP SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)  
* [PortSwigger SSRF](https://portswigger.net/web-security/ssrf)  
* API Security Top 10 API7:2023