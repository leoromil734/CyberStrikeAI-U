# Cross-Site Scripting (XSS)

> Cross-Site Scripting allows injecting client-side scripts into pages viewed by other users. Impact ranges from session theft and account takeover to wormable stored XSS in admin panels.

## Summary

* Types: Reflected / Stored / DOM-based / Blind
* Tools: [dalfox](https://github.com/hahwul/dalfox), browser DevTools, manual probes
* Always verify **execution context** (HTML body, attribute, JS string, URL, template)
* Scanner hit ≠ vulnerability — need proof of script execution or privileged action

## Entry Point Detection

* Reflect probes: `"><svg/onload=alert(1)>`, `'"><img src=x onerror=alert(1)>`
* Context checks: view-source / DOM breakpoint / CSP headers
* Blind: dalfox `--blind` or Interactsh/Burp Collaborator URL in stored fields

## Verification (min evidence)

1. **Payload** and exact parameter/path  
2. **Response or DOM** showing sink reached unescaped (or successful callback)  
3. **Impact**: cookie/localStorage read, action as victim, admin panel stored XSS chain  
4. CSP/HttpOnly may reduce severity — document residual impact  

Negative: full encoding, strict CSP with no bypass, sanitize removes all handlers.

## Common bypasses (high level)

* Event handlers / SVG / math / template literals  
* Encoding: HTML entities, URL, unicode, double encode  
* Framework sinks: `v-html`, `dangerouslySetInnerHTML`, `innerHTML`  
* Stored via secondary channel (WebSocket, chat, markdown)

## Tools mapping (CyberStrikeAI)

* Primary: `dalfox`  
* Crawl params: `katana`, `arjun`, `paramspider`  
* OOB blind: `interactsh-client` / `dnslog`  
* Do not `record_vulnerability` on nuclei xss templates alone  

## References

* [OWASP XSS](https://owasp.org/www-community/attacks/xss/)  
* [PortSwigger XSS](https://portswigger.net/web-security/cross-site-scripting)  
* PayloadsAllTheThings XSS