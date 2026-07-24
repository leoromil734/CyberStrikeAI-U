# JWT Security Testing Notes

## Common issues

* `alg: none` accepted  
* RS256 → HS256 key confusion  
* Weak HMAC secret  
* `kid` injection / jku path to attacker key  
* Missing exp / long-lived tokens / no server-side revoke  

## Verification

1. Capture real token  
2. Mutate with `jwt_tool` / jwt-analyzer  
3. Replay to API; prove privileged access or auth bypass  
4. Document header/payload before/after  

Tool: CyberStrikeAI `jwt-analyzer` (command `jwt_tool`).  

Negative: server rejects modified tokens consistently.  

## References

* [jwt.io libraries](https://jwt.io)  
* PortSwigger JWT attacks  
* OWASP API2 Broken Authentication