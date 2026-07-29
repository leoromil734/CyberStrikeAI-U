# API Token 与认证

## 基线字段

记录 token 类型、签发者、主体、角色、tenant、audience、scope、签发/过期时间、撤销状态和绑定客户端。敏感 token 只保存脱敏特征。

## JWT

按服务端可观察结果逐项验证：

- 缺失、格式错误和过期 token 是否一致拒绝。
- alg/key 选择是否由服务端可信配置决定。
- `iss`、`aud`、`exp`、`nbf`、scope、tenant 与角色是否被实际校验。
- 撤销、密码重置、登出和用户禁用后旧 token 是否失效。
- `kid`、`jku`、`x5u` 等 key 定位字段是否受信任边界约束。

修改 token 后返回 500 或不同错误只形成线索；必须证明被接受并获得新增能力。

## OAuth/OIDC

控制变量包括 redirect URI、state/nonce、PKCE、code 使用次数、客户端绑定和 token audience。正证据必须说明错误主体如何获得或复用 code/token，而不是仅展示宽松重定向页面。

## API Key 与 Session

验证 key 的环境、IP、scope、租户和轮换边界；验证 session 固定、并发、注销和敏感操作重认证。已窃取有效凭据后的正常访问应归因于凭据泄露根因，不能重复计为认证绕过。

## 负结果

记录服务端实际拒绝点与错误一致性。单个 claim 被拒绝不能证明所有 token 校验均正确。