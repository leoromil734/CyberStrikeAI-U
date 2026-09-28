# SAML 认证绕过（XSW 与 Void Canonicalization）

> SAML 的安全性完全取决于"签名校验"与"断言解析"是否看到**同一份 XML**。2025 年的《The Fragile Lock》把这条缝推到了极致：利用解析器差异 + 规范化失败，构造出**永久有效的 Golden SAML Response**。

## 基础：XSW（XML Signature Wrapping）

```text
合法响应（含 IdP 签名）
  └─ 攻击者插入一份伪造 Assertion（admin 身份）
     校验器验签 & 处理器的取值对象不是同一节点
```

经典变体：把签名包在外层、把伪造 Assertion 放到处理器会读取的位置（前置/后置/Extensions/StatusDetail）。

## 2025 新手法（Ruby-SAML / php-saml / xmlseclibs）

前提：库同时使用 **两个解析器**（如 REXML + Nokogiri），且 XPath 查询过于宽松（`//ds:Signature` 取第一个签名）。

### 1. 属性污染（Attribute Pollution）

libxml2 的 `xmlGetProp` **忽略命名空间**，只按简单名匹配；同名属性（`ID` 与 `samlp:ID`）谁被返回**取决于属性顺序**。Nokogiri 的 `node['ID']`、PHP 的 `DOMNamedNodeMap::getNamedItem('ID')` 同样只按简单名。REXML 在带前缀时选择顺序相反 → 两个解析器对"哪个元素被签名"得出不同结论。

```xml
<samlp:Response ID="attack" samlp:ID="ID">
  <Signature>
    <Reference URI="#ID"/>
  </Signature>
  <samlp:Extensions>
    <Assertion ID="#ID"/>
  </samlp:Extensions>
  <Assertion ID="evil"/>
</samlp:Response>
```

### 2. 保留前缀的命名空间混淆（无需 DTD）

REXML 把 `xmlns`/`xml` 当普通属性处理，因此可注入非法但被容忍的声明，让**签名节点对一个解析器可见、对另一个不可见**：

```xml
<Signature xml:xmlns='http://www.w3.org/2000/09/xmldsig#'/>
```

```xml
<Parent xmlns='http://www.w3.org/2000/09/xmldsig#'>
  <Child xml:xmlns='#anything'>
    <Signature/>     <!-- Nokogiri 可见，REXML 的 //ds:Signature 查不到 -->
  </Child>
</Parent>
```

### 3. Void Canonicalization（新攻击类）

规范化（canonicalization）遇到限制（如**相对 URI 命名空间** `xmlns:ns="1"`）时应报错；但 Nokogiri 的实现静默返回**空串**，于是 DigestValue 变成了"空串的哈希"：

```text
SHA-256("") = 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
```

攻击者只需一个"空串的合法签名"即可构造对**任意断言**都通过校验的消息 → Golden SAML Response。

### 4. 签名素材从哪来

- IdP 元数据（尝试 `?sign=true` 取签名版本）。
- **签名的错误响应**：构造非法 `AuthnRequest`（如 `ID="&#x80;"`、`IssueInstant="INVALID"`），IdP 按规范仍可能返回签名错误响应；若响应内回显内容触发规范化错误，即得到 void 签名。
- WS-Federation 元数据（多数大厂 IdP 公开可用）。

### 5. 覆盖版本

- ruby-saml ≤ 1.18.0（CVE-2025-66567 / CVE-2025-66568），含曾被认为已修复的 1.12.4。
- php-saml、xmlseclibs ≤ 3.1.3（3.1.4 修复）。
- 不受影响：XMLSec 库、Shibboleth xmlsectool。

## 其他常见 SAML 绕过点

- 注释截断：`admin@evil.com<!---->.corp.com` 在不同解析器下域名判定不同。
- 属性值大小写/空白、`NameID` 格式混淆（`emailAddress` vs `persistent`）。
- 断言重放：无 `InResponseTo`、无 `NotOnOrAfter` 校验。
- 未校验 `Audience` / `Recipient`，可跨 SP 重放。
- Metadata 注入与 SP 端 XML 解析器 XXE（见 `../XXE/README.md`）。

## 验证（最小证据）

1. 完整的 SAMLResponse（Base64）与目标端点请求原文。
2. 签名**未被重新计算**（证明利用了校验逻辑缺陷，而非拿到 IdP 私钥）。
3. 登录后以目标身份访问受保护资源成功的响应。
4. 标注受影响库与版本；无法确认版本时标记 `library_version_unknown`。

## 常见误报

- 仅"未签名断言被接受"但 SP 强制要求签名 → 不是绕过。
- 测试环境关闭了签名校验。
- 断言被接受但用户在 SP 侧不存在（仍拒绝登录）→ 影响力需降级。

## 修复

- 只用**签名覆盖的节点**做后续处理（先验签，再从已验签节点取值，避免二次解析）。
- 单一 XML 解析器（链路统一 libxml2 或统一纯实现），禁用 DTD/实体。
- 显式校验 `Destination`/`Audience`/`Recipient`/`InResponseTo`/`NotOnOrAfter`；断言一次性。
- 不对规范化失败做"静默降级"：任何规范化错误 → 拒绝（fail closed）。
- 及时升级 ruby-saml ≥ 1.18.0、xmlseclibs ≥ 3.1.4。

## 参考

- PortSwigger：The Fragile Lock: Novel Bypasses For SAML Authentication（2025-12）
- PortSwigger：SAMLRoulette / Splitting the Email Atom
- CVE-2025-66567、CVE-2025-66568、CVE-2025-25292、CVE-2025-23369
- 工具：SAML Raider、d0ge/XSW（Burp 扩展）
