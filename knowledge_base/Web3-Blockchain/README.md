# 区块链与智能合约攻击

> 智能合约的风险集中在四类：**重入与状态竞态**、**价格/预言机操纵**、**权限与升级缺陷**、**签名与授权缺陷**。链上交易不可回滚，因此验证必须在**测试网/分叉环境**完成。

## 一、重入与调用顺序

```solidity
function withdraw() external {
    uint256 bal = balances[msg.sender];
    (bool ok, ) = msg.sender.call{value: bal}("");   // 先转账
    require(ok);
    balances[msg.sender] = 0;                        // 后清账 → 可重入
}
```

- 变体：**只读重入（read-only reentrancy）**、跨函数重入、跨合约重入、ERC-777/ERC-1155 回调（`tokensReceived`）、`flash loan` 触发的回调重入。
- 检查点：外部调用（`call`/`transfer`/`safeTransferFrom`/`swap`）之后是否仍使用旧状态；是否遵循 checks-effects-interactions；是否有（且是否正确的）重入锁——注意跨函数/跨合约的锁可能不同。

## 二、价格与预言机操纵

- 现货池 `getReserves()` 作为价格源 → 闪电贷瞬时操纵。
- 单一 DEX 的 spot price、LP token 价格（`totalAssets/totalSupply`）、AMM 结算顺序。
- `TWAP` 窗口过短（可被跨块操纵）、`chainlink` 的 stale price/最小更新间隔未校验（`updatedAt`）。
- 组合：闪电贷 → 拉价格 → 触发清算/借贷超额度 → 归还。

## 三、权限与升级

| 问题 | 检查 |
|---|---|
| 未保护初始化 | `initialize()` 是否可被重复调用/抢先调用（proxy 模式） |
| `onlyOwner` 遗漏 | 敏感函数（`setFee`、`withdraw`、`upgradeTo`）是否缺修饰符 |
| `tx.origin` 认证 | 应使用 `msg.sender` |
| 升级函数 | `upgradeTo` 是否受保护、`UUPS` 的 `_authorizeUpgrade` 是否实现 |
| 自毁/委托调用 | `selfdestruct`、`delegatecall` 到可控地址 |
| 权限转移 | 所有权转移是否两阶段（避免转错地址导致锁死） |

## 四、签名与授权

- `ecrecover` 返回 `address(0)` 未检查 → 伪造签名通过。
- 未包含 `chainId`/合约地址/`nonce` → **跨链/跨合约重放**。
- `permit`（EIP-2612）的 `deadline`/`nonce` 校验缺失。
- `approve` + `transferFrom` 的无限授权被滥用（用户侧风险）。
- `delegatecall` 代理存储布局冲突 → 覆盖管理员槽位。

## 五、常见逻辑缺陷

- 精度与舍入：先除后乘、整数截断导致 `0` 金额或免费提款。
- 计息/份额计算：`share = amount * totalSupply / totalAssets` 的首次存款膨胀攻击（donation attack）。
- 数组遍历 DoS、无界循环、`delete` 大数组消耗 gas。
- 事件/返回值与实际状态不一致（前端信任问题）。
- ERC-20 不规范实现（不返回 bool、双花式转账）导致 `safeTransfer` 假设失效。

## 六、评估方法

1. **获取源码与字节码**：Etherscan/BscScan 验证源码；未验证时反编译（`heimdall`、`panoramix`）。
2. **静态分析**：`slither`、`mythril`、`semgrep` 规则；关注 `reentrancy`、`arbitrary-send`、`unprotected-upgrade`。
3. **分叉测试**：`foundry`（`forge test --fork-url`）在真实链状态下复现（可精确模拟预言机与闪电贷）。
4. **模糊测试**：`echidna`/`medusa` 做属性测试（不变量：总量守恒、权限不可提升）。
5. **链上取证**：检查历史交易、管理员地址、多签（Gnosis Safe）配置、时间锁（Timelock）。

## 七、验证（最小证据）

1. PoC 测试（Foundry 脚本/测试用例）在分叉环境可复现，且有明确的资金/状态变化断言。
2. 说明攻击前置条件（闪电贷额度、可用资金、区块状态）。
3. **不在主网执行**；不移动真实用户的资金。
4. 影响量化：可提取金额、受影响用户数、是否可重复。

## 八、常见误报

- 理论可重入但外部调用对象不可控（固定信任合约）。
- 预言机虽单一但有严格 TWAP 与上限，闪电贷无法在窗口内操纵。
- 权限函数由多签 + 时间锁保护（不可即时滥用）。
- 精度问题存在但影响为 0 或不可提取。

## 九、修复

- Checks-Effects-Interactions + 重入锁；跨合约场景使用"只读重入"保护（状态快照）。
- 预言机使用多源 + TWAP + 偏差与陈旧检查。
- 初始化用 `initializer` 修饰符 + 部署脚本原子化；升级路径加时间锁与多签。
- 签名中加入 `chainId`/合约地址/`nonce`/`deadline`；校验 `ecrecover != address(0)`。
- 使用经过审计的库（OpenZeppelin）；对 ERC-20 用 `SafeERC20`。
- 上线前审计 + 形式化验证（关键不变量）+ 漏洞赏金。

## 参考

- ConsenSys 智能合约最佳实践、SWC Registry（Smart Contract Weakness Classification）
- 工具：Slither、Mythril、Foundry、Echidna、Heimdall
- Skill：`blockchain-contract-attack`
