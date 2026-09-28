# 竞态条件（Race Condition）

> 竞态 = "检查与使用之间存在时间窗"。现代网络条件下，**单包技术**让远程竞态从"撞运气"变成"稳定可利用"。

## 一、类型

| 类型 | 说明 | 例子 |
|---|---|---|
| 限次突破（limit overrun） | 并发绕过"一次性/限次"逻辑 | 优惠券多次使用、OTP 多次验证、余额重复扣减 |
| 隐藏状态多视 | 同时暴露中间态 | 部分完成的订单可被改价、部分注册的用户可复用邮箱 |
| TOCTOU | 校验与操作分离 | 上传后改名、权限校验与写操作之间窗口 |
| 单端点多次 | 同一端点并行调用 | 抽奖、投票、点赞、邀请奖励 |
| 多端点编排 | 不同步骤并行 | 支付/退款/发货状态机混乱 |
| 方法级并行 | 不同 HTTP 方法对同一资源 | PUT + DELETE、POST + PATCH |

## 二、技术手法

### 1. 单包攻击（single-packet attack）

把多个请求放在**同一个 TCP 包**（HTTP/1.1 最后一个字节对齐）或**同一 HTTP/2 连接的多条流**中，消除网络抖动，使并发窗口从 ±10ms 降到 ±1ms。

- H1：用 `Turbo Intruder` 的 `single-packet` 模式，先发送所有请求（除最后一个字节），再一次性发送最后一字节。
- H2：所有流同时发 `HEADERS`，最后统一放行 `END_STREAM`。
- 需要精确控制编码层（Python 原始 socket、`h2` 库；或 Turbo Intruder）。

### 2. 连接预热与丢包对齐

- 保持连接热（keep-alive）、消除首包 RTT。
- 多连接同时发（并发数 ≈ 目标吞吐），必要时重试多轮。

### 3. HTTP/3 / QUIC

- **Quic-Fin-Sync（2025）**：在多个 QUIC 流上缓冲请求，用协调的 FIN 突发同时释放 → 把单包技术移植到 H3。

### 4. HTTP/2 流控制与 RST 滥用

- 2025 的 MadeYouReset 思路：利用流级协议错误触发服务端 RST_STREAM，绕过 `MAX_CONCURRENT_STREAMS`，驱动大量并发工作（可用于放大"限次突破"类竞态）。

## 三、验证（最小证据）

1. **基线**：串行请求 2 次 → 第二次被拒绝（如"已使用"）。
2. **并发**：单包/并行发出 N 次 → 出现多于 1 次成功（给出每次响应）。
3. 统计证据：多轮重复（如 5~10 轮）成功率的稳定性，避免单次巧合。
4. 影响证据：业务层面的实际收益（如余额变化、重复发放）、或状态不一致。
5. 记录时序参数（并发数、连接数、是否单包），便于复现。

## 四、常见误报

- 仅因客户端重试导致的服务端重复处理（幂等问题，需区分"竞态"与"无幂等键"）。
- 串行也能成功（不是竞态，是逻辑缺失）。
- 单次成功但无法重复（偶发，需更多轮次）。
- 前端乐观 UI 显示成功，服务端实际拒绝。

## 五、修复

- 服务端原子操作：数据库唯一约束、行锁、乐观锁（version）替代"先查后写"。
- 幂等键（idempotency key）绑定请求业务语义。
- 一次性资源（优惠券/OTP）用 `UPDATE ... WHERE used=false` 的原子判定，靠影响行数决定成败。
- 关键状态机用显式状态与转换校验（不允许从任意状态跳到终态）。
- 限流与排队（token bucket / 信号量），减少可并发的窗口。

## 六、工具

- Burp Turbo Intruder（`race-single-packet-attack.py`）、`execute-python-script` + 原始 socket / `h2` 库、`ffuf`（低精度辅助）。
- CyberArk：`Racing and Fuzzing HTTP/3: QuicDraw`（2025）。

## 参考

- PortSwigger：The Single-Packet Attack（2023）、Race Conditions（Web Security Academy）
- CyberArk：QuicDraw / Quic-Fin-Sync（2025）
- Gal Bar Nahum：MadeYouReset（2025）
