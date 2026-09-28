# 无线与硬件攻击面

> 无线/硬件评估的核心差异：**物理接近与合规**。多数技术只能在授权、且现场条件满足时使用；报告中要写清"信号覆盖范围"与"是否会影响他人"（如干扰属违法行为）。

## 一、无线（Wi-Fi）

### 侦察（被动优先）

```bash
# 监听模式 + 扫描
airmon-ng start wlan0
airodump-ng wlan0mon                 # ESSID/BSSID/信道/客户端/加密类型
wash -i wlan0mon                     # WPS 状态
```

关注：隐藏 SSID、企业认证（WPA2/3-Enterprise）、开放网络、WPS 开启、RADIUS 服务器标识。

### 授权内的验证方向

| 目标 | 方法 | 证据 |
|---|---|---|
| 弱 PSK | 抓 4-way handshake（`airodump-ng` + `aireplay-ng -0`）后离线爆破（hashcat 22000） | 握手文件 + 还原出的 PSK |
| WPS PIN | `reaver`/`bully`（仅在授权并且设备支持时） | 获取的 PSK 与 PIN |
| 企业认证 | 伪造 AP（`hostapd-mana`/`eaphammer`）诱导客户端连入 → 捕获 MSCHAPv2 挑战（可破解 NetNTLM） | 捕获的凭据 + 认证流程 |
| Evil Twin / 强制门户 | 克隆门户做凭据采集 | 提交记录（合规前提下） |
| 客户端隔离缺失 | 同网段横向（见 Post-Exploitation） | 从无线侧访问到其他客户端/内网资产 |
| WPA3 | 关注降级到 WPA2 的过渡模式、SAE 的 anti-clogging | 配置证据 |

**注意**：`aireplay-ng -0`（deauth）属于干扰，可能影响真实用户与关键设备（医疗、工业）；只有在客户明确允许且时间窗内执行。

### 蓝牙/BLE/Zigbee/RFID

- **BLE**：用 `bluetoothctl`/`nRF Connect`/`gatttool`/`Bettercap` 枚举 GATT 服务与特征；查找可写特征、未配对可读数据、硬编码 PIN、固件更新特征（未签名 = OTA 提权）。
- **经典蓝牙**：配对流程（Just Works 无 MITM 保护）、OBEX 文件传输、SPP 串口。
- **Zigbee/802.15.4**：需要专用硬件（`Killerbee`/`ApiMote`）；关注网络密钥硬编码、重放攻击、无重放保护。
- **RFID/NFC**：低频门禁卡（UID 可克隆）、高频卡（MIFARE Classic 的 Crypto1 已被攻破）、NFC 中继（支付场景；Android HCE 玩法见 HackTricks 2025）。
- **Sub-GHz**（433/868MHz）：遥控器重放（固定码）、滚动码分析。

## 二、硬件与固件

| 面 | 方法 | 关注点 |
|---|---|---|
| 物理接口 | UART/JTAG/SWD、SPI/I2C、USB | 找调试串口 → shell 或引导加载器；`boundary scan` |
| Flash 提取 | SPI 夹/编程器读固件 | 明文凭据、私钥、默认口令、未签名固件 |
| 固件分析 | `binwalk -Me`、`firmware-mod-kit`、`EMBA` | 文件系统、初始化脚本、硬编码密钥、CVE 组件 |
| 引导链 | 安全启动是否启用 | 签名校验缺失 → 刷入自定义固件 |
| 更新机制 | OTA 签名校验 | 未签名/降级攻击（见 Mobile 的自动更新章节） |
| 侧信道 | 功耗/电磁/时序 | 需专业设备，通常超出常规评估 |
| 硬件供应链 | 芯片型号/参考设计 | 使用同一 SDK 的设备共享漏洞 |

## 三、验证（最小证据）

1. 目标标识：BSSID/SSID、设备型号、固件版本、序列号。
2. 操作记录：使用的命令与硬件、时间与位置、信号范围。
3. 影响证据：获得的 PSK/凭据（掩码）、从无线侧访问到的内网资产、提取的固件内容片段。
4. 合规声明：不干扰他人网络、不影响关键设备；如需 deauth/JTAG 现场操作，事前取得书面许可。
5. 交付后处理：销毁抓取的握手与凭据，说明设备是否需要恢复出厂。

## 四、常见误报

- 抓到的握手来自测试设备自身（自建 AP）。
- 企业认证"捕获到挑战"但客户端实际拒绝了伪造证书（未泄露凭据）。
- WPS 开启但被锁定/限速（实际不可爆破）。
- UART 引脚可定位但无输出（未启用或需要特定触点组合）。
- 固件中的"密钥"是占位/公钥。

## 五、修复

- **无线**：禁用 WPS；WPA3（或 WPA2-Enterprise + 证书校验）；企业环境强制客户端校验 RADIUS 证书（防 Evil Twin）；开启管理帧保护（PMF/802.11w）；关闭客户端隔离以外的隐患（分段、访客网隔离）。
- **BLE/物联网**：配对使用 LE Secure Connections、敏感特征需认证写入、固件更新签名验证、轮换密钥。
- **硬件**：关闭调试接口（熔断 eFuse）、启用安全启动、固件签名与加密、密钥存于安全元件（TPM/ATECC/SE）。
- **运营**：无线作为不可信网络对待（零信任），不因"进了 Wi-Fi"就获得内网访问。

## 六、参考

- HackTricks：Radio Hacking / Hardware、BLE、NFC 相关章节
- 工具：aircrack-ng 套件、eaphammer、Bettercap、`bluetoothctl`/`nRF Connect`、binwalk、EMBA、ChipWhisperer
- Skill：`wireless-hardware-attack`
