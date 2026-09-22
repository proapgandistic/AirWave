# WiFi 测试工具

一个带 Web UI 的自动化 WiFi WPA2 测试工具。Kali 树莓派负责扫描和抓包，Windows 负责 Hashcat GPU 破解，全程在浏览器里点几下完成。支持双频扫描、实时刷新、客户端厂商识别、资产归档、历史扫描加载、户外 AP 热点直连等功能。

## 架构

```
┌──────────────────────────────────────────┐
│  浏览器（手机/电脑/平板）                  │
│  局域网: http://<kali-ip>:8000           │
│  户外:   http://100.100.100.1:8000 (AP直连)│
└──────────────────┬───────────────────────┘
                   │ HTTP
┌──────────────────▼───────────────────────┐
│  Kali 树莓派（主控端）                     │
│  ┌────────────────────────────────────┐  │
│  │  FastAPI Web 服务 (0.0.0.0:8000)  │  │
│  │  ├─ 扫描引擎 (airodump-ng 双频)    │  │
│  │  ├─ 攻击引擎 (aireplay-ng deauth)  │  │
│  │  ├─ 哈希转换 (hcxpcapngtool)       │  │
│  │  ├─ SSH 客户端 (调用 Windows Hashcat)│ │
│  │  ├─ OUI 厂商识别 (nmap数据库)      │  │
│  │  ├─ 资产归档 (.cap/.hc22000)       │  │
│  │  ├─ 历史扫描保存/加载               │  │
│  │  └─ 已知 WiFi 存储 (JSON)          │  │
│  └────────────────────────────────────┘  │
│  wlan0: AP 热点模式（户外手机直连）       │
│  wlan1mon: monitor 抓包（MT7612U）      │
└──────────────────┬───────────────────────┘
                   │ SSH (scp 传哈希 + 远程执行)
┌──────────────────▼───────────────────────┐
│  Windows（计算节点）                       │
│  ├─ OpenSSH Server (:22)                  │
│  └─ Hashcat 6.2.6 (NVIDIA GPU)           │
└──────────────────────────────────────────┘
```

## 功能一览

### 扫描
- **双频扫描**：同时扫描 2.4G + 5G（`--band ab`），ESSID 后自动标注 2.4G/5G 标签
- **持续扫描**：默认持续运行不自动停止，跟 airodump-ng 一样实时刷新，手动停止
- **实时刷新**：扫描过程中每 N 秒（可配置，默认 2 秒）更新 AP 列表、信号强度、用户数
- **列表排序**：点击表头按信号/ESSID/频道/用户数排序，支持升/降序切换
- **客户端详情**：每个 AP 显示关联用户数，点击行展开客户端 MAC、厂商、信号、数据包
- **厂商识别**：基于 nmap OUI 数据库（52000+ 条）自动识别客户端厂商，标注随机 MAC
- **历史扫描**：扫描结果自动保存（带开始/结束时间戳、真实持续时长），可随时加载历史结果无需重扫

### 资产
- **自动归档**：攻击抓到握手包后，`.cap` 和 `.hc22000` 自动归档到资产目录
- **直接破解**：资产列表中 `.hc22000` 文件可直接点「破解」，跳过抓包流程
- **下载/删除**：资产文件可下载到本地手动跑 Hashcat，或删除不需要的

### 攻击
- **一键攻击**：选择目标 AP，自动完成扫描客户端 → deauth → 抓握手 → 转换哈希 → 上传 Windows → Hashcat 破解
- **实时日志**：攻击过程每一步实时显示在 Web UI
- **前台 Hashcat**：直接前台运行 Hashcat（Windows SSH 后台进程会立刻退出，必须前台），8 位纯数字约 20 秒出结果
- **自动保存**：破解成功自动保存到「已知 WiFi」库

### 配置
- **计算节点配置**：Windows IP、端口、用户名、**密码**（支持密码认证，不只是免密）
- **测试连接**：一键测试 6 项（配置检查、SSH 连接、系统信息、NVIDIA GPU、Hashcat 文件、Hashcat 可运行）
- **攻击参数**：扫描时长、deauth 轮数/帧数/等待时间、Hashcat 掩码
- **扫描参数**：实时刷新间隔（1-10 秒）、持续扫描开关

### 户外模式
- **AP 热点**：wlan0 开热点（SSID: Redteam_wifi），手机直接连，无需路由器
- **桌面快捷方式**：双击桌面图标启动，显示连接信息
- **自动恢复**：关闭终端窗口自动停止热点、恢复有线模式
- **Web UI 访问**：手机连热点后浏览器打开 `http://100.100.100.1:8000`

## 访问方式

| 场景 | 访问地址 |
|---|---|
| Kali 本地桌面 | `http://127.0.0.1:8000` |
| 局域网其他设备 | `http://<Kali-IP>:8000`（例如 `http://192.168.31.74:8000`） |
| 户外（AP 直连） | 手机连 `Redteam_wifi` → `http://100.100.100.1:8000` |
| 公网访问 | 路由器端口映射 → `http://<公网IP>:8000`（建议配合 VPN） |

## Kali 端部署

### 前置要求

- Kali Linux（树莓派或其他设备）
- 支持 monitor mode 的 USB WiFi 网卡（MT7612U 推荐，已配置为 `wlan1mon`）
- Python 3.8+
- hostapd + dnsmasq（户外 AP 模式需要，`sudo apt install hostapd dnsmasq`）

### 安装步骤

```bash
# 1. 复制 wifi_tool 目录到 Kali（或 git clone）
cd ~/wifi_tool

# 2. 安装依赖
pip3 install --break-system-packages -r requirements.txt

# 3. 确认 wlan1mon 接口存在
iw dev
# 应该看到 Interface wlan1mon, type monitor

# 4. 启动
chmod +x run.sh
./run.sh
```

### 后台运行（推荐）

```bash
cd ~/wifi_tool
nohup python3 main.py > /tmp/wifi_tool.log 2>&1 &

# 查看日志
tail -f /tmp/wifi_tool.log

# 停止（zsh 下 pkill 可能报错，用 lsof）
sudo lsof -t -i :8000 | xargs sudo kill -9
```

### 开机自启（可选）

```bash
sudo tee /etc/systemd/system/wifi-tool.service << 'EOF'
[Unit]
Description=WiFi Testing Tool
After=network.target

[Service]
User=kali
WorkingDirectory=/home/kali/wifi_tool
ExecStart=/usr/bin/python3 main.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now wifi-tool
```

## Windows 端配置

### 一键配置（推荐）

1. 把 `setup_windows.ps1` 复制到 Windows
2. **右键 → 以管理员身份运行 PowerShell**，然后执行：
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\setup_windows.ps1
   ```
3. 脚本自动完成：安装 OpenSSH Server、启动服务、配置 PowerShell 默认 shell、防火墙放行

### 配置 SSH（免密或密码）

**免密方式**（在 Kali 上执行）：
```bash
ssh-keygen -t rsa -b 4096
scp ~/.ssh/id_rsa.pub <windows-user>@<windows-ip>:"C:/Users/<windows-user>/.ssh/authorized_keys"
ssh <windows-user>@<windows-ip> whoami
```

**密码方式**：直接在 Web UI「配置」页面填写 Windows 密码，工具自动用 `sshpass` 认证。

### 安装 Hashcat

1. 从 https://hashcat.net/files/hashcat-6.2.6.7z 下载
2. 解压到工作目录，例如 `C:\Users\<user>\Desktop\wifi_windows_test\hashcat-6.2.6\`
3. 确认 `hashcat.exe` 存在
4. 确认 NVIDIA 驱动已安装（`nvidia-smi` 能看到 GPU）

> **注意**：所有 Hashcat 相关数据（哈希、输出、日志）必须放在 `wifi_windows_test` 目录，不要放 Temp。

## 使用流程

### 1. 配置 Windows 计算节点

打开 Web UI → 「配置」页面 → 填写：
- Windows IP / 端口 / 用户名 / 密码
- Hashcat 路径（例如 `C:\Users\7950x\Desktop\software i like\wifi_windows_test\hashcat-6.2.6\hashcat.exe`）
- 扫描时长、实时刷新间隔、持续扫描开关
- deauth 轮数/帧数/等待时间
- Hashcat 掩码（默认 `?d?d?d?d?d?d?d?d` 8 位纯数字）

点「保存配置」→ 点「测试连接」确认 6 项全部通过。

### 2. 扫描

→ 「扫描」页面 → 点击「开始持续扫描」

扫描过程中：
- AP 逐个出现，信号强度和用户数实时刷新
- ESSID 后标注 2.4G/5G 标签
- 点击表头排序（信号/名称/频道/用户数）
- 点击 AP 行展开客户端详情（MAC、厂商、信号、数据包、随机 MAC 标注）
- 点「历史扫描」可加载之前保存的扫描结果
- 点「停止扫描」结束，结果自动保存

### 3. 攻击

方式一（从扫描结果）：在 AP 列表点目标的「攻击」按钮 → 跳转到「攻击」页面 → 点「开始攻击」

方式二（从资产文件）：「资产」页面 → 对 `.hc22000` 文件点「破解」→ 直接跳过抓包，上传 Windows 跑 Hashcat

攻击过程：
1. 扫描目标频道，寻找关联客户端
2. 启动抓包
3. 多轮 deauth（踢客户端下线）
4. 等待客户端重连，抓 EAPOL 握手
5. 转换为 hc22000 格式
6. 自动归档到资产目录
7. 上传到 Windows，前台运行 Hashcat（GPU 加速）
8. 解析结果，成功后自动保存到「已知 WiFi」

### 4. 查看结果

→ 「已知 WiFi」页面 → 查看所有已破解的 WiFi 名称、密码、BSSID、频道、破解时间

→ 「资产」页面 → 查看所有捕获的 `.cap` 和 `.hc22000` 文件，可下载、删除、直接破解

### 5. 户外使用（无路由器）

1. Kali 桌面双击「开启WiFi热点模式」图标
2. 终端显示 SSID `Redteam_wifi`、密码 `88668888`、管理 IP `100.100.100.1`
3. 手机连 `Redteam_wifi`
4. 手机浏览器打开 `http://100.100.100.1:8000`
5. 用完关闭终端窗口 → 自动停止热点、恢复有线模式

## 攻击参数说明

| 参数 | 默认值 | 说明 |
|---|---|---|
| 扫描时长 | 20 秒 | 定时扫描模式的持续时间（持续扫描模式下忽略） |
| 实时刷新间隔 | 2 秒 | 扫描过程中多久刷新一次 AP 列表（1-10 秒） |
| 持续扫描 | 开启 | 开启后扫描不自动停止，手动停止（推荐） |
| Deauth 轮数 | 3 | 对客户端做几轮 deauth |
| 每轮 Deauth 帧数 | 10 | 每轮发送多少个 deauth 帧（不宜过多） |
| 每轮等待时间 | 18 秒 | 每轮 deauth 后等多久让客户端重连 |
| Hashcat 掩码 | `?d?d?d?d?d?d?d?d` | 8 位纯数字，可改为其他掩码 |

**调参建议**：
- 客户端信号弱（< -70dBm）：增加 deauth 轮数到 5，增加等待时间到 25 秒
- 客户端不重连：减少每轮帧数（5-10），过多 deauth 会导致 AP 重置 EAPOL 定时器
- 密码复杂：修改掩码为更长或包含字母，例如 `?d?d?d?d?d?d?d?d?d?d`（10 位数字）
- 5G 目标：确认网卡支持 5G monitor 模式，扫描时会自动覆盖 5G 频道

## Hashcat 掩码速查

| 掩码 | 含义 |
|---|---|
| `?l` | 小写字母 a-z |
| `?u` | 大写字母 A-Z |
| `?d` | 数字 0-9 |
| `?s` | 特殊字符 |
| `?a` | 全部（?l?u?d?s） |
| `?d?d?d?d?d?d?d?d` | 8 位纯数字（1 亿组合，RTX 5070 Ti 约 20 秒） |
| `?d?d?d?d?d?d?d?d?d?d` | 10 位纯数字（100 亿组合，约 30 分钟） |

## 文件结构

```
wifi_tool/
├── main.py              # 主程序（FastAPI + 内嵌 Web UI）
├── requirements.txt     # Python 依赖
├── run.sh               # Kali 启动脚本
├── setup_windows.ps1    # Windows 一键配置脚本
├── config.json          # 运行时配置（Windows 节点、掩码等）
├── known_wifi.json      # 已破解 WiFi 列表
├── assets/              # 资产目录（.cap 抓包文件 + .hc22000 哈希文件）
├── scans/               # 历史扫描记录（scan_时间戳.json）
└── README.md            # 本文件
```

户外 AP 模式相关文件：
```
/home/kali/wifi-ap.sh       # AP 模式启动脚本（带 trap 自动恢复）
/home/kali/Desktop/wifi-ap.desktop  # 桌面快捷方式
/etc/hostapd-ap.conf        # hostapd 配置（SSID/密码/频道）
/etc/dnsmasq-ap.conf        # dnsmasq 配置（DHCP 网段）
```

## 踩坑记录与已知问题

### 网卡与驱动
- **hcxdumptool 7.x 与 mt76x2u 不兼容**：会报 `failed to arm interface`，降级到 hcxdumptool 6.3.5 可用。抓包推荐用 airodump-ng + aireplay-ng 路线。
- **MT7612U 支持双频**：2.4G + 5G 都支持 monitor 模式，5G 可用频道 36/40/44/48/52/56/60/64/149/153/157/161/165。
- **必须删除 wlan1 只留 wlan1mon**：monitor 模式下接口名是 `wlan1mon`，如果 `wlan1` 还存在会冲突。

### Windows Hashcat
- **Start-Process 后台运行会立刻退出**：Windows OpenSSH 非交互式会话中，用 `Start-Process` 启动的后台进程会在输出 `starting` 后立刻消失。必须**前台直接运行 hashcat**，SSH 连接等待完成后从 stdout 解析结果。
- **SCP 路径不能有空格问题**：上传哈希到 hashcat 目录下，用相对路径（`.\wifi_attack_hash.hc22000`）执行，避免路径空格导致失败。
- **Linux 解析 Windows 路径**：`os.path.dirname()` 在 Linux 上不认 Windows 反斜杠 `\`，需要先 `replace("\\","/")` 再 `rsplit("/",1)`。
- **所有数据放工作目录**：哈希、输出、日志全部放在 `wifi_windows_test` 目录，绝对不要放 `C:\Windows\Temp\`。

### 前端开发
- **Python 字符串替换要匹配实际内容**：多次替换失败是因为 old_string 用了"以为已经替换过"的新版本内容，而实际文件还是旧版。替换前必须 Read 确认实际内容。
- **JS 单引号转义**：在 Python 字符串中写 JS 代码时，HTML 属性里的单引号（如 `onclick="func('arg')"`）必须转义为 `\'`，否则会导致 JS 字符串提前终止，整个 script 块解析失败，所有按钮失效。
- **DOMContentLoaded 时机**：script 在 HTML 底部时，`DOMContentLoaded` 事件可能已经触发过了，事件监听器不会执行。直接调用函数更可靠。

## 常见问题

**Q: 扫描后 AP 列表为空？**
A: 确认 `wlan1mon` 接口存在且为 monitor mode：`iw dev`。如果没有，执行 `sudo airmon-ng start wlan1`。确认网卡天线已接好。

**Q: 用户数一直是 0？**
A: 实时刷新时读取的是 airodump-ng 正在写入的 CSV，可能不完整。工具已修复为先复制再解析。如果持续为 0，确认目标 AP 确实有客户端连接（可以用手机连一下测试）。

**Q: 攻击总是失败，提示"未抓到有效握手"？**
A: 可能原因：(1) 目标 AP 没有客户端连接；(2) 客户端信号太弱，deauth 收不到；(3) deauth 帧数过多导致 AP 异常。建议增加轮数、减少每轮帧数、确认客户端在线。PMKID 路线对多数现代 AP 不适用，推荐 deauth + EAPOL 握手路线。

**Q: Hashcat 破解阶段卡住或超时？**
A: 检查 Windows SSH 连接是否正常，Hashcat 路径是否正确。可以在 Kali 上手动测试：`ssh <user>@<windows-ip> "cd <hashcat_dir> && .\hashcat.exe --version"`。确认不是用 Start-Process 后台运行（会立刻退出）。

**Q: 公网访问不安全怎么办？**
A: 建议 (1) 路由器映射时改用非标准端口（如 8888）；(2) 配合 VPN 使用（WireGuard/ZeroTier）；(3) 不要在不可信网络下明文传输（可后续加 HTTPS）。

**Q: 户外 AP 模式双击图标没反应？**
A: XFCE 桌面需要右键图标 → 属性 → 权限 → 勾选「允许作为程序执行」。或者直接在终端运行 `~/wifi-ap.sh`。

**Q: 关掉 AP 模式窗口后 WiFi 还在？**
A: 脚本用了 `trap cleanup EXIT`，正常关闭窗口会触发清理。如果异常退出（比如强制杀进程），可以手动运行 `sudo killall hostapd dnsmasq && sudo ip link set wlan0 down` 恢复。

## 免责声明

本工具仅供学习研究和授权网络安全测试使用。未经授权破解他人 WiFi 网络属于违法行为。请仅在自己拥有或已获得书面授权的网络上进行测试。使用者需自行承担使用本工具产生的一切法律责任。
