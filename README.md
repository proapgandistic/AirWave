<div align="center">
  <img src="logo.png" alt="AirWave Logo" width="180" height="180">
  <h1>AirWave</h1>
  <p><strong>WiFi WPA2 安全测试自动化工具</strong></p>
  <p>
    <a href="https://github.com/proapgandistic/AirWave/releases">
      <img src="https://img.shields.io/badge/release-v0.2.1-blue.svg" alt="Release">
    </a>
    <a href="https://github.com/proapgandistic/AirWave/blob/master/LICENSE">
      <img src="https://img.shields.io/badge/license-GPLv3-green.svg" alt="License">
    </a>
    <img src="https://img.shields.io/badge/python-3.9+-yellow.svg" alt="Python">
    <img src="https://img.shields.io/badge/raspberry--pi-4B-red.svg" alt="Raspberry Pi">
    <img src="https://img.shields.io/badge/MT7612U-dual--band-orange.svg" alt="MT7612U">
    <img src="https://img.shields.io/badge/windows-GPU%20node-lightblue.svg" alt="Windows GPU">
  </p>
  <p>
    <a href="#功能特性">功能特性</a> •
    <a href="#架构">架构</a> •
    <a href="#硬件要求">硬件要求</a> •
    <a href="#快速开始">快速开始</a> •
    <a href="#使用说明">使用说明</a> •
    <a href="#版本历史">版本历史</a>
  </p>
</div>

---

WiFi WPA2 安全测试自动化工具。Kali 树莓派负责扫描抓包，Windows GPU 节点负责离线破解，全程在浏览器 Web UI 操作。

## 功能特性

### 双频扫描
- 支持 2.4G + 5G 双频 WiFi 扫描
- 显示信号强度、加密方式、频道、连接用户数
- 点击 AP 查看连接的客户端 MAC 列表
- 实时刷新，扫描过程中数据持续更新
- 历史扫描记录保存与加载

### 自动攻击
- 自动 deauth 强制客户端重连，抓取 EAPOL 四次握手
- 自动转换为 hc22000 哈希格式
- 支持 4 种 Hashcat 攻击模式：
  - 掩码暴力破解（-a 3）
  - 字典攻击（-a 0）
  - 字典 + 掩码混合（-a 6）
  - 掩码 + 字典混合（-a 7）
- 字典按长度和字符集预切分，快速定位
- 实时显示 Hashcat 进度、速度、ETA

### 多网卡适配
- 启动时自动识别所有无线网卡
- 支持选择哪块网卡做 monitor 模式
- 支持自动配置 NetworkManager，不影响日常使用
- 适配 MediaTek MT7612 等主流支持 monitor mode 的网卡

### Windows 离线破解
- 哈希通过 SSH 上传到 Windows 节点
- 利用 NVIDIA GPU 加速破解
- 支持随时添加多台计算节点
- 即使节点离线，也可以手动拷贝哈希文件去破解

### 资产与记录
- 抓到的握手包自动归档，按 SSID + BSSID 命名
- 已破解的 WiFi 自动记录到已知列表
- 所有数据持久化存储，重启不丢失

## 架构

```
┌─────────────────┐         SSH/SCP         ┌─────────────────┐
│  树莓派 Kali    │ ──────────────────────> │  Windows 计算节点 │
│  (Web UI 主控)  │ <────────────────────── │  (Hashcat GPU)  │
│                 │   哈希上传 + 结果回传    │                 │
│  MT7612U 网卡   │                         │  NVIDIA GPU     │
│  Monitor Mode   │                         │  CUDA 加速      │
└─────────────────┘                         └─────────────────┘
        │
        ▼
    目标 WiFi AP
```

## 硬件要求

| 设备 | 要求 |
|------|------|
| 抓包设备 | 树莓派 4/5，运行 Kali Linux |
| WiFi 网卡 | MediaTek MT7612U 或其他支持 monitor mode 的双频网卡 |
| 破解设备 | Windows 10/11 + NVIDIA GPU（推荐 RTX 30 系列以上） |
| 网络 | 局域网互通（Kali 和 Windows 在同一网段） |

## 快速开始

### 1. Kali 端部署

```bash
# 安装依赖
sudo apt update
sudo apt install python3 python3-pip aircrack-ng hcxtools -y
pip3 install fastapi uvicorn

# 克隆项目
git clone https://github.com/proapgandistic/AirWave.git
cd AirWave
```

### 2. Windows 端准备

1. 解压项目自带的 `hashcat-6.2.6-windows-gpu-node.7z`
2. 启用 OpenSSH Server
3. 配置 SSH 免密登录

### 3. 启动 AirWave

**方式一：桌面双击（推荐）**
双击桌面的 `AirWave.desktop` 图标。启动向导会引导你：
1. 选择 monitor 网卡
2. 选择是否关闭 NetworkManager
3. 启动 Web 服务

**方式二：命令行**
```bash
./airwave-launcher.sh
```

### 4. Web 端配置

浏览器访问 `http://<Kali-IP>:8000`，在「配置」页面填写：
- Windows 计算节点 IP
- SSH 用户名密码
- Hashcat 路径

## 配套工具

### WiFi 连接管理
当 NetworkManager 被关闭（为了 monitor 模式）时，用这个工具手动连接 WiFi：
- 双击 `WiFi连接管理.desktop`
- 从列表选择要连接的 WiFi
- 输入密码即可连接

### AP 热点模式
当户外没有路由器时，运行这个工具让树莓派自己当 WiFi 热点：
- 双击 `开启WiFi热点模式.desktop`
- 手机或其他设备可以直接连接树莓派的热点
- 通过 `http://100.100.100.1:8000` 访问 AirWave Web UI

## 使用说明

### 扫描
1. 打开「扫描」页面
2. 点击「开始扫描」
3. 等待发现目标 AP
4. 点击 AP 行展开查看客户端列表

### 抓包攻击
1. 选中目标 AP
2. 点击「开始攻击」
3. 等待自动 deauth + 抓握手
4. 抓到握手后自动上传到 Windows 破解

### 字典攻击
1. 打开「资产」页面
2. 找到要破解的 .hc22000 文件
3. 点击「加载」跳到攻击页面
4. 选择字典文件和攻击模式
5. 点击「开始」

## 项目结构

```
AirWave/
├── main.py                  # FastAPI 主控程序（内嵌 Web UI）
├── airwave-launcher.sh      # CLI 启动向导
├── AirWave.desktop          # 桌面快捷方式：启动 AirWave
├── wifi-ap.sh               # AP 热点模式脚本
├── wifi-connect.sh          # WiFi 连接脚本
├── wifi-menu.sh             # WiFi 连接菜单 UI
├── WiFi连接管理.desktop      # 桌面快捷方式：WiFi 连接管理
├── 开启WiFi热点模式.desktop   # 桌面快捷方式：开启 AP 热点
├── requirements.txt         # Python 依赖
├── README.md                # 本文档
├── LICENSE                  # GPL v3 许可证
└── hashcat-6.2.6-windows-gpu-node.7z  # Windows GPU 节点 Hashcat 安装包
```

## 版本历史

### v0.2.1 (2026-09-22)
- 统一产品名 AirWave，新增 About 页面
- 字典按长度+字符集预切分，快速定位
- Hashcat 实时进度显示
- 修复历史扫描加载不显示数据的问题
- 全页面英文字体统一为 Cascadia Code

### v0.2.0 (2026-09-21)
- 攻击页面集成完整 Hashcat 参数
- 资产归档与从资产直接发起攻击
- 扫描页面显示客户端 MAC 列表
- 历史扫描记录保存与加载
- WPS 状态检测与加密类型识别
- 户外 AP 热点直连模式

### v0.1.0 (2026-09-20)
- 首次发布
- 基础 WiFi 扫描与 deauth 抓包
- SSH 上传到 Windows Hashcat 破解

## 相关项目

- [PiSubGhz](https://github.com/proapgandistic/PiSubGhz) - 树莓派 Sub-GHz 工具

## 免责声明

本项目仅供学习和授权测试使用。未经授权破解他人 WiFi 网络属于违法行为。请仅在自己拥有或已获得书面授权的网络上进行测试。

作者不对任何滥用本工具造成的损失承担责任。

## 许可证

GPL v3
