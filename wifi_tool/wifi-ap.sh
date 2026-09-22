#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# ============================================
#  WiFi AP 模式 - 户外使用
#  SSID: Redteam_wifi  密码: 88668888
#  关闭此窗口自动恢复有线模式
# ============================================

cleanup() {
    echo ""
    echo "[*] 正在停止 AP 模式，恢复有线..."
    sudo killall hostapd 2>/dev/null
    sudo killall dnsmasq 2>/dev/null
    sudo ip link set wlan0 down 2>/dev/null
    sudo ip addr flush dev wlan0 2>/dev/null
    sudo systemctl start wpa_supplicant 2>/dev/null
    echo "[+] 已恢复有线模式，wlan0 已关闭"
    sleep 1
    exit 0
}

trap cleanup EXIT INT TERM

clear
echo "============================================"
echo "     WiFi AP 模式已启动"
echo "============================================"
echo "  SSID:     Redteam_wifi"
echo "  密码:     88668888"
echo "  管理IP:   100.100.100.1"
echo "  Web UI:   http://100.100.100.1:8000"
echo "============================================"
echo "  手机连接 Redteam_wifi 后"
echo "  浏览器打开 100.100.100.1:8000"
echo "============================================"
echo "  关闭此窗口将自动恢复有线模式"
echo "============================================"
echo ""

# 停止冲突服务
sudo systemctl stop wpa_supplicant 2>/dev/null
sudo killall hostapd dnsmasq 2>/dev/null
sleep 1

# 配置 wlan0
sudo ip link set wlan0 down
sudo ip addr flush dev wlan0
sudo ip addr add 100.100.100.1/24 dev wlan0
sudo ip link set wlan0 up
sleep 1

# 启动 DHCP
sudo dnsmasq -C "$SCRIPT_DIR/dnsmasq-ap.conf" 2>/dev/null
echo "[+] DHCP 服务就绪 (100.100.100.2-20)"

# 启动 hostapd（前台运行，窗口关闭即停止）
echo "[+] 热点已启动，等待设备连接..."
echo ""
sudo hostapd "$SCRIPT_DIR/hostapd-ap.conf"
