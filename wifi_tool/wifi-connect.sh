#!/bin/bash
# ============================================
#  WiFi 连接管理脚本 (wpa_supplicant + dhclient)
#  不影响 wlan1mon monitor 模式
# ============================================
#  用法:
#    ./wifi-connect.sh scan                  扫描周围 WiFi
#    ./wifi-connect.sh connect <SSID> <密码>  连接 WiFi
#    ./wifi-connect.sh status                查看连接状态
#    ./wifi-connect.sh disconnect            断开 WiFi
# ============================================

IFACE="${WLAN_IFACE:-wlan0}"
WPA_CONF="/tmp/wpa_supplicant_${IFACE}.conf"
WPA_PID="/tmp/wpa_supplicant_${IFACE}.pid"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[-]${NC} $1"; }

# 检查接口是否存在
check_iface() {
    if ! ip link show "$IFACE" &>/dev/null; then
        err "接口 $IFACE 不存在"
        exit 1
    fi
}

# 清理旧连接
cleanup() {
    info "清理旧连接..."
    sudo killall wpa_supplicant 2>/dev/null
    sudo dhcpcd -k "$IFACE" 2>/dev/null
    sudo ip link set "$IFACE" down 2>/dev/null
    sleep 1
}

# ========== scan ==========
do_scan() {
    check_iface
    info "启用 $IFACE..."
    sudo ip link set "$IFACE" up
    sleep 2

    info "扫描周围 WiFi（需 3-5 秒）..."
    local scan_result
    scan_result=$(sudo iw dev "$IFACE" scan 2>/dev/null)

    if [ -z "$scan_result" ]; then
        err "扫描失败，未检测到 WiFi 信号"
        exit 1
    fi

    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}        扫描到的 WiFi 列表              ${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""

    # 解析扫描结果
    local bssid=""
    local freq=""
    local signal=""
    local ssid=""
    local encrypted=""

    echo "$scan_result" | while IFS= read -r line; do
        if [[ "$line" =~ ^BSS\ ([0-9a-f:]+) ]]; then
            if [ -n "$bssid" ] && [ -n "$ssid" ]; then
                printf "  %-20s  %-17s  %-4s  %-5s  %s\n" "$ssid" "$bssid" "$freq" "$signal" "$encrypted"
            fi
            bssid="${BASH_REMATCH[1]}"
            ssid=""
            freq=""
            signal=""
            encrypted="开放"
        elif [[ "$line" =~ freq:\ ([0-9]+) ]]; then
            freq="${BASH_REMATCH[1]}"
            if [ "$freq" -gt 2400 ] && [ "$freq" -lt 2500 ]; then
                freq="2.4G"
            elif [ "$freq" -gt 5000 ]; then
                freq="5G"
            fi
        elif [[ "$line" =~ signal:\ (-?[0-9.]+)\ dBm ]]; then
            signal="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ SSID:\ (.+) ]]; then
            ssid="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ Privacy ]]; then
            encrypted="加密"
        fi
    done

    # 输出最后一个
    if [ -n "$bssid" ] && [ -n "$ssid" ]; then
        printf "  %-20s  %-17s  %-4s  %-5s  %s\n" "$ssid" "$bssid" "$freq" "$signal" "$encrypted"
    fi

    echo ""
    info "使用 ./wifi-connect.sh connect <SSID> <密码> 连接"
}

# ========== connect ==========
do_connect() {
    local ssid="$1"
    local password="$2"

    if [ -z "$ssid" ]; then
        err "请指定 SSID"
        echo "用法: ./wifi-connect.sh connect <SSID> <密码>"
        exit 1
    fi

    if [ -z "$password" ]; then
        err "请指定密码"
        echo "用法: ./wifi-connect.sh connect <SSID> <密码>"
        exit 1
    fi

    check_iface
    cleanup

    info "启用 $IFACE..."
    sudo ip link set "$IFACE" up
    sleep 1

    info "生成 wpa_supplicant 配置..."
    wpa_passphrase "$ssid" "$password" | sudo tee "$WPA_CONF" > /dev/null
    # 加上控制接口，方便 wpa_cli 管理
    echo "ctrl_interface=/var/run/wpa_supplicant" | sudo tee -a "$WPA_CONF" > /dev/null
    echo "update_config=1" | sudo tee -a "$WPA_CONF" > /dev/null

    info "启动 wpa_supplicant..."
    sudo wpa_supplicant -B -i "$IFACE" -c "$WPA_CONF" -P "$WPA_PID" > /dev/null 2>&1
    sleep 2

    # 等待连接
    info "正在连接 $ssid ..."
    local connected=false
    for i in $(seq 1 15); do
        local status
        status=$(sudo wpa_cli -i "$IFACE" status 2>/dev/null | grep -oP '(?<=wpa_state=).*')
        if [ "$status" = "COMPLETED" ]; then
            connected=true
            break
        fi
        sleep 1
        echo -n "."
    done
    echo ""

    if [ "$connected" = false ]; then
        err "连接失败，请检查 SSID 和密码是否正确"
        sudo wpa_cli -i "$IFACE" status 2>/dev/null | grep -E "wpa_state|reason"
        cleanup
        exit 1
    fi

    ok "WiFi 连接成功！"

    # 获取 IP
    info "通过 DHCP 获取 IP..."
    sudo dhcpcd "$IFACE" 2>/dev/null
    sleep 3

    local ip_addr
    ip_addr=$(ip addr show "$IFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

    if [ -z "$ip_addr" ]; then
        warn "未获取到 IP，尝试再次获取..."
        sudo dhcpcd -d "$IFACE" 2>&1 | tail -5
        sleep 2
        ip_addr=$(ip addr show "$IFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
    fi

    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}        连接成功！                      ${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo -e "  SSID:      ${CYAN}$ssid${NC}"
    echo -e "  接口:      $IFACE"
    echo -e "  IP 地址:   ${GREEN}$ip_addr${NC}"
    echo -e "  Web UI:    http://$ip_addr:8000"
    echo -e "${GREEN}========================================${NC}"
    echo ""

    # 测试外网
    info "测试外网连通性..."
    if ping -c 2 -W 3 8.8.8.8 &>/dev/null; then
        ok "外网连通正常"
    else
        warn "外网 ping 失败（可能是禁 ping，不影响使用）"
    fi
}

# ========== status ==========
do_status() {
    check_iface

    local state
    state=$(sudo wpa_cli -i "$IFACE" status 2>/dev/null)

    echo ""
    echo -e "${CYAN}=== WiFi 状态 ===${NC}"
    echo "$state" | grep -E "wpa_state|ssid|bssid|ip_address|key_mgmt" | while IFS= read -r line; do
        echo "  $line"
    done

    echo ""
    echo -e "${CYAN}=== 接口信息 ===${NC}"
    ip addr show "$IFACE" | grep -E "inet |state"
    echo ""

    echo -e "${CYAN}=== 路由 ===${NC}"
    ip route show dev "$IFACE"
    echo ""
}

# ========== disconnect ==========
do_disconnect() {
    check_iface
    info "断开 WiFi 连接..."
    sudo wpa_cli -i "$IFACE" disconnect 2>/dev/null
    cleanup
    ok "已断开，$IFACE 已关闭"
}

# ========== main ==========
case "$1" in
    scan)
        do_scan
        ;;
    connect)
        do_connect "$2" "$3"
        ;;
    status)
        do_status
        ;;
    disconnect)
        do_disconnect
        ;;
    *)
        echo "WiFi 连接管理脚本"
        echo ""
        echo "用法:"
        echo "  $0 scan                  扫描周围 WiFi"
        echo "  $0 connect <SSID> <密码>  连接 WiFi"
        echo "  $0 status                查看连接状态"
        echo "  $0 disconnect            断开 WiFi"
        echo ""
        echo "示例:"
        echo "  $0 scan"
        echo "  $0 connect MyPhone 12345678"
        echo "  $0 status"
        echo "  $0 disconnect"
        exit 0
        ;;
esac
