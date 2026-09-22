#!/bin/bash
# ============================================
#  WiFi 连接管理 - 简洁风格
#  双击运行，选网卡 → 扫描 → 选 SSID → 输密码 → 连接
# ============================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WIFI_CLI="$SCRIPT_DIR/wifi-connect.sh"
export WLAN_IFACE="wlan0"  # 默认，启动时会让用户选

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# 信号强度转格子
signal_bars() {
    local sig=$1
    sig=${sig%%.*}
    [ -z "$sig" ] && sig=-100
    if [ "$sig" -ge -50 ]; then
        echo -e "${GREEN}●●●●${NC}"
    elif [ "$sig" -ge -60 ]; then
        echo -e "${GREEN}●●●○${NC}"
    elif [ "$sig" -ge -70 ]; then
        echo -e "${YELLOW}●●○○${NC}"
    elif [ "$sig" -ge -80 ]; then
        echo -e "${YELLOW}●○○○${NC}"
    else
        echo -e "${RED}○○○○${NC}"
    fi
}

# 选择 managed 网卡（排除 monitor 和 P2P-device）
select_wlan_iface() {
    clear
    echo ""
    echo -e "${BOLD}${CYAN}  选择 WiFi 网卡${NC}"
    echo -e "${CYAN}  ──────────────────────────────────────${NC}"
    echo ""

    # 获取 airmon-ng 输出（驱动和芯片）
    local airmon_out
    airmon_out=$(sudo airmon-ng 2>/dev/null | tail -n +2)

    local idx=1
    local iface_array=()
    # 用 iw dev 列出所有 managed 接口
    while IFS= read -r iface; do
        [ -z "$iface" ] && continue

        local iface_type
        iface_type=$(iw dev 2>/dev/null | awk -v iface="$iface" '
            $2 == iface {found=1; next}
            found && /type/ {print $2; exit}
        ')

        # 显示所有接口（包括 monitor），用户自行判断

        local iface_addr
        iface_addr=$(iw dev 2>/dev/null | awk -v iface="$iface" '
            $2 == iface {found=1; next}
            found && /addr/ {print $2; exit}
        ')

        # 从 airmon-ng 获取驱动和芯片
        local iface_driver iface_chipset
        iface_driver=$(echo "$airmon_out" | awk -v iface="$iface" '$2 == iface {print $3}')
        iface_chipset=$(echo "$airmon_out" | awk -v iface="$iface" '$2 == iface {for(i=4;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/ *$//')

        # 当前连接状态
        local cur_ssid=""
        cur_ssid=$(sudo wpa_cli -i "$iface" status 2>/dev/null | grep '^ssid=' | cut -d= -f2-)
        cur_ssid=$(printf "%b" "$cur_ssid" 2>/dev/null || echo "$cur_ssid")

        iface_array+=("$iface")

        printf "  ${GREEN}%d${NC}. %-10s MAC: %-17s\n" "$idx" "$iface" "$iface_addr"
        printf "      驱动: %-10s 芯片: %s\n" "$iface_driver" "$iface_chipset"
        if [ -n "$cur_ssid" ]; then
            printf "      状态: ${GREEN}已连接: %s${NC}\n" "$cur_ssid"
        else
            printf "      状态: ${YELLOW}未连接${NC}\n"
        fi
        echo ""
        idx=$((idx+1))
    done < <(iw dev 2>/dev/null | grep -oP 'Interface \K\S+')

    local total=$((idx-1))
    if [ "$total" -eq 0 ]; then
        echo -e "  ${RED}未找到可用的 managed 网卡${NC}"
        echo ""
        read -p "  按回车退出..."
        exit 1
    fi

    echo -e "${CYAN}  ──────────────────────────────────────${NC}"
    read -p "  选择网卡 [1-$total]: " sel

    if ! [[ "$sel" =~ ^[0-9]+$ ]] || [ "$sel" -lt 1 ] || [ "$sel" -gt "$total" ]; then
        echo -e "  ${RED}无效选择${NC}"
        sleep 1
        return 1
    fi

    WLAN_IFACE="${iface_array[$((sel-1))]}"
    export WLAN_IFACE
    echo ""
    echo -e "  已选择网卡: ${GREEN}$WLAN_IFACE${NC}"
    sleep 1
}

# 扫描 WiFi（多次扫描累积，去重，按信号排序）
scan_wifi() {
    sudo ip link set "$WLAN_IFACE" up 2>/dev/null
    sleep 1

    local all_results=""
    for round in 1 2 3; do
        local scan_out
        scan_out=$(sudo iw dev "$WLAN_IFACE" scan 2>/dev/null)
        if [ -n "$scan_out" ]; then
            local parsed
            parsed=$(echo "$scan_out" | awk '
                /^BSS / {
                    if (prev_ssid != "") {
                        printf "%s\t%s\t%s\n", prev_signal, prev_ssid, prev_enc
                    }
                    prev_signal=""; prev_ssid=""; prev_enc="开放"
                }
                /signal:/ { prev_signal=$2 }
                /RSN:/ { prev_enc="WPA2" }
                /WPA:/ { if (prev_enc=="开放") prev_enc="WPA" }
                /SSID:/ {
                    s=substr($0, index($0, ":")+2)
                    if (s != "") prev_ssid=s
                }
                END {
                    if (prev_ssid != "") {
                        printf "%s\t%s\t%s\n", prev_signal, prev_ssid, prev_enc
                    }
                }
            ')
            all_results="$all_results
$parsed"
        fi
        [ "$round" -lt 3 ] && sleep 2
    done

    # 按 SSID 去重（保留信号最强的），按信号降序，解码中文
    echo "$all_results" | grep -v '^$' | sort -t$'\t' -k1 -rn | awk -F'\t' '
        !seen[$2]++ { printf "%s\t%s\t%s\n", $1, $2, $3 }
    ' | while IFS=$'\t' read -r sig ssid enc; do
        decoded_ssid=$(printf "%b" "$ssid" 2>/dev/null || echo "$ssid")
        printf "%s\t%s\t%s\n" "$sig" "$decoded_ssid" "$enc"
    done
}

# 扫描并连接
do_connect() {
    echo ""
    echo -e "${CYAN}[*] 正在通过 $WLAN_IFACE 扫描周围 WiFi...${NC}"

    local results
    results=$(scan_wifi)

    if [ -z "$results" ]; then
        echo -e "${RED}[-] 未扫描到 WiFi 信号${NC}"
        echo ""
        read -p "  按回车返回..."
        return
    fi

    local count
    count=$(echo "$results" | wc -l)

    clear
    echo ""
    echo -e "${BOLD}${CYAN}  选择 WiFi 网络  (${WLAN_IFACE})${NC}"
    echo -e "${CYAN}  ──────────────────────────────────────${NC}"
    echo ""

    local i=1
    local ssid_array=()
    while IFS=$'\t' read -r signal ssid enc; do
        ssid_array+=("$ssid")
        local bars
        bars=$(signal_bars "$signal")
        local lock=""
        [ "$enc" != "开放" ] && lock="🔒"
        printf "  ${GREEN}%2d${NC}. %s  %-28s %s %s\n" "$i" "$bars" "$ssid" "$enc" "$lock"
        i=$((i+1))
    done <<< "$results"

    echo ""
    echo -e "${CYAN}  ──────────────────────────────────────${NC}"
    echo -e "  共找到 ${GREEN}$count${NC} 个网络"
    echo ""
    read -p "  选择 [1-$count] (0=返回): " sel

    if [ "$sel" = "0" ] || [ -z "$sel" ]; then
        return
    fi

    if ! [[ "$sel" =~ ^[0-9]+$ ]] || [ "$sel" -lt 1 ] || [ "$sel" -gt "$count" ]; then
        echo -e "  ${RED}[-] 无效选择${NC}"
        sleep 1
        return
    fi

    local selected_ssid="${ssid_array[$((sel-1))]}"
    echo ""
    echo -e "  连接: ${GREEN}$selected_ssid${NC}"
    echo ""
    read -s -p "  密码: " password
    echo ""

    if [ -z "$password" ]; then
        echo -e "  ${RED}[-] 密码不能为空${NC}"
        sleep 1
        return
    fi

    echo ""
    WLAN_IFACE="$WLAN_IFACE" bash "$WIFI_CLI" connect "$selected_ssid" "$password"
    echo ""
    read -p "  按回车返回..."
}

# 主循环
select_wlan_iface
clear
while true; do
    echo ""
    echo -e "${BOLD}${CYAN}  WiFi 连接管理${NC}"
    echo -e "${CYAN}  ──────────────────────────────────────${NC}"
    echo ""

    # 当前状态
    CURRENT_SSID=$(sudo wpa_cli -i "$WLAN_IFACE" status 2>/dev/null | grep '^ssid=' | cut -d= -f2-)
    CURRENT_SSID=$(printf "%b" "$CURRENT_SSID" 2>/dev/null || echo "$CURRENT_SSID")
    CURRENT_IP=$(ip addr show "$WLAN_IFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
    echo -e "  网卡: ${GREEN}$WLAN_IFACE${NC}"
    if [ -n "$CURRENT_SSID" ]; then
        echo -e "  连接: ${GREEN}$CURRENT_SSID${NC}  ($CURRENT_IP)"
    else
        echo -e "  状态: ${YELLOW}未连接${NC}"
    fi
    echo ""

    echo -e "  ${GREEN}1${NC}. 扫描并连接 WiFi"
    echo -e "  ${GREEN}2${NC}. 断开 WiFi"
    echo -e "  ${GREEN}3${NC}. 切换网卡"
    echo -e "  ${RED}4${NC}. 退出"
    echo ""
    echo -e "${CYAN}  ──────────────────────────────────────${NC}"
    echo ""
    read -p "  选择 [1-4]: " choice

    case $choice in
        1)
            do_connect
            clear
            ;;
        2)
            echo ""
            WLAN_IFACE="$WLAN_IFACE" bash "$WIFI_CLI" disconnect
            echo ""
            read -p "  按回车返回..."
            clear
            ;;
        3)
            select_wlan_iface
            clear
            ;;
        4)
            echo ""
            echo -e "${GREEN}  再见${NC}"
            echo ""
            exit 0
            ;;
        *)
            echo -e "  ${RED}  无效选择${NC}"
            sleep 1
            clear
            ;;
    esac
done
