#!/bin/bash
# ============================================
#  AirWave 启动向导
#  选择 monitor 网卡 → airmon-ng → 启动后端 → 开浏览器
#  退出时自动恢复 Kali 原生状态
# ============================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
LAUNCHER_LOG="$LOG_DIR/launcher.log"
AIRWAVE_LOG="$LOG_DIR/airwave.log"
CONFIG_FILE="$SCRIPT_DIR/config.json"
MAIN_PY="$SCRIPT_DIR/main.py"

mkdir -p "$LOG_DIR"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} $1" | tee -a "$LAUNCHER_LOG"; }
ok()    { echo -e "${GREEN}[+]${NC} $1" | tee -a "$LAUNCHER_LOG"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1" | tee -a "$LAUNCHER_LOG"; }
err()   { echo -e "${RED}[-]${NC} $1" | tee -a "$LAUNCHER_LOG"; }

# 记录启动前的服务状态，用于恢复
NM_WAS_ACTIVE=false
WPA_WAS_ACTIVE=false
MONITOR_IFACE=""
MONITOR_PHY=""

# ========== 清理恢复函数 ==========
cleanup() {
    echo ""
    info "正在停止 AirWave 并恢复 Kali 原生状态..."

    # 1. 杀掉 main.py
    if [ -n "$MAIN_PID" ]; then
        kill "$MAIN_PID" 2>/dev/null
        sleep 1
        kill -9 "$MAIN_PID" 2>/dev/null
    fi
    # 确保没有残留的 python3 main.py
    pkill -f "python3 $MAIN_PY" 2>/dev/null
    pkill -f "uvicorn" 2>/dev/null
    info "  后端服务已停止"

    # 2. 停止 monitor 接口（airmon-ng stop）
    if [ -n "$MONITOR_IFACE" ]; then
        sudo airmon-ng stop "$MONITOR_IFACE" >/dev/null 2>&1
        info "  Monitor 接口 $MONITOR_IFACE 已停止，网卡恢复 managed"
    fi

    # 3. 恢复被 airmon-ng check kill 杀掉的服务
    if [ "$WPA_WAS_ACTIVE" = true ]; then
        sudo systemctl start wpa_supplicant 2>/dev/null
        info "  wpa_supplicant 已恢复"
    fi
    if [ "$NM_WAS_ACTIVE" = true ]; then
        sudo systemctl start NetworkManager 2>/dev/null
        info "  NetworkManager 已恢复"
    fi

    ok "Kali 已恢复原生状态"
    echo ""
    exit 0
}

trap cleanup EXIT INT TERM

# ========== 主流程 ==========
clear
echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║          AirWave 启动向导              ║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════╝${NC}"
echo ""

# ---- 步骤1：选择 monitor 网卡 ----
info "扫描无线网卡..."
echo ""

# 用 iw dev 列出所有无线接口
mapfile -t PHY_LIST < <(iw dev 2>/dev/null | grep -oP 'phy#[0-9]+' | sort -u)

if [ ${#PHY_LIST[@]} -eq 0 ]; then
    err "未检测到任何无线网卡"
    exit 1
fi

# 列出每个 phy 的接口信息
echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║       请选择 Monitor 网卡              ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
echo ""

idx=1
declare -a IFACE_NAMES
declare -a IFACE_PHYS
for phy in "${PHY_LIST[@]}"; do
    phy_num="${phy#phy#}"
    # 获取这个 phy 的接口信息
    iface_info=$(iw dev 2>/dev/null | awk -v p="phy#$phy_num" '
        $0 ~ p {found=1; next}
        found && /^[[:space:]]*Interface/ {print $2; exit}
    ')
    iface_addr=$(iw dev 2>/dev/null | awk -v p="phy#$phy_num" '
        $0 ~ p {found=1; next}
        found && /addr/ {print $2; exit}
    ')
    iface_type=$(iw dev 2>/dev/null | awk -v p="phy#$phy_num" '
        $0 ~ p {found=1; next}
        found && /type/ {print $2; exit}
    ')

    # 判断是否支持 monitor（简单判断：不是 monitor 模式的都可以）
    support_monitor="是"
    if [ "$iface_type" = "monitor" ]; then
        support_monitor="已是monitor"
    fi

    IFACE_NAMES+=("$iface_info")
    IFACE_PHYS+=("$phy_num")

    printf "  ${GREEN}%d${NC}. %-12s  MAC: %-17s  模式: %-8s  支持monitor: %s\n" \
        "$idx" "$iface_info" "$iface_addr" "$iface_type" "$support_monitor"
    idx=$((idx+1))
done

echo ""
echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
echo ""
read -p "  请选择网卡 [1-$((idx-1))]: " choice

if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt "$((idx-1))" ]; then
    err "无效选择"
    exit 1
fi

SELECTED_IFACE="${IFACE_NAMES[$((choice-1))]}"
SELECTED_PHY="${IFACE_PHYS[$((choice-1))]}"
MONITOR_IFACE="${SELECTED_IFACE}mon"
ok "已选择: $SELECTED_IFACE (phy#$SELECTED_PHY)，Monitor 接口将命名为 $MONITOR_IFACE"
echo ""

# ---- 步骤2：记录服务状态，airmon-ng check kill ----
info "检查网络服务状态..."
if systemctl is-active --quiet NetworkManager 2>/dev/null; then
    NM_WAS_ACTIVE=true
    warn "  NetworkManager 正在运行，启动后将停止（避免干扰 monitor）"
else
    info "  NetworkManager: 未运行"
fi
if systemctl is-active --quiet wpa_supplicant 2>/dev/null; then
    WPA_WAS_ACTIVE=true
    info "  wpa_supplicant: 正在运行"
else
    info "  wpa_supplicant: 未运行"
fi

echo ""
info "执行 airmon-ng check kill（清理可能干扰的进程）..."
sudo airmon-ng check kill >/dev/null 2>&1
sleep 1
ok "清理完成"
echo ""

# ---- 步骤3：airmon-ng start ----
info "执行 airmon-ng start $SELECTED_IFACE ..."
sudo airmon-ng start "$SELECTED_IFACE" >/dev/null 2>&1
sleep 2

# 验证 monitor 接口是否创建成功
if iw dev 2>/dev/null | grep -q "Interface $MONITOR_IFACE"; then
    iface_type=$(iw dev 2>/dev/null | awk -v iface="$MONITOR_IFACE" '
        $0 ~ "Interface " iface {found=1; next}
        found && /type/ {print $2; exit}
    ')
    if [ "$iface_type" = "monitor" ]; then
        ok "Monitor 接口 $MONITOR_IFACE 创建成功（type: monitor）"
    else
        err "接口 $MONITOR_IFACE 存在但模式是 $iface_type，不是 monitor"
        exit 1
    fi
else
    err "Monitor 接口 $MONITOR_IFACE 创建失败"
    err "请检查网卡是否支持 monitor 模式"
    exit 1
fi

# 启动 monitor 接口
sudo ip link set "$MONITOR_IFACE" up 2>/dev/null
echo ""

# ---- 步骤4：写入 config.json ----
info "写入配置（monitor_interface: $MONITOR_IFACE）..."
python3 -c "
import json, sys
config_file = '$CONFIG_FILE'
try:
    with open(config_file) as f:
        config = json.load(f)
except:
    config = {}
config['monitor_interface'] = '$MONITOR_IFACE'
with open(config_file, 'w') as f:
    json.dump(config, f, indent=2, ensure_ascii=False)
print('  配置已写入')
" 2>&1 | tee -a "$LAUNCHER_LOG"
echo ""

# ---- 步骤5：启动后端服务 ----
info "启动 AirWave 后端服务..."
info "  日志: $AIRWAVE_LOG"

# 杀掉可能残留的旧进程
pkill -f "python3 $MAIN_PY" 2>/dev/null
sleep 1

# 启动（后台）
cd "$SCRIPT_DIR"
nohup python3 "$MAIN_PY" > "$AIRWAVE_LOG" 2>&1 &
MAIN_PID=$!
info "  进程 PID: $MAIN_PID"

# 等待服务就绪
info "等待服务启动（最多 15 秒）..."
ready=false
for i in $(seq 1 15); do
    if curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8000/ 2>/dev/null | grep -q "200"; then
        ready=true
        break
    fi
    sleep 1
    echo -n "."
done
echo ""

if [ "$ready" = false ]; then
    err "服务启动失败，请检查日志: $AIRWAVE_LOG"
    tail -20 "$AIRWAVE_LOG"
    exit 1
fi

ok "AirWave 服务已启动！"
echo ""

# ---- 步骤6：打开浏览器 ----
info "打开浏览器 http://127.0.0.1:8000 ..."
if command -v xdg-open &>/dev/null; then
    xdg-open http://127.0.0.1:8000 >/dev/null 2>&1 &
elif command -v firefox &>/dev/null; then
    firefox http://127.0.0.1:8000 >/dev/null 2>&1 &
elif command -v chromium &>/dev/null; then
    chromium http://127.0.0.1:8000 >/dev/null 2>&1 &
else
    warn "未找到浏览器，请手动打开 http://127.0.0.1:8000"
fi
echo ""

# ---- 运行中状态 ----
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║       AirWave 运行中                  ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════╝${NC}"
echo ""
echo -e "  Monitor 接口: ${GREEN}$MONITOR_IFACE${NC}"
echo -e "  Web UI:       ${GREEN}http://127.0.0.1:8000${NC}"
echo -e "  局域网访问:    http://<Kali-IP>:8000"
echo -e "  后端日志:     $AIRWAVE_LOG"
echo -e "  启动器日志:   $LAUNCHER_LOG"
echo ""
echo -e "${CYAN}──────────────────────────────────────────${NC}"
echo ""
echo -e "  按 ${YELLOW}Q${NC} 停止服务并恢复 Kali 原生状态"
echo -e "  或直接${YELLOW}关闭此窗口${NC}也会停止并恢复"
echo ""
echo -e "${CYAN}──────────────────────────────────────────${NC}"
echo ""

# 等待用户按 Q
while true; do
    read -t 1 -n 1 key
    if [ "$key" = "q" ] || [ "$key" = "Q" ]; then
        break
    fi
    # 检查服务是否还在运行
    if ! kill -0 "$MAIN_PID" 2>/dev/null; then
        err "后端服务意外退出，查看日志: $AIRWAVE_LOG"
        tail -10 "$AIRWAVE_LOG"
        break
    fi
done

# cleanup 会被 trap 自动调用
