#!/bin/bash
# WiFi 测试工具启动脚本
cd "$(dirname "$0")"

# 检查依赖
if ! python3 -c "import fastapi, uvicorn" 2>/dev/null; then
    echo "[*] 安装依赖..."
    pip3 install -q -r requirements.txt
fi

echo ""
echo "========================================================"
echo "  WiFi 测试工具已启动"
echo "  Kali 本地:  http://127.0.0.1:8000"
echo "  局域网访问: http://$(hostname -I | awk '{print $1}'):8000"
echo "  按 Ctrl+C 停止"
echo "========================================================"
echo ""

python3 main.py
