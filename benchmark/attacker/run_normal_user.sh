#!/bin/bash
# ==============================================================================
# Script: run_normal_user.sh
# Mục đích: Đóng vai người dùng bình thường, tải web từ Victim.
# Chạy trên: Attacker VM (Namespace ns_10)
# ==============================================================================

VICTIM_IP="10.10.2.2"
DURATION="120" # 120 giây (Bao phủ Phase 1 đến hết Phase 4)

echo "[+] Bắt đầu luồng Normal User (wrk) tại ns_10..."
echo "Target: http://$VICTIM_IP"

# Bật wrk chạy trong ns_10, ghi kết quả ra normal_user_wrk.log
ip netns exec ns_10 wrk -t2 -c50 -d${DURATION}s --latency http://$VICTIM_IP > normal_user_wrk.log 2>&1 &

echo "Đã đưa wrk vào background. Nó sẽ tự thoát sau $DURATION giây."
