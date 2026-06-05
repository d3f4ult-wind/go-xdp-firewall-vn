#!/bin/bash
# =============================================================
# File: run_scenario_2.sh
# Chạy trên: VM firewall (10.10.1.1)
# Mục đích: Wrapper kích hoạt Kịch bản 2 (Random IP Spoofing)
# =============================================================

SCENARIO="sc2_random"
ATTACK_SCRIPT="attack_sc2_random.sh"

echo "=========================================================="
echo " CHUẨN BỊ KỊCH BẢN 2: TẤN CÔNG BẰNG RANDOM IP (SPOOFING)"
echo " Mô tả: Hàng ngàn IP giả mạo ngẫu nhiên nã SYN Flood vào Victim."
echo " Kỳ vọng: Bảng conntrack có thể bị quá tải, Iptables tụt hạng."
echo "          Cơ chế Geo Trust của XDP (nếu bật) giúp Legit Client"
echo "          đến từ US vẫn truy cập được bình thường."
echo "=========================================================="
sleep 2

bash ./orchestrate.sh "$SCENARIO" "$ATTACK_SCRIPT"
