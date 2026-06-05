#!/bin/bash
# =============================================================
# File: run_scenario_1.sh
# Chạy trên: VM firewall (10.10.1.1)
# Mục đích: Wrapper kích hoạt Kịch bản 1 (Botnet 1 khu vực)
# Input: Không
# Output: Kết quả log chuyển giao cho orchestrate.sh
# =============================================================

SCENARIO="sc1_botnet"
ATTACK_SCRIPT="attack_sc1_botnet.sh"

echo "=========================================================="
echo " CHUẨN BỊ KỊCH BẢN 1: BOTNET GEO SPUFFING (TRUNG QUỐC)"
echo " Mô tả: Kịch bản mô phỏng 5 IP đến từ TQ nã SYN Flood."
echo " Kỳ vọng: Watcher phát hiện, tự động tra GeoIP và BlockCountry."
echo "          Tốc độ XDP_DROP tăng đột biến."
echo "=========================================================="
sleep 2

# Gọi Master Orchestrator
bash ./orchestrate.sh "$SCENARIO" "$ATTACK_SCRIPT"
