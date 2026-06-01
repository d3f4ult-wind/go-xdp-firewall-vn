#!/bin/bash
# ==============================================================================
# Script: collect_attacker_metrics.sh
# Mục đích: Đo PPS đầu ra (TX) và CPU của Attacker để chứng minh
# "Attacker đã cố hết sức" (không bị nghẽn ở nguồn).
# ==============================================================================

OUT_FILE="attacker_stats.csv"
echo "timestamp_unix,cpu_used_pct,tx_pps" > $OUT_FILE

echo "Đang ghi số liệu ra $OUT_FILE. Bấm Ctrl+C để dừng."

while true; do
    TS=$(date +%s)
    
    # Đo CPU (Lấy 100 - idle)
    CPU_IDLE=$(mpstat 1 1 | awk '/all/ {print $12}')
    CPU_USED=$(echo "100 - $CPU_IDLE" | bc -l | awk '{printf "%.2f", $0}')
    
    # Đo TX PPS trên interface chính (Thay eth0 bằng interface kết nối Firewall)
    TX_PPS=$(sar -n DEV 1 1 | grep 'eth0' | grep -v 'Average' | head -n 1 | awk '{print $4}')
    
    echo "$TS,$CPU_USED,$TX_PPS" >> $OUT_FILE
done
