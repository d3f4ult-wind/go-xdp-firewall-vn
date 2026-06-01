#!/bin/bash
# ==============================================================================
# Script: collect_metrics.sh
# Chạy ngầm: Ghi số liệu mpstat, sar, conntrack mỗi 1 giây.
# ==============================================================================

OUT_DIR=$1
CPU_CSV="$OUT_DIR/firewall_cpu_mem.csv"
NET_CSV="$OUT_DIR/firewall_net_stack.csv"

echo "timestamp_unix,cpu_user,cpu_sys,cpu_softirq,cpu_idle,ram_used_mb,ram_free_mb" > $CPU_CSV
echo "timestamp_unix,rx_pps,tx_pps,conntrack_count" > $NET_CSV

# Hàm thu thập
while true; do
    TS=$(date +%s)
    
    # Đo CPU nhanh (Lấy dòng all)
    CPU_RAW=$(mpstat 1 1 | awk '/all/ {print $3, $5, $8, $12}')
    read -r cpu_user cpu_sys cpu_softirq cpu_idle <<< "$CPU_RAW"
    
    # Đo RAM
    RAM_RAW=$(free -m | awk '/Mem:/ {print $3, $4}')
    read -r ram_used ram_free <<< "$RAM_RAW"
    
    echo "$TS,$cpu_user,$cpu_sys,$cpu_softirq,$cpu_idle,$ram_used,$ram_free" >> $CPU_CSV
    
    # Đo Network PPS (Interface enp0s8 - hứng traffic)
    NET_RAW=$(sar -n DEV 1 1 | grep 'enp0s8' | grep -v 'Average' | head -n 1 | awk '{print $3, $4}')
    read -r rx_pps tx_pps <<< "$NET_RAW"
    
    # Đo Conntrack
    CT_COUNT=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0)
    
    echo "$TS,$rx_pps,$tx_pps,$CT_COUNT" >> $NET_CSV
    
done
