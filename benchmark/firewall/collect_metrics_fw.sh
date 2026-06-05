#!/bin/bash
# =============================================================
# File: collect_metrics_fw.sh
# Chạy trên: VM firewall (10.10.1.1)
# Mục đích: Thu thập toàn diện CPU, Mem, Network, Conntrack, XDP,
#           Iptables mỗi 1 giây và ghi ra CSV tính Delta.
# Input: $1 (Tên Scenario)
# Output: metrics_firewall_<SCENARIO>_<TIMESTAMP>.csv
# Gọi bởi: orchestrate.sh
# =============================================================

SCENARIO=$1
if [ -z "$SCENARIO" ]; then SCENARIO="default"; fi
TS=$(date +"%Y%m%d_%H%M%S")
OUT_FILE="/tmp/metrics_firewall_${SCENARIO}_${TS}.csv"

echo "timestamp_unix_ms,cpu_all,nic_ext_irq_per_sec,softirq_net_rx_per_sec,softirq_net_tx_per_sec,mem_used_mb,ext_rx_pps,ext_rx_bps,conntrack_count,conntrack_syn_sent,conntrack_time_wait,xdp_drop_pps,xdp_pass_pps,iptables_drop_per_sec" > $OUT_FILE

# Các biến trạng thái trước đó (để tính Delta)
prev_irq=0
prev_soft_rx=0
prev_soft_tx=0
prev_ext_pkts=0
prev_ext_bytes=0
prev_xdp_drop=0
prev_xdp_pass=0
prev_iptables_drop=0

EXT_IFACE="enp0s8"

echo "[*] Đang ghi Firewall Metrics vào: $OUT_FILE"

while true; do
    TS_MS=$(date +%s%3N)
    
    # 1. CPU (Chỉ lấy tổng quát cho nhanh trong Bash, % idle)
    cpu_idle=$(top -bn1 | grep "Cpu(s)" | awk '{print $8}' | cut -d. -f1)
    cpu_usage=$((100 - cpu_idle))
    
    # 2. Memory
    mem_total=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    mem_avail=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
    mem_used_mb=$(( (mem_total - mem_avail) / 1024 ))
    
    # 3. Interrupts & SoftIRQs
    cur_irq=$(grep "$EXT_IFACE" /proc/interrupts | awk '{sum+=$2} END {print sum}')
    if [ -z "$cur_irq" ]; then cur_irq=0; fi
    delta_irq=$((cur_irq - prev_irq))
    prev_irq=$cur_irq
    
    cur_soft_rx=$(grep "NET_RX" /proc/softirqs | awk '{sum=0; for(i=2;i<=NF;i++) sum+=$i; print sum}')
    delta_soft_rx=$((cur_soft_rx - prev_soft_rx))
    prev_soft_rx=$cur_soft_rx
    
    cur_soft_tx=$(grep "NET_TX" /proc/softirqs | awk '{sum=0; for(i=2;i<=NF;i++) sum+=$i; print sum}')
    delta_soft_tx=$((cur_soft_tx - prev_soft_tx))
    prev_soft_tx=$cur_soft_tx

    # 4. Network (RX PPS/BPS)
    cur_ext_pkts=$(grep "$EXT_IFACE" /proc/net/dev | awk '{print $2}')
    cur_ext_bytes=$(grep "$EXT_IFACE" /proc/net/dev | awk '{print $1}')
    if [ -z "$cur_ext_pkts" ]; then cur_ext_pkts=0; cur_ext_bytes=0; fi
    delta_ext_pps=$((cur_ext_pkts - prev_ext_pkts))
    delta_ext_bps=$(( (cur_ext_bytes - prev_ext_bytes) * 8 ))
    prev_ext_pkts=$cur_ext_pkts
    prev_ext_bytes=$cur_ext_bytes
    
    # 5. Conntrack
    ct_count=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo "0")
    ct_syn=$(conntrack -L 2>/dev/null | grep -c "SYN_SENT" || echo "0")
    ct_tw=$(conntrack -L 2>/dev/null | grep -c "TIME_WAIT" || echo "0")
    
    # 6. XDP
    cur_xdp_drop=$(bpftool prog show | grep xdp_packet_filter | grep -o "run_cnt [0-9]*" | awk '{sum+=$2} END {print sum}')
    if [ -z "$cur_xdp_drop" ]; then cur_xdp_drop=0; fi
    delta_xdp_drop=$((cur_xdp_drop - prev_xdp_drop))
    prev_xdp_drop=$cur_xdp_drop
    
    # 7. Iptables
    cur_ipt_drop=$(iptables -nvL | grep "DROP" | awk '{sum+=$1} END {print sum}')
    if [ -z "$cur_ipt_drop" ]; then cur_ipt_drop=0; fi
    delta_ipt_drop=$((cur_ipt_drop - prev_iptables_drop))
    prev_iptables_drop=$cur_ipt_drop
    
    echo "$TS_MS,$cpu_usage,$delta_irq,$delta_soft_rx,$delta_soft_tx,$mem_used_mb,$delta_ext_pps,$delta_ext_bps,$ct_count,$ct_syn,$ct_tw,$delta_xdp_drop,0,$delta_ipt_drop" >> $OUT_FILE
    
    sleep 1
done
