#!/bin/bash
# =============================================================
# File: collect_metrics_fw.sh
# Chạy trên: VM firewall (10.10.1.1)
# Mục đích: Thu thập toàn diện CPU, Mem, Network, Conntrack, XDP,
#           Iptables mỗi 1 giây và ghi ra CSV tính Delta.
# =============================================================

# Bỏ -e để tránh collector tự kill khi lệnh phụ (bpftool, conntrack) fail
set -uo pipefail

# Xử lý dọn dẹp khi bị tắt bằng Orchestrator
trap "echo '[*] Dừng thu thập Metric Firewall...'; exit 0" SIGINT SIGTERM

SCENARIO=${1:-"default"}
TS=$(date +"%Y%m%d_%H%M%S")
OUT_FILE="/tmp/metrics_firewall_${SCENARIO}_${TS}.csv"
EXT_IFACE="enp0s8"

# Kích hoạt eBPF stats trên kernel để hiển thị run_cnt
sysctl -w kernel.bpf_stats_enabled=1 >/dev/null 2>&1 || true

echo "timestamp_unix_ms,cpu_all,nic_ext_irq_per_sec,softirq_net_rx_per_sec,softirq_net_tx_per_sec,mem_used_mb,ext_rx_pps,ext_rx_bps,conntrack_count,conntrack_syn_sent,conntrack_time_wait,xdp_run_pps,xdp_drop_pps,iptables_drop_per_sec" > "$OUT_FILE"

# Biến lưu trữ vòng lặp trước để tính delta
prev_irq=0
prev_soft_rx=0
prev_soft_tx=0
prev_ext_pkts=0
prev_ext_bytes=0
prev_xdp_run=0
prev_xdp_drop=0
prev_iptables_drop=0

# Đọc CPU ban đầu từ /proc/stat
cpu_stats=($(grep '^cpu ' /proc/stat))
prev_cpu_total=0
for i in {1..8}; do
    prev_cpu_total=$((prev_cpu_total + ${cpu_stats[$i]:-0}))
done
prev_cpu_idle=${cpu_stats[4]:-0}

echo "[*] Đang ghi Firewall Metrics vào: $OUT_FILE"

while true; do
    # Đo timestamp chính xác ms
    TS_MS=$(date +%s%3N)
    
    # 1. CPU (Tính delta bằng array để tránh rỗng field ở kernel cũ)
    cpu_stats=($(grep '^cpu ' /proc/stat))
    cur_cpu_total=0
    for i in {1..8}; do
        cur_cpu_total=$((cur_cpu_total + ${cpu_stats[$i]:-0}))
    done
    cur_cpu_idle=${cpu_stats[4]:-0}
    
    total_delta=$((cur_cpu_total - prev_cpu_total))
    idle_delta=$((cur_cpu_idle - prev_cpu_idle))
    
    if [ "$total_delta" -eq 0 ]; then
        cpu_usage=0
    else
        cpu_usage=$(( 100 * (total_delta - idle_delta) / total_delta ))
    fi
    prev_cpu_total=$cur_cpu_total
    prev_cpu_idle=$cur_cpu_idle
    
    # 2. Memory
    mem_total=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
    mem_avail=$(awk '/MemAvailable/ {print $2}' /proc/meminfo)
    mem_used_mb=$(( (mem_total - mem_avail) / 1024 ))
    
    # 3. Interrupts & SoftIRQs
    # Tên driver virtio hoặc enp0s8, nếu không tìm thấy, fallback sang /sys rx_packets
    cur_irq=$(grep -iE "${EXT_IFACE}|virtio" /proc/interrupts | awk '{for(i=2;i<=NF;i++) if($i ~ /^[0-9]+$/) sum+=$i} END {print sum+0}' || true)
    if [ -z "$cur_irq" ] || [ "$cur_irq" -eq 0 ]; then
        cur_irq=$(cat /sys/class/net/$EXT_IFACE/statistics/rx_packets 2>/dev/null || echo "0")
    fi
    delta_irq=$((cur_irq - prev_irq))
    if [ "$delta_irq" -lt 0 ]; then delta_irq=0; fi
    prev_irq=$cur_irq
    
    cur_soft_rx=$(grep "NET_RX:" /proc/softirqs | awk '{for(i=2;i<=NF;i++) sum+=$i} END {print sum+0}' || true)
    if [ -z "$cur_soft_rx" ]; then cur_soft_rx=0; fi
    delta_soft_rx=$((cur_soft_rx - prev_soft_rx))
    if [ "$delta_soft_rx" -lt 0 ]; then delta_soft_rx=0; fi
    prev_soft_rx=$cur_soft_rx
    
    cur_soft_tx=$(grep "NET_TX:" /proc/softirqs | awk '{for(i=2;i<=NF;i++) sum+=$i} END {print sum+0}' || true)
    if [ -z "$cur_soft_tx" ]; then cur_soft_tx=0; fi
    delta_soft_tx=$((cur_soft_tx - prev_soft_tx))
    if [ "$delta_soft_tx" -lt 0 ]; then delta_soft_tx=0; fi
    prev_soft_tx=$cur_soft_tx

    # 4. Network (RX PPS/BPS) sửa lỗi cột
    net_data=$(grep -w "$EXT_IFACE" /proc/net/dev | awk -F':' '{print $2}')
    cur_ext_bytes=$(echo "$net_data" | awk '{print $1}')
    cur_ext_pkts=$(echo "$net_data" | awk '{print $2}')
    if [ -z "$cur_ext_pkts" ]; then cur_ext_pkts=0; cur_ext_bytes=0; fi
    
    delta_ext_pps=$((cur_ext_pkts - prev_ext_pkts))
    delta_ext_bps=$(( (cur_ext_bytes - prev_ext_bytes) * 8 ))
    if [ "$delta_ext_pps" -lt 0 ]; then delta_ext_pps=0; delta_ext_bps=0; fi
    prev_ext_pkts=$cur_ext_pkts
    prev_ext_bytes=$cur_ext_bytes
    
    # 5. Conntrack (Lấy 1 lần snapshot, thêm || true để chống set -e)
    ct_count=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo "0")
    ct_dump=$(conntrack -L 2>/dev/null || true)
    ct_syn=$(echo "$ct_dump" | grep -c "SYN_SENT" || true)
    ct_tw=$(echo "$ct_dump" | grep -c "TIME_WAIT" || true)
    
    # 6. XDP
    # Tính tổng xdp_run bằng JSON để chống lỗi Parse Version
    cur_xdp_run=$(bpftool prog show name xdp_packet_filter -j 2>/dev/null | python3 -c "
import sys,json
try:
    d=json.loads(sys.stdin.read() or '[]')
    d=d if isinstance(d,list) else [d]
    print(sum(int(p.get('run_cnt',0)) for p in d if isinstance(p,dict)))
except Exception:
    print(0)
" 2>/dev/null || true)
    # Lấy dòng đầu tiên, loại bỏ khoảng trắng, fallback về 0 nếu rỗng
    cur_xdp_run=$(echo "${cur_xdp_run:-0}" | head -1 | tr -d '[:space:]')
    cur_xdp_run=${cur_xdp_run:-0}
    delta_xdp_run=$((cur_xdp_run - prev_xdp_run))
    if [ "$delta_xdp_run" -lt 0 ]; then delta_xdp_run=0; fi
    prev_xdp_run=$cur_xdp_run
    
    # Đọc tổng số Drop từ Map mitigation_stats (PERCPU). Index 3,4,5 tương ứng Drop/Block.
    # Fix: bpftool PERCPU_ARRAY key có thể là int (3) hoặc hex string ("0x00000003")
    # Cần convert về int trước khi so sánh. Index 3=syn_dropped, 4=udp_dropped, 5=icmp_dropped
    cur_xdp_drop=$(bpftool map dump name mitigation_stats -j 2>/dev/null | python3 -c "
import sys,json
try:
    d=json.loads(sys.stdin.read() or '[]')
    total=0
    for e in d:
        if not isinstance(e,dict): continue
        k=e.get('key','')
        if isinstance(k,str):
            try: k=int(k,16)
            except: k=-1
        elif isinstance(k,list):
            try: k=int.from_bytes(bytes(k),'little')
            except: k=-1
        if k in (2,3,4,5):
            vals=e.get('values',[])
            total+=sum(int(v.get('value',0)) for v in vals if isinstance(v,dict))
    print(total)
except Exception:
    print(0)
" 2>/dev/null || true)
    cur_xdp_drop=$(echo "${cur_xdp_drop:-0}" | head -1 | tr -d '[:space:]')
    cur_xdp_drop=${cur_xdp_drop:-0}
    delta_xdp_drop=$((cur_xdp_drop - prev_xdp_drop))
    if [ "$delta_xdp_drop" -lt 0 ]; then delta_xdp_drop=0; fi
    prev_xdp_drop=$cur_xdp_drop
    
    # 7. Iptables
    cur_ipt_drop=$(iptables -nvL | grep "DROP" | awk '{sum+=$1} END {print sum+0}' || true)
    if [ -z "$cur_ipt_drop" ]; then cur_ipt_drop=0; fi
    delta_ipt_drop=$((cur_ipt_drop - prev_iptables_drop))
    # Chống âm khi flush rules
    if [ "$delta_ipt_drop" -lt 0 ]; then delta_ipt_drop=0; fi
    prev_iptables_drop=$cur_ipt_drop
    
    # Xuất ra CSV
    echo "$TS_MS,$cpu_usage,$delta_irq,$delta_soft_rx,$delta_soft_tx,$mem_used_mb,$delta_ext_pps,$delta_ext_bps,$ct_count,$ct_syn,$ct_tw,$delta_xdp_run,$delta_xdp_drop,$delta_ipt_drop" >> "$OUT_FILE"
    
    sleep 1
done
