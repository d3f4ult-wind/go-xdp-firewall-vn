#!/bin/bash
# =============================================================
# File: orchestrate.sh
# Chạy trên: VM firewall (10.10.1.1)
# Mục đích: Master controller để điều phối 3 VMs, đồng bộ thời
#           gian, thu thập log, và đánh dấu sự kiện.
# Input: $1 (Tên Scenario, VD: sc1_botnet)
#        $2 (Tên script chạy trên Attacker VM, VD: attack_sc1.sh)
# Output: Thư mục results_SCENARIO_TIMESTAMP/
# Gọi bởi: run_scenario_X.sh
# =============================================================

SCENARIO=$1
ATTACK_SCRIPT=$2

if [ -z "$SCENARIO" ] || [ -z "$ATTACK_SCRIPT" ]; then
    echo "Usage: ./orchestrate.sh <scenario_name> <attack_script_name>"
    exit 1
fi

ATTACKER_IP="10.10.1.2"
VICTIM_IP="10.10.2.2"
USER="kali" # Cần sửa lại user nếu ssh user khác
REMOTE_DIR="~/go-xdp-firewall-vn/benchmark" # Thư mục chứa code trên các VM

TS=$(date +"%Y%m%d_%H%M%S")
OUT_DIR="results_${SCENARIO}_${TS}"
mkdir -p "$OUT_DIR"
EVENT_LOG="$OUT_DIR/timeline_events.csv"
echo "timestamp_unix_ms,event_name,note" > $EVENT_LOG

log_event() {
    TS_MS=$(date +%s%3N)
    echo "$TS_MS,$1,$2" >> $EVENT_LOG
    echo "[$TS_MS] EVENT: $1 ($2)"
}

check_remote_process() {
    local ip=$1
    local proc_name=$2
    local desc=$3
    
    # Chờ 2s để tiến trình kịp bung ra
    sleep 2
    ssh -o BatchMode=yes $USER@$ip "pgrep -f '$proc_name' >/dev/null"
    if [ $? -eq 0 ]; then
        echo "    [+] XÁC NHẬN: $desc ĐANG CHẠY."
    else
        echo "    [!] LỖI NGHIÊM TRỌNG: $desc KHÔNG CHẠY! (Hãy check log /tmp trên $ip)"
        # Tùy chọn: Thêm 'exit 1' nếu muốn dừng khẩn cấp
    fi
}

echo "=========================================================="
echo " KHỞI ĐỘNG BENCHMARK: $SCENARIO"
echo "=========================================================="

# 0. Kiểm tra SSH
echo "[*] Kiểm tra kết nối SSH tới Attacker và Victim..."
ssh -o BatchMode=yes -o ConnectTimeout=2 $USER@$ATTACKER_IP "echo 'SSH Attacker OK'" || { echo "[ERROR] Không thể SSH Attacker"; exit 1; }
ssh -o BatchMode=yes -o ConnectTimeout=2 $USER@$VICTIM_IP "echo 'SSH Victim OK'" || { echo "[ERROR] Không thể SSH Victim"; exit 1; }

# 0.5. Dọn dẹp file CSV/Log cũ trên /tmp
echo "[*] Dọn dẹp file rác từ các kịch bản trước trên cả 3 VM..."
ssh $USER@$ATTACKER_IP "sudo rm -f /tmp/legit_*.csv /tmp/wrk_*.csv /tmp/*.log"
ssh $USER@$VICTIM_IP "sudo rm -f /tmp/apache_status_*.csv /tmp/*.log"
sudo rm -f /tmp/metrics_firewall_*.csv /tmp/collector_*.log

# 1. Bật Metric Collector
echo "[*] Kích hoạt Firewall Metric Collector..."
COLLECTOR_LOG="/tmp/collector_${SCENARIO}.log"
bash ./collect_metrics_fw.sh "$SCENARIO" > "$COLLECTOR_LOG" 2>&1 &
FW_PID=$!
sleep 2
if ps -p $FW_PID > /dev/null; then
    echo "    [+] XÁC NHẬN: Firewall Collector ĐANG CHẠY (PID=$FW_PID, log: $COLLECTOR_LOG)."
else
    echo "    [!] LỖI NGHIÊM TRỌNG: Firewall Collector KHÔNG CHẠY! Xem log: $COLLECTOR_LOG"
fi

echo "[*] Kích hoạt Apache Monitor (Victim VM)..."
ssh $USER@$VICTIM_IP "nohup sudo bash $REMOTE_DIR/victim/monitor_apache.sh $SCENARIO >/tmp/mon.log 2>&1 &"
check_remote_process $VICTIM_IP "monitor_apache.sh" "Apache Monitor"

echo "[*] Kích hoạt Legitimate Client (Attacker VM) trong netns legit..."
ssh $USER@$ATTACKER_IP "nohup sudo ip netns exec legit python3 $REMOTE_DIR/attacker/legit_client.py $SCENARIO >/tmp/legit.log 2>&1 &"
check_remote_process $ATTACKER_IP "legit_client.py" "Legitimate Client"

echo "[*] Kích hoạt WRK Throughput Monitor (Attacker VM) trong netns legit..."
ssh $USER@$ATTACKER_IP "nohup sudo ip netns exec legit bash $REMOTE_DIR/attacker/wrk_monitor_v2.sh $SCENARIO >/tmp/wrk_mon.log 2>&1 &"
check_remote_process $ATTACKER_IP "wrk_monitor_v2.sh" "WRK Monitor"

log_event "baseline_start" "Bắt đầu đo Baseline 30s"
sleep 30

# 2. Phát động tấn công
log_event "attack_start" "Phát động tấn công từ Attacker VM"
ssh $USER@$ATTACKER_IP "nohup sudo bash $REMOTE_DIR/attacker/$ATTACK_SCRIPT >/tmp/attack.log 2>&1 &"
check_remote_process $ATTACKER_IP "$ATTACK_SCRIPT" "Mã nguồn Tấn công ($ATTACK_SCRIPT)"

# Chờ 15s để xem XDP bật chưa
sleep 15
log_event "mitigation_active" "Kiểm tra XDP Drop/Iptables Drop Rate"

# Chờ nốt 15s của pha Attack
sleep 15

# 3. Dừng tấn công
log_event "attack_stop" "Gửi lệnh dừng tấn công"
# sudo pkill vì hping3 chạy bằng root (operation not permitted nếu không có sudo)
ssh $USER@$ATTACKER_IP "sudo pkill -9 hping3 2>/dev/null; sudo pkill -9 -f hping3_cidr.sh 2>/dev/null; sudo pkill -9 -f slowloris 2>/dev/null" || true

# 4. Recovery
log_event "recovery_start" "Bắt đầu đo Recovery 30s"
sleep 30
log_event "recovery_complete" "Hoàn tất Benchmark"

# 5. Dọn dẹp & Kéo file về
echo "[*] Dọn dẹp tiến trình..."
kill $FW_PID
ssh $USER@$VICTIM_IP "sudo pkill -f monitor_apache.sh 2>/dev/null" || true
ssh $USER@$ATTACKER_IP "sudo pkill -f legit_client.py 2>/dev/null; sudo pkill -f wrk_monitor_v2.sh 2>/dev/null; sudo pkill wrk 2>/dev/null" || true

echo "[*] Đang thu thập CSV từ các VM về Firewall..."
scp $USER@$VICTIM_IP:/tmp/apache_status_${SCENARIO}_*.csv "$OUT_DIR/" 2>/dev/null || true
scp $USER@$ATTACKER_IP:/tmp/legit_${SCENARIO}_*.csv "$OUT_DIR/" 2>/dev/null || true
scp $USER@$ATTACKER_IP:/tmp/wrk_${SCENARIO}_*.csv "$OUT_DIR/" 2>/dev/null || true
# Di chuyển firewall metrics CSV (collector ghi vào /tmp)
mv /tmp/metrics_firewall_${SCENARIO}_*.csv "$OUT_DIR/" 2>/dev/null || echo "    [!] Không tìm thấy metrics_firewall CSV — collector có thể bị crash sớm."

echo "=========================================================="
echo " ĐÃ HOÀN TẤT! Kết quả được lưu tại: $OUT_DIR"
echo "=========================================================="
