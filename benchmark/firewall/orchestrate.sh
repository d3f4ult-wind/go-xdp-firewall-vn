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

echo "=========================================================="
echo " KHỞI ĐỘNG BENCHMARK: $SCENARIO"
echo "=========================================================="

# 0. Kiểm tra SSH
echo "[*] Kiểm tra kết nối SSH tới Attacker và Victim..."
ssh -o BatchMode=yes -o ConnectTimeout=2 $USER@$ATTACKER_IP "echo 'SSH Attacker OK'" || { echo "[ERROR] Không thể SSH Attacker"; exit 1; }
ssh -o BatchMode=yes -o ConnectTimeout=2 $USER@$VICTIM_IP "echo 'SSH Victim OK'" || { echo "[ERROR] Không thể SSH Victim"; exit 1; }

# 1. Bật Metric Collector
echo "[*] Kích hoạt Firewall Metric Collector..."
./collect_metrics_fw.sh "$SCENARIO" > /dev/null 2>&1 &
FW_PID=$!

echo "[*] Kích hoạt Apache Monitor (Victim VM)..."
ssh $USER@$VICTIM_IP "nohup $REMOTE_DIR/victim/monitor_apache.sh $SCENARIO >/tmp/mon.log 2>&1 &"

echo "[*] Kích hoạt Legitimate Client (Attacker VM) trong netns legit_client..."
ssh $USER@$ATTACKER_IP "nohup ip netns exec legit_client python3 $REMOTE_DIR/attacker/legit_client.py $SCENARIO >/tmp/legit.log 2>&1 &"

log_event "baseline_start" "Bắt đầu đo Baseline 30s"
sleep 30

# 2. Phát động tấn công
log_event "attack_start" "Phát động tấn công từ Attacker VM"
ssh $USER@$ATTACKER_IP "nohup $REMOTE_DIR/attacker/$ATTACK_SCRIPT >/tmp/attack.log 2>&1 &"
if [ $? -eq 0 ]; then
    echo "[OK] Đã gửi lệnh tấn công thành công!"
else
    echo "[ERROR] Lệnh SSH phát động tấn công thất bại!"
    # Vẫn tiếp tục hoặc exit tùy bạn
fi

# Chờ 15s để xem XDP bật chưa
sleep 15
log_event "mitigation_active" "Kiểm tra XDP Drop/Iptables Drop Rate"

# Chờ nốt 15s của pha Attack
sleep 15

# 3. Dừng tấn công
log_event "attack_stop" "Gửi lệnh dừng tấn công"
ssh $USER@$ATTACKER_IP "pkill hping3; pkill python; pkill slowloris"

# 4. Recovery
log_event "recovery_start" "Bắt đầu đo Recovery 30s"
sleep 30
log_event "recovery_complete" "Hoàn tất Benchmark"

# 5. Dọn dẹp & Kéo file về
echo "[*] Dọn dẹp tiến trình..."
kill $FW_PID
ssh $USER@$VICTIM_IP "pkill -f monitor_apache.sh"
ssh $USER@$ATTACKER_IP "pkill -f legit_client.py"

echo "[*] Đang thu thập CSV từ các VM về Firewall..."
scp $USER@$VICTIM_IP:/tmp/apache_status_${SCENARIO}_*.csv $OUT_DIR/ 2>/dev/null
scp $USER@$ATTACKER_IP:/tmp/legit_${SCENARIO}_*.csv $OUT_DIR/ 2>/dev/null
mv /tmp/metrics_firewall_${SCENARIO}_*.csv $OUT_DIR/

echo "=========================================================="
echo " ĐÃ HOÀN TẤT! Kết quả được lưu tại: $OUT_DIR"
echo "=========================================================="
