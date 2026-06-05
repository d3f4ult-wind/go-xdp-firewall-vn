#!/bin/bash
# ==============================================================================
# Script: orchestrate.sh
# Mục đích: Điều phối kịch bản 150 giây (5 Phase) trên máy Firewall
# Cách dùng: sudo ./orchestrate.sh --mode hybrid
# ==============================================================================

if [ "$EUID" -ne 0 ]; then
  echo "Vui lòng chạy bằng quyền root (sudo)"
  exit 1
fi

MODE="hybrid"
if [ "$1" == "--mode" ]; then
    MODE=$2
fi

echo "=========================================================="
echo " KHỞI ĐỘNG BENCHMARK - CHẾ ĐỘ: $MODE"
echo "=========================================================="

# 0. Chuẩn bị thư mục kết quả
TS=$(date +"%Y%m%d_%H%M%S")
OUT_DIR="benchmark_results_${TS}_${MODE}"
mkdir -p "$OUT_DIR"
EVENT_LOG="$OUT_DIR/timeline_events.csv"
echo "timestamp_unix_ms,event_name,note" > $EVENT_LOG

# Hàm tiện ích log sự kiện
log_event() {
    TS_MS=$(date +%s%3N)
    echo "$TS_MS,$1,$2" >> $EVENT_LOG
    echo "[$TS_MS] EVENT: $1 ($2)"
}

# 1. Thu thập thông tin hệ thống ban đầu
echo "[*] Đang thu thập system_snapshot..."
lscpu > "$OUT_DIR/system_snapshot.txt"
free -h >> "$OUT_DIR/system_snapshot.txt"
uname -a >> "$OUT_DIR/system_snapshot.txt"

# 2. Ép Iptables chết dễ hơn (Theo kế hoạch đã bàn)
sysctl -w net.netfilter.nf_conntrack_max=10000 > /dev/null

# 3. TẮT TÍNH NĂNG BẢO VỆ XDP ĐỂ BẮT ĐẦU CHẠY BASELINE (Giây 0 -> 90)
./firewall/toggle_enforcement.sh 0
log_event "PHASE_0_START" "XDP Enforcement = OFF"

# 4. Kích hoạt ngầm bộ thu thập Metric 
./firewall/collect_metrics.sh "$OUT_DIR" &
COLLECT_PID=$!

echo "[*] Đang ghi Metric. Vui lòng mở máy Attacker và chuẩn bị chạy Script trong vòng 30 giây tới..."

# Đếm ngược 90 giây đầu tiên (Phase 0 -> Phase 1 -> Phase 2)
for i in {1..90}; do
    sleep 1
    if [ $i -eq 30 ]; then
        log_event "PHASE_1_NORMAL" "Normal User (wrk) nên bắt đầu lúc này"
    fi
    if [ $i -eq 60 ]; then
        log_event "PHASE_2_ATTACK" "Attack (hping3) nên bắt đầu lúc này"
    fi
done

# Tại Giây 90: Đột ngột giơ khiên XDP lên đỡ (CÔNG TẮC VÀNG)
log_event "PHASE_3_DEFENSE_TRIGGER" "Đang bật XDP Enforcement!"
./firewall/toggle_enforcement.sh 1
log_event "PHASE_3_DEFENSE_ACTIVE" "XDP Enforcement = ON"

# Chờ 60 giây cuối cùng (Phase 3 -> Phase 4)
for i in {91..150}; do
    sleep 1
    if [ $i -eq 120 ]; then
        log_event "PHASE_4_RECOVERY" "Attack nên đã dừng lúc này"
    fi
done

log_event "BENCHMARK_END" "Hoàn tất 150 giây"

# Dọn dẹp
kill $COLLECT_PID
wait $COLLECT_PID 2>/dev/null

echo "=========================================================="
echo " ĐÃ HOÀN TẤT! Kết quả được lưu tại: $OUT_DIR"
echo "=========================================================="
