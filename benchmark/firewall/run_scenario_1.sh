#!/bin/bash
# =============================================================
# File: run_scenario_1.sh
# Chạy trên: VM firewall (10.10.1.1)
# Mục đích: Wrapper kịch bản 1 — Botnet giả mạo IP Trung Quốc
# Kỳ vọng:
#   - 5 IP CN mỗi IP gửi ~100 PPS SYN → vượt iptables threshold (30/s)
#   - Iptables LOG [FW-DOS]SYN-FLOOD → IptablesTailer bắt được
#   - GeoHeuristic đếm 4 IP CN → BlockCountry("CN") → auto_block_map
#   - Metric thấy: iptables_drop_per_sec tăng ban đầu, xdp_drop_pps tăng sau
# =============================================================

SCENARIO="sc1_botnet"
ATTACK_SCRIPT="attack_sc1_botnet.sh"
FW_API="http://localhost:8080"

echo "=========================================================="
echo " CHUẨN BỊ KỊCH BẢN 1: BOTNET GEO SPOOFING (TRUNG QUỐC)"
echo " Mô tả: 5 IP CN nã SYN Flood → Iptables LOG → GeoHeuristic"
echo "        → BlockCountry(CN) → XDP Drop theo LPM subnet CN"
echo "=========================================================="

# --- PRE-FLIGHT 1: Kiểm tra watcher (third_party_code) đang chạy ---
echo "[*] Kiểm tra third_party_code watcher..."
if ! pgrep -f "go run" > /dev/null 2>&1 && ! pgrep -f "watcher" > /dev/null 2>&1; then
    echo "[!] CẢNH BÁO: Không tìm thấy watcher process!"
    echo "    Hãy đảm bảo đã chạy: cd third_party_code/cmd/watcher && sudo go run ."
    echo "    Nhấn Enter để tiếp tục nếu bạn chắc chắn watcher đang chạy, Ctrl+C để hủy."
    read -r
else
    echo "    [+] Watcher đang chạy."
fi

# --- PRE-FLIGHT 2: Kiểm tra firewall API ---
echo "[*] Kiểm tra Firewall API (localhost:8080)..."
if ! curl -s --max-time 2 "$FW_API/health" > /dev/null 2>&1; then
    echo "[!] LỖI NGHIÊM TRỌNG: Firewall API không phản hồi tại $FW_API"
    echo "    Hãy đảm bảo đã khởi động go-xdp-firewall trước khi chạy benchmark."
    exit 1
fi
echo "    [+] Firewall API OK."

# --- PRE-FLIGHT 3: Bật XDP Enforcement ---
echo "[*] Bật XDP Enforcement (chế độ hoạt động)..."
curl -s -X POST "$FW_API/enforcement" \
    -H "Content-Type: application/json" \
    -d '{"enabled": true}' > /dev/null
echo "    [+] Enforcement = ON."

# --- PRE-FLIGHT 4: Đặt Rate Limit threshold RẤT CAO ---
# Mục đích: Đảm bảo gói CN (100 PPS/IP) KHÔNG bị XDP rate limit chặn trước.
# Phải để iptables thấy và LOG trước → IptablesTailer mới hoạt động.
# threshold = 100000 PPS, window = 1000ms
echo "[*] Đặt XDP Rate Limit threshold = 100000 PPS (để bypass cho SC1)..."
curl -s -X POST "$FW_API/ratelimit/config" \
    -H "Content-Type: application/json" \
    -d '{"pps": 100000, "window_ms": 1000}' > /dev/null
echo "    [+] Rate Limit threshold = 100000 PPS."

# --- PRE-FLIGHT 5: Tắt Tier 1 AutoMode (SC1 dùng Tier 2, không cần Tier 1) ---
echo "[*] Tắt Tier 1 AutoMode (SC1 chỉ cần Tier 2 hoạt động)..."
curl -s -X POST "$FW_API/tier1/watcher" \
    -H "Content-Type: application/json" \
    -d '{"auto_mode": false}' > /dev/null
echo "    [+] AutoMode = OFF."

echo ""
echo "[*] Pre-flight hoàn tất. Bắt đầu sau 3 giây..."
sleep 3

# --- Gọi Master Orchestrator ---
bash ./orchestrate.sh "$SCENARIO" "$ATTACK_SCRIPT"
