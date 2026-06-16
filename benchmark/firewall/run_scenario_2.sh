#!/bin/bash
# =============================================================
# File: run_scenario_2.sh
# Chạy trên: VM firewall (10.10.1.1)
# Mục đích: Wrapper kịch bản 2 — Random Source SYN Flood
# Kỳ vọng:
#   - 5 luồng hping3 --rand-source qua ns6..ns10 → rate limit per-IP vô dụng
#   - Watcher AutoMode bật → đọc mitigation_stats → avgPps vượt watermark
#   - Tier 1 escalate lên Level 1/2/3 → XDP probabilistic drop SYN
#   - Legit Client (10.10.1.3 trong trusted_map) KHÔNG bị drop
# =============================================================

SCENARIO="sc2_random"
ATTACK_SCRIPT="attack_sc2_random_v2.sh"
FW_API="http://localhost:8080"
# IP legit client trong netns "legit" — cần bypass Tier 1
LEGIT_IP="10.10.1.3"

echo "=========================================================="
echo " CHUẨN BỊ KỊCH BẢN 2: RANDOM SOURCE SYN FLOOD"
echo " Mô tả: 5 luồng hping3 --rand-source → Tier 1 adaptive drop"
echo " Kỳ vọng: Watcher escalate level, XDP Drop tăng dần,"
echo "          Legit Client vẫn truy cập được nhờ trusted_map."
echo "=========================================================="

# --- PRE-FLIGHT 1: Kiểm tra watcher ---
echo "[*] Kiểm tra Firewall API (localhost:8080)..."
if ! curl -s --max-time 2 "$FW_API/health" > /dev/null 2>&1; then
    echo "[!] LỖI NGHIÊM TRỌNG: Firewall API không phản hồi tại $FW_API"
    exit 1
fi
echo "    [+] Firewall API OK."

# --- PRE-FLIGHT 2: Bật XDP Enforcement ---
echo "[*] Bật XDP Enforcement..."
curl -s -X POST "$FW_API/enforcement" \
    -H "Content-Type: application/json" \
    -d '{"enabled": true}' > /dev/null
echo "    [+] Enforcement = ON."

# --- PRE-FLIGHT 3: Đặt Rate Limit threshold cao ---
# Với rand-source, mỗi IP chỉ gửi ~2 PPS → rate limit không bao giờ trigger.
# Đặt cao để chắc chắn không ảnh hưởng số liệu.
echo "[*] Đặt XDP Rate Limit threshold = 100000 PPS..."
curl -s -X POST "$FW_API/ratelimit/config" \
    -H "Content-Type: application/json" \
    -d '{"pps": 100000, "window_ms": 1000}' > /dev/null
echo "    [+] Rate Limit threshold = 100000 PPS."

# --- PRE-FLIGHT 4: Reset Tier 1 về Level 0 ---
echo "[*] Reset Tier 1 Mitigation về Level 0 (baseline sạch)..."
curl -s -X POST "$FW_API/tier1/mitigation" \
    -H "Content-Type: application/json" \
    -d '{"level":0,"syn_drop":0,"udp_drop":0,"icmp_drop":0,"geo_syn_drop":0,"geo_udp_drop":0,"geo_icmp_drop":0}' > /dev/null
echo "    [+] Tier 1 = Level 0."

# --- PRE-FLIGHT 5: Thêm Legit Client vào trusted_map (bypass Tier 1) ---
# Legit Client chạy trong netns "legit" với IP 10.10.1.3.
# Phải thêm vào trusted_map TRƯỚC khi Tier 1 bắt đầu drop,
# để dù escalate lên Level 3 (drop 100%), legit vẫn qua được.
echo "[*] Thêm Legit Client IP ($LEGIT_IP) vào trusted_map (bypass Tier 1)..."
TRUSTED_RESP=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$FW_API/tier1/trusted" \
    -H "Content-Type: application/json" \
    -d "{\"ip\": \"$LEGIT_IP\"}")
if [ "$TRUSTED_RESP" = "200" ]; then
    echo "    [+] $LEGIT_IP đã được thêm vào trusted_map."
else
    echo "    [!] CẢNH BÁO: Không thêm được trusted IP (HTTP $TRUSTED_RESP). Legit có thể bị drop!"
fi

# --- Thêm Legit vào iptables WHITELIST (ipset) ---
# Không có bước này, packet của legit rơi vào DROP-DEFAULT
# → IptablesTailer block chính legit trước cả attacker!
echo "[*] Thêm Legit Client ($LEGIT_IP) vào iptables WHITELIST (ipset ddos_whitelist)..."
ipset add ddos_whitelist "$LEGIT_IP" 2>/dev/null || true
echo "    [+] $LEGIT_IP đã được whitelist trong iptables."

# --- PRE-FLIGHT 6: Bật Tier 1 AutoMode (Watcher sẽ tự escalate) ---
echo "[*] Bật Tier 1 AutoMode (Watcher sẽ tự điều chỉnh Protection Level)..."
curl -s -X POST "$FW_API/tier1/watcher" \
    -H "Content-Type: application/json" \
    -d '{"auto_mode": true}' > /dev/null
echo "    [+] AutoMode = ON."

# --- PRE-FLIGHT 7: Bật BPF Stats (BẮT BUỘC để đo xdp_run_pps / xdp_drop_pps) ---
# Nếu thiếu lệnh này, bpftool prog show trả về run_cnt=0 mãi mãi
# → Biểu đồ "Năng lực đánh chặn" sẽ trống hoàn toàn dù XDP đang hoạt động.
echo "[*] Bật BPF Program Stats (kernel.bpf_stats_enabled=1)..."
sysctl -w kernel.bpf_stats_enabled=1 > /dev/null
echo "    [+] BPF Stats = ON."


echo ""
echo "[*] Pre-flight hoàn tất. Watcher sẽ tự escalate khi phát hiện flood."
echo "[*] Bắt đầu sau 3 giây..."
sleep 3

# --- Gọi Master Orchestrator ---
bash ./orchestrate.sh "$SCENARIO" "$ATTACK_SCRIPT"

# --- POST: Tắt AutoMode sau khi benchmark xong ---
echo "[*] POST: Tắt AutoMode và reset Tier 1..."
curl -s -X POST "$FW_API/tier1/watcher" \
    -H "Content-Type: application/json" \
    -d '{"auto_mode": false}' > /dev/null
curl -s -X POST "$FW_API/tier1/mitigation" \
    -H "Content-Type: application/json" \
    -d '{"level":0,"syn_drop":0,"udp_drop":0,"icmp_drop":0,"geo_syn_drop":0,"geo_udp_drop":0,"geo_icmp_drop":0}' > /dev/null

# Xóa trusted IP sau khi test
curl -s -X DELETE "$FW_API/tier1/trusted" \
    -H "Content-Type: application/json" \
    -d "{\"ip\": \"$LEGIT_IP\"}" > /dev/null
echo "    [+] Cleanup POST hoàn tất."
