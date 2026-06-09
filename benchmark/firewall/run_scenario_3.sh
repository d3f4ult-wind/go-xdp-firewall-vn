#!/bin/bash
# =============================================================
# File: run_scenario_3.sh
# Chạy trên: VM firewall (10.10.1.1)
# Mục đích: Wrapper kịch bản 3 — Slowloris Attack (L7)
# Kỳ vọng:
#   - XDP và Iptables KHÔNG chặn được vì traffic hoàn toàn hợp lệ ở L3/L4.
#   - Suricata (L7 IDS) sẽ bắt được pattern Slowloris và gọi API block IP.
#   - Watcher KHÔNG bật Tier 1 vì PPS của Slowloris cực kỳ thấp.
# =============================================================

SCENARIO="sc3_slowloris"
ATTACK_SCRIPT="attack_sc3_slowloris.sh"
FW_API="http://localhost:8080"
LEGIT_IP="10.10.1.3"

echo "=========================================================="
echo " CHUẨN BỊ KỊCH BẢN 3: SLOWLORIS ATTACK (LAYER 7)"
echo " Mô tả: Tấn công cạn kiệt kết nối Web Server ở tốc độ chậm."
echo " Kỳ vọng: XDP Tier 1 bỏ qua. Iptables IPS (Suricata) phát hiện"
echo "          và cập nhật blocklist. Legit client phục hồi."
echo "=========================================================="

# --- PRE-FLIGHT 1: Kiểm tra watcher ---
echo "[*] Kiểm tra Firewall API..."
if ! curl -s --max-time 2 "$FW_API/health" > /dev/null 2>&1; then
    echo "[!] LỖI NGHIÊM TRỌNG: Firewall API không phản hồi tại $FW_API"
    exit 1
fi

# --- PRE-FLIGHT 2: Bật XDP Enforcement ---
echo "[*] Bật XDP Enforcement..."
curl -s -X POST "$FW_API/enforcement" -H "Content-Type: application/json" -d '{"enabled": true}' > /dev/null

# --- PRE-FLIGHT 3: Reset Tier 1 về Level 0 (Tắt Adaptive Mitigation) ---
echo "[*] Reset Tier 1 Mitigation về Level 0 (vì PPS của Slowloris rất thấp)..."
curl -s -X POST "$FW_API/tier1/watcher" -H "Content-Type: application/json" -d '{"auto_mode": false}' > /dev/null
curl -s -X POST "$FW_API/tier1/mitigation" -H "Content-Type: application/json" -d '{"level":0,"syn_drop":0,"udp_drop":0,"icmp_drop":0,"geo_syn_drop":0,"geo_udp_drop":0,"geo_icmp_drop":0}' > /dev/null

# --- PRE-FLIGHT 4: Xóa toàn bộ Blocklist cũ ---
echo "[*] Dọn dẹp IP Blocklist cũ để sẵn sàng test Suricata..."
# Lấy danh sách rule cũ và xóa (có thể sẽ phức tạp nếu có quá nhiều rule, tạm thời gọi API clear nếu có, hoặc khởi động lại FW)
# Để an toàn, hãy chắc chắn bạn đã restart Firewall daemon trước khi chạy kịch bản này.

# --- PRE-FLIGHT 5: Whitelist Legit Client ---
echo "[*] Whitelist Legit Client ($LEGIT_IP) trong Iptables..."
ipset add ddos_whitelist "$LEGIT_IP" 2>/dev/null || true

# --- PRE-FLIGHT 6: Bật BPF Stats ---
sysctl -w kernel.bpf_stats_enabled=1 > /dev/null

echo ""
echo "[*] Pre-flight hoàn tất. Chờ Suricata phát hiện và block Slowloris."
echo "[*] Bắt đầu sau 3 giây..."
sleep 3

# --- Gọi Master Orchestrator ---
bash ./orchestrate.sh "$SCENARIO" "$ATTACK_SCRIPT"

# --- POST CLEANUP ---
echo "[*] POST: Dọn dẹp sau kịch bản 3..."
echo "    [+] Cleanup hoàn tất."
