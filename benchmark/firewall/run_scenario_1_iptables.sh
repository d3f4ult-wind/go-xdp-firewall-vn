#!/bin/bash
# =============================================================
# File: run_scenario_0_iptables.sh
# Chạy trên: VM firewall (10.10.1.1)
# Mục đích: Wrapper kịch bản 0 (Baseline) — CHỈ DÙNG IPTABLES
# Mô tả: Tắt hoàn toàn XDP (Tier 1 & Tier 2) để xem hệ thống Iptables
#        thuần túy chịu tải thế nào dưới đợt tấn công SYN Flood.
# =============================================================

SCENARIO="sc1_iptables_only"
ATTACK_SCRIPT="attack_sc1_botnet_v2.sh"
FW_API="http://localhost:8080"

echo "=========================================================="
echo " CHUẨN BỊ KỊCH BẢN 0 (BASELINE): IPTABLES ONLY"
echo " Mô tả: Tắt XDP. Chỉ dùng Iptables chống SYN Flood."
echo "=========================================================="

# --- PRE-FLIGHT 1: Kiểm tra firewall API ---
echo "[*] Kiểm tra Firewall API (localhost:8080)..."
if ! curl -s --max-time 2 "$FW_API/health" > /dev/null 2>&1; then
    echo "[!] LỖI NGHIÊM TRỌNG: Firewall API không phản hồi tại $FW_API"
    echo "    Hãy đảm bảo đã khởi động go-xdp-firewall trước khi chạy benchmark."
    exit 1
fi
echo "    [+] Firewall API OK."

# --- PRE-FLIGHT 2: TẮT XDP ENFORCEMENT ---
echo "[*] Tắt XDP Enforcement (Unload eBPF)..."
curl -s -X POST "$FW_API/enforcement" \
    -H "Content-Type: application/json" \
    -d '{"enabled": false}' > /dev/null
echo "    [+] XDP Enforcement = OFF."

# --- PRE-FLIGHT 3: Tắt kernel SYN Cookie (đảm bảo Baseline thuần túy) ---
echo "[*] Tắt kernel SYN Cookie (đảm bảo môi trường Iptables gốc)..."
sysctl -w net.ipv4.tcp_syncookies=0 > /dev/null
echo "    [+] SYN Cookie = OFF."

# --- PRE-FLIGHT 4: Thêm Legit Client vào iptables WHITELIST_SET ---
LEGIT_IP="10.10.1.3"
echo "[*] Thêm Legit Client ($LEGIT_IP) vào iptables WHITELIST (ipset ddos_whitelist)..."
ipset add ddos_whitelist "$LEGIT_IP" 2>/dev/null || true
echo "    [+] $LEGIT_IP đã được whitelist trong iptables."

echo ""
echo "[*] Pre-flight hoàn tất. Bắt đầu sau 3 giây..."
sleep 3

# --- Gọi Master Orchestrator ---
bash ./orchestrate.sh "$SCENARIO" "$ATTACK_SCRIPT"
