#!/bin/bash
# =============================================================
# File: run_scenario_2_iptables.sh
# Chạy trên: VM firewall (10.10.1.1)
# Mục đích: Wrapper kịch bản 2 (Baseline) — IPTABLES ONLY + RANDOM SOURCE SYN
# Mô tả: Tắt hoàn toàn XDP (Tier 1 & 2), thử nghiệm sức mạnh của Iptables 
#        (có bật kernel SYN Cookie) trước đợt tấn công SYN giả mạo IP ngẫu nhiên.
# =============================================================

SCENARIO="sc2_iptables_only"
ATTACK_SCRIPT="attack_sc2_random_v2.sh"
FW_API="http://localhost:8080"
LEGIT_IP="10.10.1.3"

echo "=========================================================="
echo " CHUẨN BỊ KỊCH BẢN 2 (BASELINE): IPTABLES ONLY + KERNEL SYN COOKIE"
echo " Mô tả: Tắt XDP. Bật tcp_syncookies = 1. Chống Random Source SYN Flood."
echo "=========================================================="

# --- PRE-FLIGHT 1: Kiểm tra firewall API ---
echo "[*] Kiểm tra Firewall API (localhost:8080)..."
if ! curl -s --max-time 2 "$FW_API/health" > /dev/null 2>&1; then
    echo "[!] LỖI NGHIÊM TRỌNG: Firewall API không phản hồi tại $FW_API"
    exit 1
fi

# --- PRE-FLIGHT 2: TẮT XDP ENFORCEMENT ---
echo "[*] Tắt XDP Enforcement (Unload eBPF)..."
curl -s -X POST "$FW_API/enforcement" -H "Content-Type: application/json" -d '{"enabled": false}' > /dev/null

# --- PRE-FLIGHT 3: BẬT kernel SYN Cookie ---
echo "[*] Bật kernel SYN Cookie (tcp_syncookies = 1)..."
sysctl -w net.ipv4.tcp_syncookies=1 > /dev/null

# --- PRE-FLIGHT 4: Whitelist Legit Client ---
echo "[*] Thêm Legit Client ($LEGIT_IP) vào iptables WHITELIST (ipset ddos_whitelist)..."
ipset add ddos_whitelist "$LEGIT_IP" 2>/dev/null || true

echo ""
echo "[*] Pre-flight hoàn tất. Bắt đầu sau 3 giây..."
sleep 3

# --- Gọi Master Orchestrator ---
bash ./orchestrate.sh "$SCENARIO" "$ATTACK_SCRIPT"
