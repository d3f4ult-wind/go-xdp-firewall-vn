#!/bin/bash
# =============================================================
# File: setup_netns.sh
# Chạy trên: VM attacker (10.10.1.2)
# Mục đích: Tạo network namespace 'legit_client' với IP 10.10.1.3
#           để giả lập user hợp lệ gửi request độc lập với IP tấn công.
# Input: Không
# Output: Namespace legit_client
# Gọi bởi: Chạy độc lập 1 lần trước khi test
# =============================================================

if [ "$EUID" -ne 0 ]; then
  echo "Vui lòng chạy bằng quyền root (sudo)"
  exit 1
fi

set -euo pipefail

# ================= CẤU HÌNH =================
OUT_IFACE="enp0s8"          # Interface vật lý nối tới Firewall
FW_IP="10.10.1.1"           # IP Firewall phía Attacker
VICTIM_NET="10.10.2.0/24"   # Mạng phía Victim

# Khai báo danh sách Namespace và IP tương ứng
declare -A NS_LIST=(
    ["legit"]="10.10.1.3"
    ["ns6"]="10.10.1.6"
    ["ns7"]="10.10.1.7"
    ["ns8"]="10.10.1.8"
    ["ns9"]="10.10.1.9"
    ["ns10"]="10.10.1.10"
)
TRANSIT_PREFIX="10.254.0"   # Dải IP transit nội bộ
IDX=10

# ================= DỌN DẸP =================
echo "[*] Đang dọn dẹp namespace/veth cũ và route cũ..."
for ns in "${!NS_LIST[@]}"; do
    ip netns del $ns 2>/dev/null || true
    ip link del "veth_${ns}" 2>/dev/null || true
    ip route del "${NS_LIST[$ns]}/32" 2>/dev/null || true
done
# Xóa sạch các route rác từ lần chạy trước (của script cũ) bị kẹt
ip route flush root 10.254.0.0/24 2>/dev/null || true

# ================= SYSCTL TOÀN CỤC =================
echo "[*] Điều chỉnh sysctl kernel cho lab DDoS..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.${OUT_IFACE}.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.${OUT_IFACE}.accept_local=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.all.accept_local=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.${OUT_IFACE}.proxy_arp=1 >/dev/null 2>&1 || true

# ================= ROUTE TRÊN HOST =================
echo "[*] Thiết lập route tới Victim qua Firewall..."
ip route add ${VICTIM_NET} via ${FW_IP} dev ${OUT_IFACE} 2>/dev/null || true

# ================= TẠO NAMESPACE & VETH =================
echo "[*] Đang tạo namespaces..."
for ns in "${!NS_LIST[@]}"; do
    ATTACK_IP="${NS_LIST[$ns]}"
    VETH_HOST="veth_${ns}"
    VETH_NS="veth_${ns}_in"
    
    # Sinh IP transit hợp lệ
    HOST_VETH_IP="${TRANSIT_PREFIX}.${IDX}"

    echo "[+] Thiết lập $ns (IP: $ATTACK_IP)..."

    # 1. Tạo netns và veth pair
    ip netns add $ns
    ip link add $VETH_HOST type veth peer name $VETH_NS
    ip link set $VETH_NS netns $ns

    # 2. Cấu hình TRONG netns
    ip netns exec $ns ip addr add ${ATTACK_IP}/32 dev $VETH_NS
    ip netns exec $ns ip link set $VETH_NS up
    ip netns exec $ns ip link set lo up
    # Route default trỏ về host
    ip netns exec $ns ip route add default via ${HOST_VETH_IP} dev $VETH_NS onlink

    # 3. Cấu hình TRÊN HOST
    ip addr add ${HOST_VETH_IP}/30 dev $VETH_HOST
    ip link set $VETH_HOST up
    ip link set $VETH_HOST txqueuelen 10000
    # Xóa route cũ bị kẹt nếu có và định hướng lại
    ip route del ${ATTACK_IP}/32 2>/dev/null || true
    ip route add ${ATTACK_IP}/32 dev $VETH_HOST

    # 4. Sysctl riêng cho veth host
    sysctl -w net.ipv4.conf.${VETH_HOST}.proxy_arp=1 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.${VETH_HOST}.accept_local=1 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.${VETH_HOST}.rp_filter=0 >/dev/null 2>&1 || true

    echo "    ↳ $ns: ${ATTACK_IP} -> ${HOST_VETH_IP} -> ${OUT_IFACE}"
    IDX=$((IDX + 2))
done

echo "[OK] Setup Netns hoàn tất."
echo "[*] Đang kiểm tra ping tới Victim (10.10.2.2)..."
for ns in "${!NS_LIST[@]}"; do
    ip netns exec $ns ping -c 1 -W 1 10.10.2.2 >/dev/null 2>&1 && echo "    [+] Ping từ $ns OK" || echo "    [-] Ping từ $ns FAILED"
done
