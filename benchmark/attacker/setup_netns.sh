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

EXT_IFACE="enp0s8"
LEGIT_IP="10.10.1.3/24"
GATEWAY="10.10.1.1"

echo "[*] Xóa namespace cũ nếu có..."
ip netns del legit_client 2>/dev/null
ip link del macvlan-legit 2>/dev/null

echo "[*] Tạo namespace legit_client..."
ip netns add legit_client

echo "[*] Tạo macvlan interface nối với $EXT_IFACE..."
ip link add macvlan-legit link $EXT_IFACE type macvlan mode bridge

echo "[*] Gán macvlan vào namespace legit_client..."
ip link set macvlan-legit netns legit_client

echo "[*] Cấu hình IP $LEGIT_IP cho legit_client..."
ip netns exec legit_client ip addr add $LEGIT_IP dev macvlan-legit
ip netns exec legit_client ip link set macvlan-legit up
ip netns exec legit_client ip link set lo up

# Route traffic qua Firewall
ip netns exec legit_client ip route add default via $GATEWAY

echo "[OK] Setup Netns hoàn tất. Test ping tới Victim (10.10.2.2)..."
ip netns exec legit_client ping -c 2 10.10.2.2 || echo "[WARNING] Không ping được Victim. Hãy kiểm tra lại routing của Firewall VM."
