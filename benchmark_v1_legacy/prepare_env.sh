#!/bin/bash
# ==============================================================================
# Script: prepare_env.sh
# Mục đích: Tạo 4 Network Namespace cho Attacker (Chỉ chạy 1 lần)
# Máy đích: Attacker VM
# ==============================================================================

if [ "$EUID" -ne 0 ]; then
  echo "Vui lòng chạy bằng quyền root (sudo)"
  exit 1
fi

INTERFACE="enp0s8" # Hãy thay đổi nếu card mạng nối vào Firewall của bạn có tên khác!

# Hàm tạo namespace
setup_ns() {
    NS_NAME=$1
    IP_ADDR=$2
    
    echo "Đang tạo Namespace: $NS_NAME với IP: $IP_ADDR"
    
    ip netns add $NS_NAME
    
    # Tạo veth pair
    ip link add veth0_$NS_NAME type veth peer name veth1_$NS_NAME
    
    # Đưa veth1 vào namespace
    ip link set veth1_$NS_NAME netns $NS_NAME
    
    # Đặt IP cho veth1 trong ns
    ip netns exec $NS_NAME ip addr add $IP_ADDR/24 dev veth1_$NS_NAME
    ip netns exec $NS_NAME ip link set dev veth1_$NS_NAME up
    
    # Bật veth0 ở host
    ip link set dev veth0_$NS_NAME up
    
    # Bật NAT/Routing trên host (Giả sử br0 hoặc giao thức route tương ứng, 
    # phần này phụ thuộc cách bạn đấu nối lớp L2/L3 giữa host và các Netns)
    # Tạm thời cấu hình cơ bản, cần tùy chỉnh theo lab mạng của bạn.
}

# Tạo 4 ns
setup_ns ns_10 10.10.1.10
setup_ns ns_11 10.10.1.11
setup_ns ns_50 10.10.1.50
setup_ns ns_100 10.10.1.100

echo "Hoàn thành tạo môi trường Namespace!"
