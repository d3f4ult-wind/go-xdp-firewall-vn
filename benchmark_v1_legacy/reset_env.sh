#!/bin/bash
# ==============================================================================
# Script: reset_env.sh
# Mục đích: Dọn dẹp conntrack, eBPF map trước mỗi lần Benchmark
# Máy đích: Firewall VM
# ==============================================================================

if [ "$EUID" -ne 0 ]; then
  echo "Vui lòng chạy bằng quyền root (sudo)"
  exit 1
fi

echo "============================================="
echo "[+] Reset Môi trường Benchmark"
echo "============================================="

# 1. Xóa sách bảng Conntrack
echo "[*] Đang flush conntrack table..."
conntrack -F

# 2. Xóa Log cũ của Suricata
echo "[*] Đang dọn dẹp Suricata log..."
truncate -s 0 /var/log/suricata/fast.log
truncate -s 0 /var/log/suricata/stats.log
truncate -s 0 /var/log/suricata/eve.json

# 3. Kêu gọi Restart XDP-Firewall (REST API call hoặc systemctl)
# Chú ý: Ở đây ta chỉ làm mẫu gọi API bật Enforcement. 
# Việc restart daemon tốt nhất là thao tác thủ công.
curl -s -X POST http://localhost:8080/enforcement -H "Content-Type: application/json" -d '{"enabled": false}'
echo ""
echo "[*] Đã tắt tính năng Enforcement (Bypass mode) qua REST API"

# 4. Flush cache (Để làm ấm lại CPU)
echo "[*] Giải phóng memory cache..."
sync; echo 3 > /proc/sys/vm/drop_caches

echo "[+] Sẵn sàng cho lần Benchmark mới!"
