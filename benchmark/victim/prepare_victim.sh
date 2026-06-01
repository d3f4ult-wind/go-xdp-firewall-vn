#!/bin/bash
# ==============================================================================
# Script: prepare_victim.sh
# Mục đích: Dọn dẹp Victim trước mỗi lần Benchmark
# Chạy trên: Victim VM
# ==============================================================================

if [ "$EUID" -ne 0 ]; then
  echo "Vui lòng chạy bằng quyền root (sudo)"
  exit 1
fi

echo "[*] Dọn dẹp log Apache2/Nginx..."
# (Tùy thuộc bạn dùng web server nào)
truncate -s 0 /var/log/apache2/access.log 2>/dev/null
truncate -s 0 /var/log/apache2/error.log 2>/dev/null
truncate -s 0 /var/log/nginx/access.log 2>/dev/null
truncate -s 0 /var/log/nginx/error.log 2>/dev/null

echo "[*] Restarting Web Server..."
systemctl restart apache2 2>/dev/null || systemctl restart nginx 2>/dev/null

echo "[+] Victim đã sẵn sàng!"
