#!/bin/bash
# =============================================================
# File: attack_sc3_slowloris.sh
# Chạy trên: VM attacker (10.10.1.2)
# Mục đích: Kích hoạt cuộc tấn công cạn kiệt kết nối (Slowloris)
# =============================================================

echo "[*] [ATTACKER] Đang chuẩn bị tấn công Slowloris (L7)..."

# Xóa các tiến trình slowloris cũ nếu có
sudo pkill -9 -f slowloris 2>/dev/null || true

# Gọi script slowloris.sh chạy ở chế độ nền
bash $(dirname "$0")/slowloris.sh > /dev/null 2>&1 &

echo "[*] [ATTACKER] KỊCH BẢN 3 ĐÃ KÍCH HOẠT! Slowloris đang vắt kiệt kết nối Web Server..."
