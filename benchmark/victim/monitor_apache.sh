#!/bin/bash
# =============================================================
# File: monitor_apache.sh
# Chạy trên: VM victim (10.10.2.2)
# Mục đích: Đọc thông số server-status của Apache mỗi giây, ghi
#           vào file CSV và hiển thị realtime ra màn hình.
# Input: $1 (Tên Scenario để đặt tên file CSV, ví dụ "sc1")
# Output: apache_status_<SCENARIO>_<TIMESTAMP>.csv
# Gọi bởi: orchestrate.sh (thông qua SSH)
# =============================================================

SCENARIO=$1
if [ -z "$SCENARIO" ]; then
    SCENARIO="default"
fi

TS=$(date +"%Y%m%d_%H%M%S")
OUT_FILE="/tmp/apache_status_${SCENARIO}_${TS}.csv"

echo "timestamp_unix_ms,active_workers,idle_workers,total_connections,requests_per_sec" > $OUT_FILE
echo "[*] Bắt đầu theo dõi Apache. Ghi log ra: $OUT_FILE"
echo "-------------------------------------------------------------------------"
echo -e "TIME\t\tACTIVE\tIDLE\tCONN\tREQ/S"
echo "-------------------------------------------------------------------------"

while true; do
    TS_MS=$(date +%s%3N)
    
    # Lấy dữ liệu từ Apache server-status
    STATUS=$(curl -s "http://127.0.0.1/server-status?auto")
    
    if [ -z "$STATUS" ]; then
        # Apache bị sập hoặc không phản hồi
        ACTIVE=-1
        IDLE=-1
        CONN=-1
        REQPS=-1
    else
        ACTIVE=$(echo "$STATUS" | grep "BusyWorkers:" | awk '{print $2}')
        IDLE=$(echo "$STATUS" | grep "IdleWorkers:" | awk '{print $2}')
        CONN=$(echo "$STATUS" | grep "ConnsTotal:" | awk '{print $2}')
        REQPS=$(echo "$STATUS" | grep "ReqPerSec:" | awk '{print $2}')
        
        # Nếu ConnsTotal chưa có (tuỳ phiên bản Apache), lấy số tiến trình apache2
        if [ -z "$CONN" ]; then
            CONN=$(pgrep apache2 | wc -l)
        fi
        if [ -z "$REQPS" ]; then REQPS=0; fi
    fi
    
    # In ra terminal để quay màn hình
    echo -e "$(date +"%H:%M:%S")\t${ACTIVE}\t${IDLE}\t${CONN}\t${REQPS}"
    
    # Ghi vào CSV
    echo "$TS_MS,$ACTIVE,$IDLE,$CONN,$REQPS" >> $OUT_FILE
    
    sleep 1
done
