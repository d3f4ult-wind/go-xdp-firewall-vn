#!/bin/bash
# =============================================================
# File: wrk_monitor_v2.sh
# Chạy trên: VM attacker (10.10.1.2) - Môi trường Network Namespace 'legit'
# Mục đích: Đo Throughput, Latency, Socket Errors, Success Rate
# Tham số V2: 4 threads, 10 connections, 10s duration, 2s nghỉ
# =============================================================

TARGET="http://10.10.2.2/"
OUT_FILE=${1:-"/tmp/wrk_log.csv"}

# --- CẤU HÌNH WRK V2 ---
WRK_THREADS=4
WRK_CONNS=10
WRK_DURATION=10
# -----------------------

echo "timestamp_unix_ms,req_per_sec,avg_latency_ms,p99_latency_ms,total_reqs,connect_err,read_write_err,timeout_err,success_rate_pct" > "$OUT_FILE"
echo "[*] WRK Monitor V2 bắt đầu. Ghi ra: $OUT_FILE"

# Tạo file Lua script để rate-limit wrk và build custom request
cat << 'EOF' > /tmp/wrk_delay_v2.lua
function request()
    wrk.headers["User-Agent"]      = "Mozilla/5.0 (LegitClient Benchmark V2/1.0)"
    wrk.headers["Accept"]          = "text/html,application/json"
    wrk.headers["Connection"]      = "keep-alive"
    return wrk.format("GET", nil)
end

function delay()
   return 50
end
EOF

# Hàm xử lý parse thời gian (s/ms/us)
parse_latency() {
    local raw=$1
    if [[ "$raw" == *"ms"* ]]; then
        echo "${raw%ms}"
    elif [[ "$raw" == *"us"* ]]; then
        val="${raw%us}"
        echo "$val" | awk '{printf "%.2f", $1/1000}'
    elif [[ "$raw" == *"s"* ]]; then
        val="${raw%s}"
        echo "$val" | awk '{printf "%.2f", $1*1000}'
    else
        echo "0"
    fi
}

while true; do
    TS_MS=$(date +%s%3N)

    # Chạy wrk và capture output
    WRK_OUT=$(wrk -t${WRK_THREADS} -c${WRK_CONNS} -d${WRK_DURATION}s \
        -s /tmp/wrk_delay_v2.lua \
        --latency "$TARGET" 2>/dev/null)

    if [ -z "$WRK_OUT" ]; then
        # Lỗi nghiêm trọng, không có output
        echo "$TS_MS,0,0,0,0,0,0,0,0" >> "$OUT_FILE"
    else
        # 1. Parse Req/sec
        REQ_PER_SEC=$(echo "$WRK_OUT" | grep "Requests/sec" | awk '{print $2}')
        REQ_PER_SEC=${REQ_PER_SEC:-0}

        # 2. Parse Latency
        AVG_LAT_RAW=$(echo "$WRK_OUT" | grep -E "^\s+Latency" | awk '{print $2}')
        AVG_LAT=$(parse_latency "$AVG_LAT_RAW")
        
        P99_LAT_RAW=$(echo "$WRK_OUT" | grep "99%" | awk '{print $2}')
        P99_LAT=$(parse_latency "$P99_LAT_RAW")

        # 3. Parse Total Requests (Thành công)
        TOTAL_REQS=$(echo "$WRK_OUT" | grep "requests in" | awk '{print $1}')
        TOTAL_REQS=${TOTAL_REQS:-0}

        # 4. Parse Errors (Socket errors: connect X, read Y, write Z, timeout W)
        ERR_LINE=$(echo "$WRK_OUT" | grep "Socket errors:")
        
        CONNECT_ERR=0
        READ_ERR=0
        WRITE_ERR=0
        TIMEOUT_ERR=0

        if [ -n "$ERR_LINE" ]; then
            CONNECT_ERR=$(echo "$ERR_LINE" | grep -o "connect [0-9]*" | awk '{print $2}')
            READ_ERR=$(echo "$ERR_LINE" | grep -o "read [0-9]*" | awk '{print $2}')
            WRITE_ERR=$(echo "$ERR_LINE" | grep -o "write [0-9]*" | awk '{print $2}')
            TIMEOUT_ERR=$(echo "$ERR_LINE" | grep -o "timeout [0-9]*" | awk '{print $2}')
            
            CONNECT_ERR=${CONNECT_ERR:-0}
            READ_ERR=${READ_ERR:-0}
            WRITE_ERR=${WRITE_ERR:-0}
            TIMEOUT_ERR=${TIMEOUT_ERR:-0}
        fi

        # 5. Calculate Success Rate (%)
        READ_WRITE_ERR=$((READ_ERR + WRITE_ERR))
        TOTAL_ATTEMPTS=$((TOTAL_REQS + CONNECT_ERR + READ_WRITE_ERR + TIMEOUT_ERR))
        
        if [ "$TOTAL_ATTEMPTS" -gt 0 ]; then
            # Dùng bc hoặc awk để tính toán tỉ lệ %
            SUCCESS_RATE=$(awk "BEGIN {printf \"%.2f\", ($TOTAL_REQS / $TOTAL_ATTEMPTS) * 100}")
        else
            SUCCESS_RATE=0
        fi

        # 6. Ghi vào file CSV
        echo "$TS_MS,$REQ_PER_SEC,$AVG_LAT,$P99_LAT,$TOTAL_REQS,$CONNECT_ERR,$READ_WRITE_ERR,$TIMEOUT_ERR,$SUCCESS_RATE" >> "$OUT_FILE"
    fi

    # Thời gian nghỉ 2s trước vòng mới
    sleep 2
done
