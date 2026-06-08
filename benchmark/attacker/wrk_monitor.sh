#!/bin/bash
# =============================================================
# File: wrk_monitor.sh
# Chạy trên: VM attacker trong netns legit (IP: 10.10.1.3)
# Mục đích: Đo throughput HTTP thực tế từ góc nhìn Legit Client
#           bằng cách chạy wrk liên tục, ghi kết quả vào CSV.
# Ghi: Mỗi 5 giây chạy wrk 3s, parse Req/s và P99 Latency
# Output: /tmp/wrk_SCENARIO_TIMESTAMP.csv
# =============================================================

SCENARIO=${1:-default}
TS=$(date +"%Y%m%d_%H%M%S")
OUT_FILE="/tmp/wrk_${SCENARIO}_${TS}.csv"
TARGET="http://10.10.2.2/health.php"

# wrk params: Giữ thấp dưới ngưỡng Suricata để không bị block
# sid:9000001: TCP SYN > 20 conn/10s → giữ conns ≤ 5
# sid:9002001: HTTP GET > 1000 req/10s → wrk 2t×2c ~40-80 req/s = an toàn
# sid:9002003: Missing User-Agent → thêm header
WRK_THREADS=2
WRK_CONNS=2
WRK_DURATION=3
WRK_UA="Mozilla/5.0 (LegitClient Benchmark/1.0)"

echo "timestamp_unix_ms,req_per_sec,avg_latency_ms,p99_latency_ms,errors" > "$OUT_FILE"
echo "[*] WRK Monitor bắt đầu. Ghi ra: $OUT_FILE"

# Tạo file Lua script để rate-limit wrk và build custom request
cat << 'EOF' > /tmp/wrk_delay.lua
function request()
    wrk.headers["User-Agent"]      = "Mozilla/5.0 (LegitClient Benchmark/1.0)"
    wrk.headers["Accept"]          = "text/html,application/json"
    wrk.headers["Accept-Language"] = "en-US,en;q=0.9"
    wrk.headers["Connection"]      = "keep-alive"
    return wrk.format("GET", nil)
end

function delay()
   return 50
end
EOF

while true; do
    TS_MS=$(date +%s%3N)

    # Chạy wrk và capture output
    WRK_OUT=$(wrk -t${WRK_THREADS} -c${WRK_CONNS} -d${WRK_DURATION}s \
        -s /tmp/wrk_delay.lua \
        --latency "$TARGET" 2>/dev/null)

    if [ -z "$WRK_OUT" ]; then
        # wrk không chạy được (victim sập hoặc không phản hồi)
        echo "$TS_MS,0,0,0,-1" >> "$OUT_FILE"
    else
        # Parse Requests/sec
        REQ_PER_SEC=$(echo "$WRK_OUT" | grep "Requests/sec" | awk '{print $2}' | tr -d '[:space:]')
        REQ_PER_SEC=${REQ_PER_SEC:-0}

        # Parse Avg Latency (wrk output: "Latency   12.34ms  ...")
        AVG_LAT_RAW=$(echo "$WRK_OUT" | grep -E "^\s+Latency" | awk '{print $2}')
        # Chuyển đổi về ms (có thể là 12.34ms hoặc 1.23s)
        AVG_LAT_MS=$(python3 -c "
s='${AVG_LAT_RAW:-0ms}'
if s.endswith('ms'): print(round(float(s[:-2]),2))
elif s.endswith('s'): print(round(float(s[:-1])*1000,2))
elif s.endswith('us'): print(round(float(s[:-2])/1000,2))
else: print(0)
" 2>/dev/null || echo 0)

        # Parse P99 Latency từ --latency output
        P99_RAW=$(echo "$WRK_OUT" | grep "99%" | awk '{print $2}')
        P99_MS=$(python3 -c "
s='${P99_RAW:-0ms}'
if s.endswith('ms'): print(round(float(s[:-2]),2))
elif s.endswith('s'): print(round(float(s[:-1])*1000,2))
elif s.endswith('us'): print(round(float(s[:-2])/1000,2))
else: print(0)
" 2>/dev/null || echo 0)

        # Parse errors (Socket errors)
        ERRORS=$(echo "$WRK_OUT" | grep -c "Socket errors" || true)

        echo "$TS_MS,$REQ_PER_SEC,$AVG_LAT_MS,$P99_MS,$ERRORS" >> "$OUT_FILE"
        echo "  [wrk] $(date +%H:%M:%S) | Req/s=$REQ_PER_SEC | P99=${P99_MS}ms"
    fi

    # Chờ 2s (3s wrk + 2s gap = 5s interval)
    sleep 2
done
