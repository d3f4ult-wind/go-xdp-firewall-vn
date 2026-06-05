#!/usr/bin/env python3
# =============================================================
# File: legit_client.py
# Chạy trên: VM attacker (10.10.1.2) trong netns legit_client
# Mục đích: Gửi request HTTP liên tục tới Victim, đo lường Availability,
#           ghi nhận Response Time, Status Code vào CSV.
# Input: $1 (Tên Scenario)
# Output: legit_<SCENARIO>_<TIMESTAMP>.csv
# Gọi bởi: orchestrate.sh
# =============================================================

import sys
import time
import urllib.request
import urllib.error
from datetime import datetime

scenario = sys.argv[1] if len(sys.argv) > 1 else "default"
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
out_file = f"/tmp/legit_{scenario}_{timestamp}.csv"

VICTIM_URL = "http://10.10.2.2/health.php"
TIMEOUT_SEC = 3.0 # Yêu cầu < 3000ms

with open(out_file, "w") as f:
    f.write("timestamp_unix_ms,response_time_ms,status_code,available\n")

print(f"[*] Starting Legitimate Client. Logging to {out_file}")

# Vòng lặp bắn request mỗi 200ms
while True:
    ts_ms = int(time.time() * 1000)
    start_time = time.time()
    
    status_code = 0
    available = 0
    
    try:
        req = urllib.request.Request(VICTIM_URL)
        with urllib.request.urlopen(req, timeout=TIMEOUT_SEC) as response:
            status_code = response.getcode()
            if status_code == 200:
                available = 1
    except urllib.error.HTTPError as e:
        status_code = e.code
    except Exception as e:
        status_code = -1 # Connection Refused, Timeout, vv.
        
    response_time_ms = int((time.time() - start_time) * 1000)
    
    # Nếu timeout thì gán response time = 3000ms
    if status_code == -1 and response_time_ms >= 3000:
        response_time_ms = 3000
        
    with open(out_file, "a") as f:
        f.write(f"{ts_ms},{response_time_ms},{status_code},{available}\n")
        
    # Nghỉ 1 chút để không làm ngập server
    time.sleep(0.2)
