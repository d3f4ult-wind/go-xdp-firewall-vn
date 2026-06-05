# HƯỚNG DẪN THỰC THI BENCHMARK V2 (3 VMs)

Tài liệu này cung cấp hướng dẫn toàn diện để triển khai, đo lường và đánh giá hệ thống Firewall trong 3 kịch bản tấn công thực tế.

## 1. YÊU CẦU MÔI TRƯỜNG & CHUẨN BỊ
Mô hình chạy trên 3 Virtual Machines (VMs) độc lập kết nối qua Virtual Switch/Bridge.

### 1.1. Topology
- **Attacker VM:** `10.10.1.2` (enp0s8)
  - Phân vùng Netns (Legit Client): `10.10.1.3`
- **Firewall VM (Master):** 
  - Interface IN: `10.10.1.1` (enp0s8)
  - Interface OUT: `10.10.2.1` (enp0s9)
- **Victim VM (Apache):** `10.10.2.2` (enp0s8)

### 1.2. Khởi tạo Đồng bộ Thời gian (NTP) & SSH
- **NTP:** Do biểu đồ yêu cầu độ chính xác ms, cả 3 máy phải chạy đồng bộ thời gian (NTP):
  ```bash
  sudo apt install chrony -y
  sudo systemctl restart chrony
  ```
- **SSH Không Mật khẩu:** Firewall VM đóng vai trò Orchestrator. Từ Firewall VM, hãy tạo SSH Key và đẩy sang Attacker & Victim:
  ```bash
  ssh-keygen -t rsa -N ""
  ssh-copy-id attacker_user@10.10.1.2
  ssh-copy-id victim_user@10.10.2.2
  ```
- **Kiểm tra Ping (Khuyến nghị < 5ms):** Đảm bảo môi trường ảo hóa không bị nghẽn:
  ```bash
  ping -c 4 10.10.1.2
  ping -c 4 10.10.2.2
  ```

## 2. THỨ TỰ CHẠY TỪNG KỊCH BẢN
Tất cả kịch bản được điều phối tập trung từ **Firewall VM**. Không cần chạy tay trên từng máy.

**Bước 1: Setup Victim (Chỉ chạy 1 lần trên Victim VM)**
```bash
# SSH vào Victim VM:
cd benchmark/victim
sudo ./setup_apache.sh
```

**Bước 2: Setup Attacker (Chỉ chạy 1 lần trên Attacker VM)**
```bash
# SSH vào Attacker VM:
cd benchmark/attacker
sudo ./setup_netns.sh
```

**Bước 3: Chạy Kịch bản (Trên Firewall VM)**
Chạy từng kịch bản, mỗi kịch bản mất khoảng 90s (30s Baseline -> 30s Attack -> 30s Recovery).
```bash
# Chạy Kịch bản 1 (Botnet 1 Khu vực)
sudo ./run_scenario_1.sh

# Chạy Kịch bản 2 (Random Source & Geo Trust)
sudo ./run_scenario_2.sh

# Chạy Kịch bản 3 (Slowloris L7)
sudo ./run_scenario_3.sh
```

## 3. CÁCH ĐỌC OUTPUT CSV
Mỗi kịch bản sẽ tạo ra một thư mục `results_SCENARIO_X_TIMESTAMP/` trên Firewall VM. Trong đó gồm:
- **`metrics_firewall.csv`**: Chứa tải CPU, XDP Drop rate, ngắt IRQ, trạng thái SoftIRQ, bộ nhớ RAM, Iptables log đếm từng giây.
- **`apache_status.csv` (Kéo từ Victim):** Trạng thái `active_workers`, `idle_workers`. 
- **`legitimate_client.csv` (Kéo từ Attacker):** `response_time_ms`, `status_code` của User hợp lệ (10.10.1.3).
- **`summary.txt`:** Bản tóm tắt text (Peak Drop, Availability %, P95 Latency, Recovery Time). Báo cáo nhanh!

Để vẽ biểu đồ, bạn chỉ cần gộp các trục tọa độ dựa trên cột `timestamp_unix_ms`.

## 4. CÁC THAM SỐ CẦN ĐIỀU CHỈNH
Mọi tham số cứng đã được dời lên đầu file script. Nếu chuyển từ Lab VM lên Bare-Metal (Máy thật), hãy chỉnh:
- **Tốc độ bắn PPS (Attacker):** Trong `attack_scX.sh`, tìm biến `DEFAULT_PPS=5000` tăng lên `1000000` (1 triệu PPS).
- **Số Worker Apache (Victim):** Mặc định đang ép xuống `50` (Để lab dễ sập). Tăng `MaxRequestWorkers` trong `setup_apache.sh` lên `500` hoặc `1000`.
- **Băng thông (wrk):** Trong `legit_client.py` có thể tăng số threads và connections.

## 5. TROUBLESHOOTING (LỖI THƯỜNG GẶP)
- **Lỗi SSH:** `[ERROR] Lệnh SSH thất bại!` -> Bạn chưa setup `ssh-copy-id` (Mục 1.2).
- **Collector bị Crash (-1):** Nếu thấy CSV toàn `-1` ở cột XDP, nghĩa là Firewall XDP chưa được `attach` (Map không tồn tại). Hãy bật Core Go Firewall trước khi chạy Kịch bản!
- **Apache không sập ở Kịch bản 3:** Do `slowloris` gửi chưa đủ. Hãy tăng `DEFAULT_CONN=500` lên `1000` trong `attack_sc3_slowloris.sh`.
- **Dữ liệu Legit Client không có:** Kiểm tra Netns trên Attacker (`ip netns list`), đảm bảo netns `legit_client` đã có IP `10.10.1.3` và ping được sang Victim `10.10.2.2`.
