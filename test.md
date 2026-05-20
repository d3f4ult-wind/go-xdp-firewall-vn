# KỊCH BẢN KIỂM THỬ XDP FIREWALL (HYBRID)

Tài liệu này cung cấp các kịch bản để kiểm thử 3 tính năng mới: **XDP Rate Limit**, **Threat Intel AutoBlock (Suricata/Iptables)**, và **GeoIP On-demand**.

## 0. SƠ ĐỒ MẠNG & CHUẨN BỊ
- **Attacker (Botnet):** `10.10.1.2` (Chứa các netns: `10.10.1.10`, `10.10.1.11`, `10.10.1.50`, `10.10.1.100`).
- **Firewall:** `10.10.1.1` (eth0 - hường ra Attacker) và `10.10.2.1` (eth1 - hướng ra Victim).
- **Victim:** `10.10.2.2` (Apache Prefork siêu yếu).

### 0.1. Khởi động hệ thống trên Firewall
Mở 3 terminal riêng biệt trên máy Firewall:
1. **Terminal 1 (Core):** `sudo ./firewall`
2. **Terminal 2 (UI):** `cd flask_ui && python3 app.py` (Mở trình duyệt: `http://<IP-Firewall>:8000/ratelimit`)
3. **Terminal 3 (Watcher):** `cd third_party_code/cmd/watcher && sudo go run .`

---

## 1. KỊCH BẢN 1: KIỂM THỬ XDP RATE LIMITING (CHỐNG DDoS TẦNG THẤP)

**Mục tiêu:** Đảm bảo XDP tự động gạt bỏ các IP gửi gói tin vượt ngưỡng thiết lập.

**Bước 1:** Trên giao diện UI (Rate Limit), cài đặt ngưỡng: 
- PPS Threshold: `500`
- Time Window: `1000` (ms)

**Bước 2:** Trên máy Attacker, dùng netns `10.10.1.10` xả TCP SYN flood ở tốc độ cao (ví dụ: 10,000 pps):
```bash
sudo ip netns exec bot10 hping3 -S -p 80 --flood 10.10.2.2
```

**Bước 3:** Quan sát kết quả:
- **Trên Firewall:** Mở UI, nhìn vào bảng **"Auto-Blocked IPs (Tự động XDP Rate Limit)"**.
- **Kỳ vọng:** IP `10.10.1.10` xuất hiện ngay lập tức trên bảng kèm số lượng packet count tăng vọt. Traffic tới Victim bị XDP drop hoàn toàn, Apache trên Victim không bị nghẽn.

**Bước 4:** Dừng tấn công trên Attacker (Ctrl+C). Đợi một lúc (hết window), IP sẽ tự động biến mất khỏi bảng Rate Limit.

---

## 2. KỊCH BẢN 2: THREAT INTEL - SURICATA AUTOBLOCK

**Mục tiêu:** Suricata phát hiện chữ ký tấn công phức tạp (Application Layer) và Watcher tự động lấy IP đẩy xuống XDP.

**Bước 1:** Đảm bảo Suricata đang chạy trên Firewall và theo dõi interface `eth0`.
**Bước 2:** Viết 1 luật Suricata đơn giản (hoặc dùng luật có sẵn), ví dụ chặn chuỗi `"/admin-login-brute"`:
```text
alert http any any -> any any (msg:"Test Brute Force"; content:"/admin-login-brute"; sid:999999; rev:1;)
```
*(Đảm bảo đã restart Suricata).*

**Bước 3:** Trên máy Attacker, dùng netns `10.10.1.11` bắn request HTTP chứa payload đó (Dùng tốc độ chậm để không bị XDP Rate Limit bắt):
```bash
sudo ip netns exec bot11 curl http://10.10.2.2/admin-login-brute
```

**Bước 4:** Quan sát kết quả:
- **Trên UI:** Bảng **"Threat Intelligence Blocklist"** xuất hiện dòng `10.10.1.11/32`.
- **Trên Terminal Watcher:** Hiển thị log `[Suricata] Phat hien tan cong tu IP: 10.10.1.11` và `[BPF] Da block: 10.10.1.11/32`.
- **Xác minh:** Thử `curl` lại từ bot11, gói tin sẽ bị XDP drop ngay ở Layer 2.

---

## 3. KỊCH BẢN 3: THREAT INTEL - IPTABLES AUTOBLOCK

**Mục tiêu:** Watcher đọc Syslog, trích xuất IP từ log của Iptables (có cờ `[FW-DOS]`) và đẩy xuống XDP.

**Bước 1:** Cài đặt 1 luật iptables trên Firewall giả lập việc dò port (Port Scan) kết hợp ghi log:
```bash
sudo iptables -A FORWARD -p tcp --dport 22 -m limit --limit 3/min -j LOG --log-prefix "[FW-DOS] SSH Brute: "
```

**Bước 2:** Trên máy Attacker, dùng netns `10.10.1.50` cố gắng liên tục SSH vào Victim:
```bash
sudo ip netns exec bot50 nc -zv 10.10.2.2 22
```

**Bước 3:** Quan sát kết quả:
- **Trên UI:** IP `10.10.1.50/32` xuất hiện trong bảng **"Threat Intelligence Blocklist"**.
- **Trên Terminal Watcher:** Log `[Iptables] Phat hien tan cong tu IP: 10.10.1.50` xuất hiện.
- Máy `10.10.1.50` sẽ bị cách ly hoàn toàn khỏi mạng lưới.

---

## 4. KỊCH BẢN 4: KIỂM THỬ GEOIP (ON-DEMAND BLOCKING)

**Mục tiêu:** Đảm bảo Watcher có thể quét file CSV cực nhanh và nhét hàng ngàn Subnet vào LPM Trie.

**Bước 1:** Do đây là môi trường Lab (mạng LAN 10.x), file CSV của MaxMind không chứa dải `10.10.x.x`. Vì vậy, chúng ta sẽ test bằng cách Block một quốc gia có thật (VD: "CN" - Trung Quốc) và kiểm tra xem UI có hiển thị đúng các Subnet không.

**Bước 2:** Bật tính năng giả lập (Test trigger). Mở file `third_party_code/cmd/watcher/geoip.go`, dòng 76, bỏ comment dòng này:
```go
go g.BlockCountry("CN")
```
*(Nếu muốn test không cần build lại, bạn có thể thiết kế 1 API nhỏ trên Watcher để nhận lệnh Block, hoặc đơn giản là sửa code và chạy lại `go run .`)*

**Bước 3:** Restart lại Watcher:
```bash
cd third_party_code/cmd/watcher && sudo go run .
```

**Bước 4:** Quan sát kết quả:
- **Trên Terminal Watcher:** Báo cáo `Dang quet Subnet cua CN...` và hoàn thành trong khoảng 1 giây: `[GeoIP] Hoan thanh! Da block XXXX Subnets...`.
- **Trên UI:** Bảng **Threat Intel Blocklist** đột nhiên xuất hiện hàng ngàn dòng dải mạng (Ví dụ: `1.0.1.0/24`, `1.0.2.0/23`, ...).
- Điều này chứng minh kiến trúc LPM Trie xử lý cực tốt cả chục ngàn Subnet mà không hề hấn gì.

---

## 5. KỊCH BẢN 5: GỠ BỎ THỦ CÔNG (MANUAL UNBAN) TRÊN GIAO DIỆN

**Mục tiêu:** Đảm bảo Admin có thể tha bổng IP bị phạt trước thời hạn.

**Bước 1:** Trên UI, trong bảng Threat Intel Blocklist, tìm IP `10.10.1.11/32` (hoặc `10.10.1.50/32`) vừa bị chặn ở Kịch bản 2/3.
**Bước 2:** Bấm nút **"🗑️ Gỡ bỏ"**. Chọn "OK" ở hộp thoại xác nhận.
**Bước 3:** IP biến mất khỏi bảng.
**Bước 4:** Lập tức quay lại máy Attacker, dùng đúng netns đó để gửi gói tin bình thường (không dùng mã độc):
```bash
sudo ip netns exec bot11 ping -c 1 10.10.2.2
```
**Kỳ vọng:** Ping thành công. Lệnh xóa từ Frontend đã xuyên qua Flask UI -> HTTP API -> Go Backend -> `auto_block_map` ở nhân Kernel eBPF thành công!
