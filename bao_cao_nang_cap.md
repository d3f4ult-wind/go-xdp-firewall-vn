# BÁO CÁO CÁC TÍNH NĂNG NÂNG CẤP (SO VỚI MÃ NGUỒN GỐC)

Tài liệu này tổng hợp các thay đổi, sửa lỗi và các tính năng đột phá đã được bổ sung vào hệ thống XDP Firewall nhằm biến nó từ một packet filter cơ bản thành một **Tường lửa Hybrid thông minh**. Những thông tin này cực kỳ quan trọng để đưa vào Báo cáo Đồ án Tốt nghiệp.

---

## 1. SỬA LỖI KIẾN TRÚC LÕI (FIX BUGS)

### 1.1. Sửa lỗi logic khi chặn Dải mạng (CIDR) - Commit "Version 2"
- **Hạn chế của code gốc (Version 1.0):** Tác giả ban đầu đã thiết kế `BPF_MAP_TYPE_LPM_TRIE` để chặn CIDR, tuy nhiên cơ chế này bị lỗi logic và không hoạt động. Nguyên nhân cốt lõi là do sự bất đồng bộ về Endianness (Byte Order) giữa User-space (Go) và Kernel-space (C). Trong C, tác giả sử dụng `bpf_ntohl()` để chuyển đổi IP, còn trong Go lại dùng `binary.BigEndian.Uint32`, dẫn đến thuật toán Longest Prefix Matching đối chiếu sai lệch bit.
- **Cách khắc phục:** Đã sửa lại định dạng Key của LPM Trie. Thay vì dùng số nguyên `__u32 addr` kết hợp `ntohl`, hệ thống được đổi sang sử dụng mảng byte nguyên thủy `__u8 addr[4]`. Dữ liệu IP được truyền trực tiếp từ Go (`copy(key.Addr[:], ip.To4())`) xuống Kernel dưới dạng Network Byte Order chuẩn mà không cần qua bất kỳ bước biến đổi Endian nào nữa.
- **Kết quả:** XDP đã có thể hiểu và kiểm tra chính xác các gói tin thuộc một mạng con (Subnet). Lỗi chặn CIDR được khắc phục hoàn toàn.

### 1.2. Giải quyết vấn đề Xung đột Dữ liệu (Race-Condition) - Commit "Add Mutex"
- **Hạn chế của code gốc:** Cấu trúc quản lý Control Plane ở phía User-space (Go) lưu trữ các bản ghi ánh xạ Subnet (`prefixToID`, `idToPrefix`) nhưng không có cơ chế đồng bộ luồng (Thread-safe). Khi có nhiều yêu cầu API cùng truy xuất (Read/Write) vào bộ nhớ đệm này, hệ thống Go Backend có nguy cơ bị crash (Data Race/Concurrent Map Write).
- **Cách khắc phục:** Bổ sung cơ chế khóa đọc/ghi `sync.RWMutex` vào struct `Firewall`. Các đoạn code nhạy cảm trong hàm `AddRule`, `DeleteRule`, và `ListRules` đều được bọc cẩn thận bằng `fw.mu.Lock()` và `fw.mu.RLock()`.
- **Kết quả:** Đảm bảo tính toàn vẹn dữ liệu, Control Plane có thể chịu tải đồng thời nhiều luồng thao tác mà không bị sập.

---

## 2. NÂNG CẤP CHỐNG DDOS Ở TẦNG KERNEL (XDP RATE LIMITING)

- **Tính năng mới:** Bổ sung module Rate Limit hoàn toàn tự động trực tiếp ở tầng eBPF Kernel (`xdp-filter.c`).
- **Cơ chế hoạt động:** Sử dụng thuật toán **Fixed Time Window**. Kernel sẽ cấp phát một Map (`rate_limit_map`) lưu trữ số lượng gói tin đếm được của **mọi địa chỉ IP** đang giao tiếp với server.
- **Ưu điểm vượt trội:** 
  - Toàn bộ logic cộng dồn đếm gói tin và ra quyết định DROP được thực thi ở mức NIC (Card mạng), trước khi HĐH kịp nhận thức.
  - Tự động thả chặn (Auto-unban) cực kỳ thanh lịch ngay khi hết khung thời gian (Time Window) nếu IP ngừng gửi gói tin. Không tốn bộ nhớ lưu trữ các trạng thái block vĩnh viễn.

---

## 3. TÍCH HỢP THREAT INTELLIGENCE (HYBRID ARCHITECTURE)

Đây là nâng cấp đồ sộ nhất, biến firewall tĩnh thành Firewall Động, có khả năng phân tích hành vi lớp ứng dụng (L7).

### 3.1. Phân tách Management Daemon (Watcher)
- Thay vì nhồi nhét mã nguồn độc hại, tôi đã viết một tiến trình giám sát độc lập (Out-of-process) bằng Go nằm tại `third_party_code/cmd/watcher/`.
- **Giao tiếp Zero-Conflict:** Tiến trình Watcher này giao tiếp với nhân Kernel thông qua cơ chế **eBPF Map Pinning** (đọc/ghi thẳng vào file `/sys/fs/bpf/xdp_auto_block`). Điều này giúp Watcher và luồng API của Admin hoạt động song song mà không bao giờ tranh chấp tài nguyên của nhau.

### 3.2. Cảm biến Suricata (L7 IPS)
- XDP rất nhanh nhưng bị mù ở lớp ứng dụng (Application Layer). Tôi đã kết nối XDP với Suricata (chạy ở tầng trên). 
- Watcher sẽ liên tục đọc log `eve.json` của Suricata (`tailer.go`). Nếu phát hiện hành vi Brute Force, Slowloris, SQLi,... Watcher lập tức trích xuất IP và thả xuống cho XDP chặn đứng ngay tại cửa ngõ.

### 3.3. Cảm biến Iptables (Stateful Firewall)
- Tương tự Suricata, Watcher đọc log từ `syslog` (`iptables_tailer.go`) để khai thác khả năng theo dõi trạng thái kết nối (`conntrack`) của Iptables (như chống ACK-Flood giả mạo hay TCP Port Scan).

### 3.4. Chặn dải IP theo Quốc gia (GeoIP On-Demand)
- Tích hợp cơ sở dữ liệu MaxMind CSV. 
- Thay vì nạp toàn bộ 400,000 dải mạng (22MB) vào RAM làm treo hệ thống, module `geoip.go` được thiết kế theo cơ chế **On-Demand**. Khi có lệnh chặn 1 quốc gia, nó sẽ quét file CSV cực nhanh (chưa tới 1 giây) và nạp hàng ngàn dải Subnet của quốc gia đó xuống thẳng `LPM Trie` của Kernel.

---

## 4. NÂNG CẤP BẢNG ĐIỀU KHIỂN & GIAO DIỆN QUẢN TRỊ (UI/UX)

- **Phân tách giao diện:** Tách biệt trang Dashboard (quản lý luật tĩnh) và trang Threat Intel/Rate Limit (`ratelimit.html`).
- **Giao diện thời gian thực:** Viết lại logic Flask API và JavaScript để "Polling" (kéo dữ liệu) liên tục từ Kernel lên trình duyệt mỗi 5 giây.
- **Trực quan hóa Dữ liệu:** 
  - Phân tách rõ ràng bảng **Tự động chặn do Rate Limit** và **Danh sách đen từ Threat Intel**.
  - Xử lý định dạng thông minh hiển thị Subnet (VD: Hiển thị `10.10.1.0/24` thay vì bắt ép phải là `/32`).
- **Manual Unban (Gỡ bỏ thủ công):** Mặc dù hệ thống có khả năng tự gỡ block qua module `unban.go`, nhưng quyền lực tối thượng vẫn được trao cho Admin thông qua nút bấm **"🗑️ Gỡ bỏ"** ngay trên UI (tích hợp bằng API `DELETE` đẩy lệnh trực tiếp xuống Kernel).

---
**Tổng kết:** Mã nguồn gốc chỉ là một bộ lọc mạng thô sơ. Hệ thống hiện tại đã trở thành một nền tảng phòng thủ đa lớp (Defense in Depth), vừa sở hữu tốc độ phần cứng của eBPF, vừa có trí tuệ nhân tạo của Suricata, lại được bọc trong một kiến trúc mã nguồn Go sạch sẽ, tối ưu chuẩn công nghiệp.
