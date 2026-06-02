# BÁO CÁO NÂNG CẤP KIẾN TRÚC FIREWALL (VERSION 2.0)
*Tiếp nối bản báo cáo nâng cấp v1, tài liệu này ghi nhận các kiến trúc và thuật toán tiên tiến nhất vừa được tích hợp vào hệ thống, biến Firewall tĩnh thành một hệ thống Phòng vệ Tự động Thích nghi (Adaptive Mitigation).*

---

## 1. NÂNG CẤP LÕI eBPF: XDP TIER 1 PROBABILISTIC DROP
- **Khắc phục lỗi Bitfield trong eBPF:** Trình biên dịch LLVM/Clang đôi khi gặp vấn đề khi xử lý bitfield của struct `tcphdr` trong C. Đội ngũ đã viết lại bộ phân tích cú pháp (parser) TCP header, truy xuất trực tiếp vào `byte[13]` của TCP header để bắt chính xác cờ SYN (0x02) và ACK (0x10), tránh tình trạng drop nhầm gói tin hợp lệ.
- **WRED (Weighted Random Early Detection):** Tích hợp thuật toán xác suất rơi tự do (Probabilistic Drop). Thay vì drop 100% gây đứt gãy kết nối, eBPF dùng `bpf_get_prandom_u32()` để quyết định rớt % tỷ lệ các gói SYN, UDP, ICMP theo cấu hình từ Admin. 
- **Độc lập Tác chiến:** Phân tách rõ ràng tỷ lệ Drop của dải IP Toàn cầu (Global) và tỷ lệ Drop của các IP thuộc Quốc gia nghi ngờ (GeoIP).

## 2. QUẢN TRỊ WHITELIST & GEOIP LINH HOẠT THREAD-SAFE
- **Kiến trúc Lập trình Đồng thời (Concurrency):** Bổ sung các phương thức `RemoveTrustedIP`, `RemoveGeoPrefix` và `ClearGeoPrefixes` trong `tier1.go`.
- **An toàn Tuyệt đối:** Áp dụng `sync.RWMutex` (Mutex Lock) khi xóa/sửa các bản ghi trong LPM Trie và Hash Map. Ngăn chặn triệt để tình trạng ứng dụng Go bị Crash toàn cục do lỗi Race Condition khi có đồng thời cả luồng API và luồng Watcher cùng tranh chấp ghi dữ liệu.
- **RESTful API hoàn chỉnh:** Mở rộng giao diện API với các handler `DELETE`, cho phép gỡ bỏ từng IP riêng lẻ, từng dải mạng (CIDR), hoặc dọn dẹp sạch sẽ (Clear All) toàn bộ danh sách Whitelist quốc gia với độ trễ cực thấp.

## 3. THREAT ENGINE: WATCHER DAEMON & HYSTERESIS (PHASE B)
*Đây là bước nhảy vọt kiến trúc: Thiết kế một bộ não tự động quan sát và phản ứng với các đợt DDoS, thay thế hoàn toàn sức người.*

- **Telemetry làm Kim Chỉ Nam:** Khác với các hệ thống nghiệp dư chỉ dựa vào số lượng log (Alerts), hệ thống sử dụng PPS (Packets Per Second) thực tế đọc từ XDP `mitigation_stats` làm biến độc lập (Primary Signal).
- **Sliding Window (Cửa sổ trượt):** Cứ mỗi 1 giây, hệ thống tính toán lưu lượng và đưa vào cửa sổ trượt (5 giây) để lấy trung bình.
- **Thuật toán Hysteresis (Chống giật cục):** Đặt ngưỡng High/Low Watermark và thời gian Cooldown (15 giây). Đảm bảo Level phòng thủ chỉ tăng khi thực sự có bão, và không hạ cấp quá sớm khi cuộc tấn công chỉ vừa tạm ngưng. Hệ thống duy trì sự ổn định tối đa (Không bị oscillation).
- **Tín hiệu phụ (Alert Accelerator):** Bổ sung song song hai Tailer đọc log từ **Suricata** (L7) và **Iptables**. Nếu có Alerts cao, nó sẽ làm "chất xúc tác" để đẩy nhanh quyết định nâng Level phòng vệ kể cả khi PPS chưa chạm trần.

## 4. QUẢN TRỊ XUNG ĐỘT: MANUAL OVERRIDE & ATOMIC TYPES
- **Vấn đề thiết kế:** Hệ thống tự động (Auto Mode) và Con người (Admin) luôn có rủi ro tranh chấp quyền điều khiển cấu hình (Data Race & Logic Conflict).
- **Giải pháp - Manual Override:** Thiết kế chuẩn mực của các thiết bị mạng công nghiệp. Hệ thống được trang bị biến trạng thái cấu trúc `sync/atomic.Bool` (`AutoMode`).
- **Nguyên lý Tối thượng của Con người:** Khi hệ thống đang tự động nhảy số phòng vệ, nếu Admin nhận thấy có sai sót (False Positive), Admin chỉ cần cấu hình tay và bấm "Lưu". Luồng API sẽ can thiệp lập tức `atomic.Store(false)`, "tắt điện" hệ thống Auto Mode để bảo lưu ý chí của Admin.

## 5. UI/UX: GIAO DIỆN KIỂM SOÁT TƯƠNG TÁC THỜI GIAN THỰC
- **Auto Mode Toggle:** Bổ sung công tắc Switch trượt và Badge hiển thị trạng thái động (AUTO/MANUAL) đồng bộ hóa hoàn toàn với Backend API.
- **WRED Auto-fill:** Admin chọn Protection Level (Low, Medium, High), giao diện sẽ tự động điền các thông số tỷ lệ Drop tối ưu mà không cần cấu hình bằng tay.
- **Realtime Dashboard:** Vòng lặp tự động làm mới `setInterval` lấy dữ liệu Thống kê gói tin và Trạng thái Auto Mode mỗi 2 giây.

## 6. SỬA LỖI ĐÓNG GÓI & TRIỂN KHAI (DEPENDENCY MANAGEMENT)
- **Thiếu thư viện mmdb:** Khắc phục tình trạng Go compiler báo lỗi thiếu thư viện đọc `GeoLite2-Country.mmdb` mỗi lần Clone repository mới. Bằng cách cập nhật triệt để thư viện `github.com/oschwald/geoip2-golang` vào `go.mod`, giúp tiến trình build tự động `go mod tidy` chạy trơn tru 100%.

---
**TỔNG KẾT V2.0:** Hệ thống đã chuyển mình từ một bộ quy tắc tĩnh thành một **"Sinh vật sống"** (Adaptive Tier 1). Nó có khả năng tự động cảm nhận áp lực (XDP Telemetry), phân tích môi trường xung quanh (Suricata/Iptables Alerts), tự động quyết định phản công (WRED Probabilistic Drop), nhưng vẫn luôn tôn trọng quyền điều khiển tối cao của người quản trị (Manual Override).
