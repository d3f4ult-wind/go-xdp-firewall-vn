# TÀI LIỆU HƯỚNG DẪN ĐỌC CODE: HANSELGRAY-XDP-FIREWALL

## 1. Mô tả dự án
Dự án này là một nguyên mẫu Firewall hiệu năng cao hoạt động dựa trên công nghệ XDP (Express Data Path) của Linux Kernel. Nó cho phép lọc và xử lý gói tin ngay tại tầng driver mạng, trước khi gói tin đi vào stack mạng của hệ điều hành, giúp đạt tốc độ xử lý cực cao và độ trễ tối thiểu. Hệ thống giải quyết bài toán quản lý truy cập mạng quy mô lớn bằng cách kết hợp sức mạnh xử lý của Kernel và tính linh hoạt của Go API.
- **Công nghệ:** C (eBPF/XDP), Go (cilium/ebpf), Python (Flask), Linux XDP.
- **Kiến trúc tổng quan:** XDP lọc gói tin tại tầng NIC, Go điều phối tài nguyên qua eBPF Maps, Flask cung cấp giao diện quản trị.

---

## 2. Thứ tự đọc code để hiểu dự án
Để nắm bắt dự án một cách logic nhất, bạn hãy đọc theo thứ tự "từ lõi ra vỏ":

1. **internal/bpf/xdp-filter.c & packet-parsers.h**: Đọc đầu tiên để hiểu logic thực thi gói tin trong Kernel.
2. **internal/bpf/gen.go & xdp_packet_filter_bpfel.go**: Hiểu cách mã C được biên dịch và ánh xạ sang môi trường Go.
3. **internal/bpf/loader.go**: Tìm hiểu quy trình nạp chương trình vào card mạng thực tế.
4. **internal/bpf/firewall.go & rules.go**: Hiểu cách quản lý nghiệp vụ và đồng bộ dữ liệu giữa userspace và kernel.
5. **internal/rest/api_endpoints.go & flask_ui/app.py**: Đọc cuối cùng để hiểu cách người dùng tương tác với toàn bộ hệ thống.

---

## 3. Mô tả chi tiết từng file

### 1. internal/bpf/xdp-filter.c & packet-parsers.h
- **Mô tả:** Đây là "tuyến đầu" của firewall chạy trực tiếp trong kernel. File này chứa mã C eBPF để bóc tách header gói tin (L2-L4) và so khớp với các luật trong Maps để quyết định PASS hoặc DROP.
- **Đọc file này xong, bạn sẽ hiểu được:** Cách viết mã an toàn cho XDP và giải thuật Longest Prefix Match (LPM) để lọc dải IP.

### 2. internal/bpf/gen.go & xdp_packet_filter_bpfel.go
- **Mô tả:** Tầng trung gian (Glue Code). File này chứa bytecode đã biên dịch và các struct đồng bộ giữa Go và C giúp chương trình Go có thể điều khiển được mã eBPF.
- **Đọc file này xong, bạn sẽ hiểu được:** Cách bộ thư viện `bpf2go` kết nối mã máy của C vào hệ sinh thái Go.

### 3. internal/bpf/loader.go
- **Mô tả:** Tầng triển khai (Deployment). Chịu trách nhiệm thực hiện các syscall bpf để nạp chương trình và gắn (attach) nó vào giao diện mạng cụ thể (như eth0, ens33).
- **Đọc file này xong, bạn sẽ hiểu được:** Quy trình nạp mã vào Kernel và sự khác biệt giữa các chế độ XDP (Native/Generic).

### 4. internal/bpf/firewall.go & rules.go
- **Mô tả:** Tầng điều khiển (Control Plane). Quản lý trạng thái firewall trong bộ nhớ và thực hiện các thao tác CRUD (thêm, xóa, liệt kê) trên các eBPF Maps thông qua Go.
- **Đọc file này xong, bạn sẽ hiểu được:** Cách ánh xạ dải IP (Subnet) thành các PolicyID để tối ưu bộ nhớ trong Kernel.

### 5. internal/rest/api_endpoints.go & flask_ui/app.py
- **Mô tả:** Tầng giao diện (Interface). Cung cấp các endpoint HTTP REST để người dùng điều khiển firewall và một lớp proxy (Flask) để phục vụ Dashboard Web.
- **Đọc file này xong, bạn sẽ hiểu được:** Luồng dữ liệu từ một cú click chuột trên UI đi qua API và cuối cùng thay đổi hành vi của gói tin mạng như thế nào.