/**
 * =================================================================================
 * FILE: firewall.go
 * MÔ TẢ: Định nghĩa cấu trúc dữ liệu cốt lõi của Firewall.
 * LUỒNG HOẠT ĐỘNG: 
 *   Quản lý sự đồng bộ giữa trạng thái trong bộ nhớ RAM (Go) và trạng thái trong 
 *   Kernel (eBPF Maps).
 * =================================================================================
 */

package bpf 

import (
	"github.com/cilium/ebpf"
	"net"
	"sync"
	"time"
)

/**
 * # Cấu trúc Rule (Nội bộ)
 * Dùng để tính toán logic và giao tiếp với tầng Kernel.
 * TẠI SAO: Sử dụng net.IP (dạng byte) thay vì string để tối ưu hóa việc 
 * chuyển đổi sang định dạng nhị phân mà Kernel yêu cầu.
 */
type Rule struct {
	Addr    net.IP // IP nguồn
	Masklen uint32 // Độ dài subnet mask (vd: 24)
	Proto   int32  // TCP=6, UDP=17, ICMP=1
	Port    uint32 // Cổng đích
	Action  uint32 // 1 = PASS, 2 = DROP (dựa trên hằng số XDP)
}

/**
 * # Cấu trúc YamlRule
 * Chuyên biệt cho việc giải mã file cấu hình (Unmarshalling).
 * TẠI SAO: Dữ liệu từ YAML thường là chuỗi (vd: "192.168.1.0/24"), 
 * cần một cấu trúc trung gian trước khi parse thành struct Rule xịn.
 */
type YamlRule struct {
	SubnetAddr string `yaml:"subnetAddr"`
	Proto      int32  `yaml:"proto"`
	Port       uint32 `yaml:"port"`
	Action     uint32 `yaml:"action"`
}

/**
 * # Đối tượng Firewall
 * Trái tim của Control-plane.
 */
type Firewall struct {
	// ---- eBPF objects ----
	// Lưu trữ các con trỏ đến Maps thực tế đang chạy trong Kernel.
	// CẠM BẪY: Các biến này thực chất là các File Descriptors. Nếu Kernel đóng các FD này,
	// Firewall sẽ không thể cập nhật luật được nữa.
	ipTrie        *ebpf.Map
	policies      *ebpf.Map
	defaultAction *ebpf.Map

	// mu: Bảo vệ các map trong bộ nhớ đệm (User-space) khỏi lỗi concurrent map read/write
	mu sync.RWMutex

	// ---- Control-plane state (Bộ nhớ đệm User-space) ----
	// TẠI SAO: Kernel eBPF Map rất khó để duyệt (iterate) và tìm kiếm ngược.
	// Chúng ta giữ một bản sao ở User-space để phục vụ API List/Delete nhanh chóng.
	
	// prefixToID: "192.168.1.0/24" -> ID: 1
	prefixToID map[string]uint32
	
	// idToPrefix: ID: 1 -> {LPM Key}. Dùng khi cần hiển thị luật từ Kernel cho người dùng.
	idToPrefix map[uint32]xdp_packet_filterIpv4LpmKey
	
	// nextID: Tự động tăng để gán cho các Subnet mới.
	// CẠM BẪY: Nếu ID này vượt quá giới hạn của uint32 (hiếm gặp), cần cơ chế tái sử dụng ID.
	nextID     uint32

	// ---- Thông tin vận hành (Metrics) ----
	startTime time.Time
	cpuUsagePercent float64
	memUsageMB      uint64
	xdpAttached bool // Cờ đánh dấu XDP đã được gắn vào interface thành công hay chưa
}

/**
 * Khởi tạo đối tượng Firewall mới.
 * Yêu cầu các Map eBPF phải được nạp thành công trước đó.
 */
func New(ipTrie, policies, defaultAction *ebpf.Map) *Firewall {
	return &Firewall{
		ipTrie:        ipTrie,
		policies:      policies,
		defaultAction: defaultAction,

		prefixToID: make(map[string]uint32),
		idToPrefix: make(map[uint32]xdp_packet_filterIpv4LpmKey),
		nextID:     1, // Bắt đầu từ 1 vì trong một số logic Kernel, 0 thường là giá trị lỗi/mặc định.
	}
}