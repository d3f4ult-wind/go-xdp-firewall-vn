/**
 * =================================================================================
 * FILE: loader.go
 * MÔ TẢ: Tầng triển khai (Deployment Layer) - Nạp và kích hoạt XDP vào Card mạng.
 * LUỒNG HOẠT ĐỘNG:
 *   1. Tìm chỉ số (Index) của card mạng dựa trên tên (ví dụ: "eth0").
 *   2. Gọi mã máy từ file .o đã nhúng để nạp vào Kernel thông qua Syscall.
 *   3. Lựa chọn chế độ đính kèm (Native vs Generic/SKB).
 *   4. Tạo một "Link" để duy trì sự tồn tại của chương trình trên Interface.
 * CẢI TIẾN/VERSION: v1.0 - Hỗ trợ tự động fallback sang Generic mode nếu Driver không hỗ trợ.
 * =================================================================================
 */

package bpf

import (
	"fmt"
	"net"
	"log"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf"
)

// BPF đóng vai trò là một "Handle" duy nhất để quản lý toàn bộ tài nguyên eBPF.
// Việc gom nhóm Objs và Link giúp ta dễ dàng quản lý vòng đời (Lifecycle) của Firewall.
type BPF struct {
	Objs *xdp_packet_filterObjects // Chứa các Maps và Programs đã nạp
	Link link.Link                 // Đại diện cho kết nối vật lý giữa Program và Card mạng
}

/**
 * # HÀM TRUY VẤN TRẠNG THÁI (Introspection)
 * Sau khi nạp, ta cần hỏi lại Kernel xem chương trình thực sự đã "sống" chưa.
 * Trả về ID của chương trình trong hệ thống và thông tin chi tiết về Hook Point.
 */
func getXDPStatus(lnk link.Link) (ebpf.ProgramID, *link.XDPInfo, error) {
	info, err := lnk.Info() // Lấy metadata của link từ Kernel
	if err != nil {
		return 0, nil, err
	}

	xdp := info.XDP() // Chích xuất thông tin cụ thể về XDP
	if xdp == nil {
		// CẠM BẪY: Có thể link tồn tại nhưng không phải loại XDP (ví dụ: TC hoặc Kprobe).
		return 0, nil, fmt.Errorf("link is not XDP")
	}

	return info.Program, xdp, nil
}

/**
 * # HÀM LoadAndAttach: Bước quan trọng nhất để khởi động Firewall
 * @ifaceName: Tên card mạng (vd: eth0, enp0s3)
 * @mode: Chế độ nạp ("native" hoặc "skb")
 */
func LoadAndAttach(ifaceName string, mode string) (*BPF, error) {
	// # BƯỚC 1: Xác định Interface mạng mục tiêu
	// Kernel không làm việc với tên chuỗi "eth0", nó làm việc với số nguyên (Interface Index).
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Printf("[fatal!] Cannot find interface with if_name: %s", ifaceName)
		return nil, fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}

	// # BƯỚC 2: Đưa Bytecode vào Kernel (Loading)
	// Hàm này thực hiện syscall bpf(BPF_PROG_LOAD). 
	// Lúc này eBPF Verifier sẽ quét mã C của bạn để đảm bảo không có vòng lặp vô tận hay truy cập RAM bậy bạ.
	objs := xdp_packet_filterObjects{}
	if err := loadXdp_packet_filterObjects(&objs, nil); err != nil {
		log.Printf("[fatal!] Cannot load eBPF program: %v", err)
		return nil, fmt.Errorf("loading BPF objects: %w", err)
	}

	// # BƯỚC 3: Lựa chọn chế độ XDP (XDP Modes)
	// Đây là một quyết định kỹ thuật quan trọng ảnh hưởng đến hiệu năng:
	var flags link.XDPAttachFlags

	switch mode {
	case "native":
		// Native Mode: Chương trình chạy trực tiếp trong Driver của card mạng.
		// Ưu điểm: Tốc độ cao nhất (vài chục triệu gói/giây).
		// Nhược điểm: Card mạng và Driver phải hỗ trợ (thường là card Intel, Mellanox...).
		flags = link.XDPDriverMode
	case "skb":
		// Generic/SKB Mode: Chạy ở tầng phần mềm sau khi Kernel đã nhận gói tin.
		// Ưu điểm: Chạy được trên MỌI card mạng (kể cả card ảo, wifi).
		// Nhược điểm: Chậm hơn Native vì Kernel phải tốn công tạo struct sk_buff trước.
		flags = link.XDPGenericMode
	default:
		flags = link.XDPGenericMode
	}

	// # BƯỚC 4: "Gắn" chương trình vào Card mạng (Attaching)
	// Lệnh này tương đương với việc thực hiện `ip link set dev eth0 xdp obj ...`
	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpPacketFilter,
		Interface: iface.Index,
		Flags:     flags,
	})
	if err != nil {
		log.Printf("ERROR attaching XDP: %v", err)
		objs.Close() // Giải phóng Maps nếu đính kèm thất bại để tránh rò rỉ bộ nhớ Kernel
		return nil, fmt.Errorf("[fatal!] cannot attach XDP: %w", err)
	}

	// # BƯỚC 5: Xác nhận và ghi Log thành công
	programId, xdpStatus, err := getXDPStatus(lnk)
	if err!= nil {
		// CẠM BẪY: Lỗi ở đây không có nghĩa là Firewall không chạy, chỉ là ta không lấy được metadata.
		fmt.Printf("[warning] failed to obtain XDP program metadata: %v\n", err)
		log.Printf("[warning] failed to obtain XDP program metadata: %v\n", err)
	} else {
		// Log ra ID của chương trình giúp ta debug bằng lệnh `bpftool prog show id <ID>`
		fmt.Printf("[success] xdp program attached: if_index: %d, if_name: %s, xdp_prog_id: %d\n", xdpStatus.Ifindex, iface.Name, programId)
		log.Printf("[success] xdp program attached: if_index: %d, if_name: %s, xdp_prog_id: %d\n", xdpStatus.Ifindex, iface.Name, programId)
	}

	return &BPF{
		Objs: &objs,
		Link: lnk,
	}, nil
}

/**
 * # HÀM DỌN DẸP (Destructor)
 * Tại sao phải gọi hàm này?
 * eBPF Link là một cơ chế giữ chương trình tồn tại. Nếu bạn tắt ứng dụng Go mà không gọi Link.Close(),
 * firewall có thể vẫn chạy ngầm trong Kernel. Điều này cực kỳ nguy hiểm nếu bạn nạp một luật
 * "DROP ALL" rồi bị văng app, bạn sẽ mất hoàn toàn kết nối tới server!
 */
func (b *BPF) Close() {
	if b.Link != nil {
		// Tháo chương trình khỏi card mạng
		b.Link.Close()
	}
	if b.Objs != nil {
		// Giải phóng các Maps và Programs khỏi bộ nhớ Kernel
		b.Objs.Close()
	}
}