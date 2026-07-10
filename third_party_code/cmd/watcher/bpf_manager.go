/**
 * =================================================================================
 * FILE: bpf_manager.go
 * MÔ TẢ: Cầu nối giao tiếp giữa Watcher Daemon và eBPF Map trong Kernel.
 * LUỒNG HOẠT ĐỘNG:
 *   1. Mở (load) file đại diện của eBPF Map từ hệ thống file ảo (bpf fs) đã được ghim.
 *   2. Cung cấp API nội bộ cho phép thêm/xóa các dải IP vào `auto_block_map`.
 * =================================================================================
 */

package main

import (
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf"
)

// LpmKey tương ứng với struct ipv4_lpm_key trong file xdp-filter.c
// Chú ý: Cấu trúc này phải khớp chính xác với bộ nhớ của Kernel.
type LpmKey struct {
	PrefixLen uint32
	Data      [4]byte
}

type BPFManager struct {
	autoBlockMap *ebpf.Map
}

/**
 * # HÀM NewBPFManager
 * Kết nối tới Map eBPF. 
 * TẠI SAO PHẢI PIN MAP? Do eBPF Map mặc định sẽ bị xóa khi chương trình tạo ra nó (Firewall chính) tắt.
 * Pin Map giúp map được lưu lại dưới dạng file trong thư mục /sys/fs/bpf/, cho phép các tiến trình
 * khác (như Watcher này) có thể đọc và ghi chung vào một bộ nhớ Kernel.
 */
func NewBPFManager(pinPath string) (*BPFManager, error) {
	// Load map đã được ghim từ hệ thống file ảo
	opts := &ebpf.LoadPinOptions{
		ReadOnly: false, // Ta cần ghi vào Map
	}
	m, err := ebpf.LoadPinnedMap(pinPath, opts)
	if err != nil {
		return nil, err
	}

	return &BPFManager{
		autoBlockMap: m,
	}, nil
}

/**
 * # HÀM BlockIP
 * Tiện ích: Chuyển đổi một địa chỉ IP lẻ thành định dạng Subnet (/32) để tương thích 
 * với cấu trúc LPM (Longest Prefix Match) của eBPF Map.
 */
// BlockIP nhận vào một chuỗi IP lẻ (tự động chuyển thành /32)
func (m *BPFManager) BlockIP(ipStr string) error {
	return m.BlockSubnet(ipStr + "/32")
}

/**
 * # HÀM BlockSubnet
 * Tính toán và chuyển đổi cấu trúc mạng (CIDR) thành mảng byte thô (Network Byte Order).
 * Sau đó đẩy xuống Kernel cùng với timestamp hiện tại (để phục vụ Auto-unban sau này).
 */
// BlockSubnet nhận vào một dải CIDR (vd: 192.168.1.0/24) và đẩy xuống LPM Trie
func (m *BPFManager) BlockSubnet(cidr string) error {
	ipStr, maskStr, err := net.ParseCIDR(cidr)
	var ip net.IP
	var masklen int
	
	if err != nil {
		// Thử parse như một IP thường nếu không có /
		ip = net.ParseIP(cidr)
		if ip == nil {
			return fmt.Errorf("CIDR khong hop le: %s", cidr)
		}
		masklen = 32
	} else {
		ip = ipStr
		masklen, _ = maskStr.Mask.Size()
	}

	ip = ip.To4()
	if ip == nil {
		return fmt.Errorf("Chi ho tro IPv4: %s", cidr)
	}

	key := LpmKey{
		PrefixLen: uint32(masklen),
	}
	copy(key.Data[:], ip)

	now := uint64(time.Now().Unix())

	if err := m.autoBlockMap.Update(&key, &now, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("Loi khi cap nhat map: %w", err)
	}

	fmt.Printf("[BPF] Da block: %s/%d vao luc %v\n", ip.String(), masklen, time.Now().Format("15:04:05"))
	return nil
}

/**
 * # HÀM RemoveSubnet
 * Xóa một entry khỏi danh sách chặn tự động. 
 * Gọi khi IP đó đã hết hạn khóa chặn (ban duration).
 */
// RemoveSubnet xóa Subnet/IP khỏi sổ đen bằng LpmKey
func (m *BPFManager) RemoveSubnet(key LpmKey) error {
	err := m.autoBlockMap.Delete(&key)
	if err != nil {
		return err
	}
	
	ipStr := net.IP(key.Data[:]).String()
	fmt.Printf("[BPF] Da UNBAN: %s/%d\n", ipStr, key.PrefixLen)
	return nil
}

func (m *BPFManager) Close() {
	if m.autoBlockMap != nil {
		m.autoBlockMap.Close()
	}
}
