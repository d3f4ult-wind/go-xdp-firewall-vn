/**
 * =================================================================================
 * FILE: unban.go
 * MÔ TẢ: Tiến trình ngầm tự động dọn dẹp các IP đã bị chặn khỏi sổ đen.
 * LUỒNG HOẠT ĐỘNG:
 *   1. Chạy một vòng lặp quét đếm ngược (Ticker).
 *   2. Duyệt toàn bộ các entry đang nằm trong `auto_block_map` của Kernel.
 *   3. Kiểm tra Timestamp lúc bắt đầu block. Nếu quá hạn (Ban Duration) -> Xóa khỏi Map.
 * TẠI SAO CẦN UNBAN:
 *   - Các đợt DDoS thường chỉ diễn ra theo đợt (Wave).
 *   - Rất có thể các IP bị tấn công là IP botnet hoặc IP người dùng bị spoofing.
 *   - Nếu block vĩnh viễn, map sẽ đầy (đạt giới hạn Max Entries) và gây tắc nghẽn dịch vụ.
 * =================================================================================
 */

package main

import (
	"fmt"
	"time"
)

type UnbanService struct {
	bpfManager    *BPFManager
	banDuration   uint64 // Thời gian ban tính bằng giây
	checkInterval time.Duration
}

func NewUnbanService(bpfManager *BPFManager, banDurationSeconds uint64) *UnbanService {
	return &UnbanService{
		bpfManager:    bpfManager,
		banDuration:   banDurationSeconds,
		checkInterval: 10 * time.Second, // Quét 10 giây 1 lần
	}
}

func (s *UnbanService) Start() {
	fmt.Printf("[Unban] Khoi dong tien trinh Auto-unban (Thoi gian block: %d giay)...\n", s.banDuration)
	ticker := time.NewTicker(s.checkInterval)
	defer ticker.Stop()

	for range ticker.C {
		s.sweep()
	}
}

/**
 * # HÀM sweep (Quét dọn)
 * Khởi tạo Iterator duyệt qua Kernel Map (eBPF). 
 * CẠM BẪY: Việc duyệt qua BPF Map có chi phí (cost) khá cao so với Map thường trên RAM.
 * Do đó, tần suất quét (checkInterval) không nên quá nhỏ.
 */
func (s *UnbanService) sweep() {
	now := uint64(time.Now().Unix())
	
	// Khởi tạo một Iterator để quét toàn bộ Map
	entries := s.bpfManager.autoBlockMap.Iterate()
	var key LpmKey
	var value uint64

	for entries.Next(&key, &value) {
		// value chính là timestamp lúc bắt đầu block
		if now - value >= s.banDuration {
			// Đã hết hạn block -> Xóa khỏi map
			err := s.bpfManager.RemoveSubnet(key)
			if err != nil {
				fmt.Printf("[Unban] Loi khi xoa Subnet/IP: %v\n", err)
			}
		}
	}

	if err := entries.Err(); err != nil {
		fmt.Printf("[Unban] Loi khi duyet Map: %v\n", err)
	}
}
