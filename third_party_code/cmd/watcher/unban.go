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
