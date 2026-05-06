/**
 * =================================================================================
 * FILE: health.go
 * MÔ TẢ: Thu thập tài nguyên hệ thống (System Metrics).
 * LUỒNG HOẠT ĐỘNG: 
 *   Sử dụng thư viện `gopsutil` để đọc thông tin từ file system ảo của Linux (/proc).
 * TẠI SAO CẦN:
 *   XDP xử lý gói tin cực nhanh, nhưng nếu logic ở User-space (như nạp luật liên tục)
 *   bị lỗi, nó có thể "ăn" hết CPU. Đây là công cụ giám sát cơ bản.
 * =================================================================================
 */

package rest

import (
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"time"
)

/**
 * Lấy dung lượng RAM đã sử dụng (đơn vị MB).
 */
func getMemMB() (uint64, error) {
	v, err := mem.VirtualMemory()
	if err != nil {
		return 0, err
	}
	// Quy đổi từ Bytes sang MB (chia cho 1024 hai lần) để con người dễ đọc.
	return v.Used / 1024 / 1024, nil
}

/**
 * Lấy phần trăm sử dụng CPU.
 * LÝ DO DÙNG time.Second: 
 *   CPU Usage không phải là một con số tức thời tại một thời điểm (snapshot). 
 *   Nó cần một khoảng thời gian quan sát (sampling window) để tính toán tỉ lệ 
 *   thời gian CPU "bận" so với thời gian "rảnh". 1 giây là khoảng thời gian hợp lý.
 */
func getCPUPercent() (float64, error) {
	p, err := cpu.Percent(time.Second, false)
	if err != nil || len(p) == 0 {
		return 0, err
	}
	// Trả về phần trăm của nhân CPU đầu tiên hoặc trung bình (tùy cấu hình flags).
	return p[0], nil
}