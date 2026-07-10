/**
 * =================================================================================
 * FILE: suricata_tailer.go
 * MÔ TẢ: Đọc và phân tích log NIDS từ Suricata.
 * LUỒNG HOẠT ĐỘNG:
 *   1. Đọc liên tục file eve.json của Suricata (định dạng cấu trúc JSON).
 *   2. Bắt các sự kiện có `event_type` là "alert".
 *   3. Trích xuất `src_ip` và gọi XDP khóa chặn ngay ở Tầng 1/2 để bảo vệ hệ thống.
 * TẠI SAO LẠI KẾT HỢP SURICATA + XDP?
 *   Suricata rất giỏi trong việc phân tích Payload rác/xấu (DPI) bằng hàng ngàn luật,
 *   nhưng chặn (Drop) gói tin lại rất chậm. XDP thì siêu tốc nhưng không biết phân tích DPI.
 *   Sự kết hợp này mang lại sức mạnh "Kiếm hiệp": Suricata là con Mắt, XDP là thanh Kiếm.
 * =================================================================================
 */

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

type SuricataTailer struct {
	filePath     string
	bpfManager   *BPFManager
	geoHeuristic *GeoHeuristic
}

func NewSuricataTailer(path string, bpfManager *BPFManager, geoHeuristic *GeoHeuristic) *SuricataTailer {
	return &SuricataTailer{
		filePath:     path,
		bpfManager:   bpfManager,
		geoHeuristic: geoHeuristic,
	}
}

/**
 * # HÀM Start
 * Vòng lặp vô tận chờ và đọc file eve.json.
 */
func (t *SuricataTailer) Start() {
	fmt.Printf("[Suricata] Dang doi doc file: %s\n", t.filePath)
	
	// Mở file
	file, err := os.Open(t.filePath)
	if err != nil {
		fmt.Printf("[Suricata] WARNING: Khong the mo file log: %v. Tien trinh doc bi huy.\n", err)
		return
	}
	defer file.Close()

	// Di chuyển con trỏ tới cuối file để chỉ đọc các sự kiện mới
	file.Seek(0, io.SeekEnd)
	
	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				// Đợi file có thêm dữ liệu mới
				time.Sleep(500 * time.Millisecond)
				continue
			}
			fmt.Printf("[Suricata] Loi khi doc file: %v\n", err)
			time.Sleep(1 * time.Second)
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		t.processLine(line)
	}
}

// Cấu trúc JSON cơ bản của eve.json (tập trung vào trường src_ip và event_type)
type EveLog struct {
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
}

/**
 * # HÀM processLine
 * Cố gắng giải mã chuỗi text thành cấu trúc JSON. Nếu là một "Alert" (cảnh báo nguy hiểm),
 * lập tức chuyển IP đó cho BPFManager khóa chặn.
 */
func (t *SuricataTailer) processLine(line string) {
	var eve EveLog
	err := json.Unmarshal([]byte(line), &eve)
	if err != nil {
		// Log không phải JSON hợp lệ (hoặc lỗi parse)
		return
	}

	// Chỉ quan tâm đến các event có type là "alert"
	if eve.EventType == "alert" && eve.SrcIP != "" {
		fmt.Printf("[Suricata] Phat hien Alert tu IP: %s\n", eve.SrcIP)
		
		// Đẩy xuống eBPF
		err := t.bpfManager.BlockIP(eve.SrcIP)
		if err != nil {
			fmt.Printf("[Suricata] Loi khi block IP: %v\n", err)
		}

		// Báo cáo IP xấu cho Heuristic Engine để đếm theo quốc gia
		if t.geoHeuristic != nil {
			t.geoHeuristic.ReportBadIP(eve.SrcIP)
		}
	}
}
