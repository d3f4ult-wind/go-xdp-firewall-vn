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
	filePath   string
	bpfManager *BPFManager
}

func NewSuricataTailer(path string, bpfManager *BPFManager) *SuricataTailer {
	return &SuricataTailer{
		filePath:   path,
		bpfManager: bpfManager,
	}
}

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
	}
}
