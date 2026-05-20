package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

type IptablesTailer struct {
	filePath   string
	bpfManager *BPFManager
	// Regex để tìm kiếm chuỗi dạng "SRC=192.168.1.100" trong dòng log của iptables
	srcIpRegex *regexp.Regexp
}

// NewIptablesTailer khởi tạo bộ đọc log Iptables.
// Mặc định Iptables thường ghi log ra /var/log/syslog (Ubuntu/Debian) hoặc /var/log/messages (CentOS).
// CHÚ Ý: Nếu hệ thống của bạn cấu hình Iptables ghi log ra file khác (vd: /var/log/kern.log), 
// hãy sửa đường dẫn này trong file main.go khi khởi tạo NewIptablesTailer.
func NewIptablesTailer(path string, bpfManager *BPFManager) *IptablesTailer {
	return &IptablesTailer{
		filePath:   path,
		bpfManager: bpfManager,
		srcIpRegex: regexp.MustCompile(`SRC=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)`),
	}
}

func (t *IptablesTailer) Start() {
	fmt.Printf("[Iptables] Dang doi doc file log: %s\n", t.filePath)
	
	file, err := os.Open(t.filePath)
	if err != nil {
		fmt.Printf("[Iptables] WARNING: Khong the mo file log: %v. Tien trinh doc bi huy.\n", err)
		return
	}
	defer file.Close()

	// Di chuyển con trỏ tới cuối file để chỉ đọc các sự kiện mới nhất
	file.Seek(0, io.SeekEnd)
	
	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			fmt.Printf("[Iptables] Loi khi doc file: %v\n", err)
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

func (t *IptablesTailer) processLine(line string) {
	// Dựa vào file iptables.rules của bạn, bạn đang sử dụng tiền tố "--log-prefix '[FW-DOS]'"
	// Chúng ta chỉ phân tích các dòng có chứa tiền tố này để tiết kiệm CPU
	if strings.Contains(line, "[FW-DOS]") {
		matches := t.srcIpRegex.FindStringSubmatch(line)
		if len(matches) > 1 {
			srcIP := matches[1]
			fmt.Printf("[Iptables] Phat hien tan cong tu IP: %s\n", srcIP)
			
			// Đẩy xuống eBPF Map
			err := t.bpfManager.BlockIP(srcIP)
			if err != nil {
				fmt.Printf("[Iptables] Loi khi block IP: %v\n", err)
			}
		}
	}
}
