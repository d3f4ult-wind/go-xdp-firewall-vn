/**
 * =================================================================================
 * FILE: main.go
 * MÔ TẢ: Điểm khởi đầu (Entry point) của Watcher Daemon độc lập.
 * LUỒNG HOẠT ĐỘNG:
 *   1. Kết nối với eBPF Map `auto_block_map` đã được ghim sẵn bởi Control Plane chính.
 *   2. Khởi tạo và chạy song song các tiến trình:
 *      - Đọc log Suricata (NIDS) và Iptables (Log rules).
 *      - Quản lý khóa dải IP theo quốc gia (GeoIP) kết hợp Heuristic.
 *      - Tiến trình quét định kỳ để tự động mở khóa (Auto-unban) các IP đã hết hạn.
 * TẠI SAO LẠI TÁCH RỜI KHỎI CONTROL PLANE CHÍNH?
 *   - Giúp module này hoạt động độc lập, có thể bảo trì, nâng cấp, hoặc thay thế 
 *     bằng các công nghệ đọc log khác (như Filebeat/Logstash) mà không cần biên dịch 
 *     lại lõi Firewall (Go Controller).
 * =================================================================================
 */

package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

/**
 * # HÀM main
 * Quản lý vòng đời của Watcher Daemon. Khởi tạo tất cả các thành phần và chặn luồng 
 * chờ tín hiệu tắt (Ctrl+C).
 */
func main() {
	fmt.Println("[*] XDP Watcher (Management Daemon) is starting...")

	// 1. Kết nối với eBPF Map đã được Pin bởi dự án Go XDP
	bpfManager, err := NewBPFManager("/sys/fs/bpf/xdp_auto_block")
	if err != nil {
		log.Fatalf("Khong the ket noi toi BPF Map: %v\n(Hay chac chan rang Firewall chinh dang chay va da Pin map)", err)
	}
	defer bpfManager.Close()

	// 2. Khởi chạy tiến trình Auto-unban (quét định kỳ)
	unbanService := NewUnbanService(bpfManager, 15*60) // 15 phút
	go unbanService.Start()

	// 4. Khởi chạy bộ theo dõi GeoIP
	geoMonitor := NewGeoIPMonitor(
		bpfManager, 
		"../../GeoLite2-Country-Blocks-IPv4.csv",
		"../../GeoLite2-Country-Locations-en.csv",
	)
	go geoMonitor.Start()

	// Khởi tạo Heuristic Engine phân tích IP (Dynamic Geo-Blocking)
	geoHeuristic := NewGeoHeuristic("../../GeoLite2-Country.mmdb", geoMonitor)
	defer geoHeuristic.Close()

	// 3. Khởi chạy tiến trình đọc log Suricata
	// Chú ý: Đường dẫn file eve.json tùy thuộc vào cấu hình hệ thống của bạn
	suricataTailer := NewSuricataTailer("/var/log/suricata/eve.json", bpfManager, geoHeuristic)
	go suricataTailer.Start()

	// 5. Khởi chạy tiến trình đọc log Iptables
	// NẾU HỆ THỐNG CỦA BẠN GHI LOG IPTABLES RA FILE KHÁC (vd: /var/log/kern.log hoặc /var/log/messages)
	// Hãy thay đổi chuỗi "/var/log/syslog" ở dưới đây thành đường dẫn tương ứng!
	iptablesTailer := NewIptablesTailer("/var/log/syslog", bpfManager, geoHeuristic)
	go iptablesTailer.Start()

	// Giữ cho chương trình chạy cho đến khi nhận được tín hiệu dừng (Ctrl+C)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\n[*] XDP Watcher is shutting down...")
}
