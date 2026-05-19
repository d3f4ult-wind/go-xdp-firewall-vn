/**
 * =================================================================================
 * FILE: main.go
 * MÔ TẢ: Điểm khởi đầu của hệ thống Hanselgray XDP Firewall.
 * LUỒNG HOẠT ĐỘNG: 
 *   1. Khởi tạo Logging để theo dõi hệ thống.
 *   2. Đọc cấu hình từ file init.yaml.
 *   3. Nạp và đính kèm chương trình XDP vào Kernel (Data Plane).
 *   4. Khởi tạo logic quản lý luật (Control Plane).
 *   5. Chạy REST API Server trong tiến trình ngầm (Goroutine).
 *   6. Lắng nghe tín hiệu từ Hệ điều hành để tắt firewall an toàn.
 * CẢI TIẾN: Sử dụng cơ chế Signal Handling để đảm bảo tháo gỡ XDP khi tắt ứng dụng.
 * =================================================================================
 */

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"fmt"
	"xdpfilter/internal/bpf"
	"xdpfilter/internal/rest"
)

func main() {
	fmt.Println("[BOOT] xdp-fw starting")

	// # BƯỚC 1: Cấu hình Logging
	// TẠI SAO: Firewall chạy ở mức hệ thống nên cần ghi lại vết (audit log) để debug.
	// CẠM BẪY: /var/log thường yêu cầu quyền root. Nếu chạy không có sudo, app sẽ crash tại đây.
	logFile, err := os.OpenFile("/var/log/xdp-firewall.log",
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("failed to open log file: %v", err)
	}
	defer logFile.Close()

	log.SetOutput(logFile)
	// Log bao gồm cả micro giây và file nguồn để dễ dàng truy vết race-condition.
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)

	log.Println("xdp-firewall starting")

	// # BƯỚC 2: Đọc file cấu hình ban đầu
	cfg, err := bpf.LoadConfig("init.yaml")
	if err != nil {
		log.Fatalf("[fatal!] cannot load config, error: %v", err)
	}
	log.Printf("[success] config loaded")

	// # BƯỚC 3: Nạp Data-plane (Kernel-space)
	// Đây là thời điểm chương trình C được đẩy vào Kernel và gắn vào card mạng.
	bpfHandle, err := bpf.LoadAndAttach(cfg.Interface, cfg.Mode)
	if err != nil {
		log.Fatalf("[fatal!] Failed to initialize BPF data-plane, error: %v", err)
	}
	
	// CỰC KỲ QUAN TRỌNG: defer Close() đảm bảo khi main thoát, chương trình XDP 
	// sẽ được gỡ khỏi card mạng. Nếu không, server có thể bị mất mạng vĩnh viễn.
	defer bpfHandle.Close()

	log.Println("BPF dataplane loaded")

	// # BƯỚC 4: Khởi tạo Control-plane (User-space)
	// Kết nối các Map eBPF thực tế vào bộ máy quản lý Firewall trong Go.
	fw := bpf.New(
		bpfHandle.Objs.SubnetMap,
		bpfHandle.Objs.RuleMap,
		bpfHandle.Objs.DefaultActionMap,
		bpfHandle.Objs.RateLimitMap,
		bpfHandle.Objs.RlConfigMap,
	)   

	// Thiết lập hành động mặc định (vd: chặn hết hoặc cho qua hết).
	if err := fw.SetDefaultBehaviour(cfg.DefaultAction); err != nil {
		log.Fatalf("failed to set default action: %v", err)
	}
	log.Printf("default action set to %d", cfg.DefaultAction)

	// Nạp các luật tĩnh từ file cấu hình vào Kernel ngay khi khởi động.
	for _, rule := range cfg.Rules {
		if err := fw.AddRule(rule); err != nil {
			log.Fatalf("failed to load rule: %v", err)
		}
	}
	log.Printf("loaded %d rules", len(cfg.Rules))

	// # BƯỚC 5: Triển khai REST API Server
	api := rest.New(fw, bpfHandle)
	
	// TẠI SAO DÙNG GOROUTINE: api.Listen là một hàm "chặn" (blocking). 
	// Nếu không chạy ngầm, chương trình sẽ kẹt ở đây và không thể thực hiện 
	// logic dọn dẹp (Graceful Shutdown) ở phía dưới.
	go func() {
		log.Println("REST API listening on :8080")
		if err := api.Listen(":8080"); err != nil {
			// Nếu API chết, ta nên log lại nhưng không nhất thiết phải dừng toàn bộ firewall.
			log.Printf("REST API failed: %v", err)
		}
	}()

	// # BƯỚC 6: Quản lý vòng đời ứng dụng (Graceful Shutdown)
	// Tạo channel để lắng nghe các tín hiệu ngắt từ bàn phím (Ctrl+C) hoặc hệ thống.
	sig := make(chan os.Signal, 1)
	
	// SIGINT: Ctrl+C | SIGTERM: Lệnh kill từ hệ thống.
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Chương trình sẽ "treo" tại đây cho đến khi nhận được tín hiệu ngắt.
	<-sig
	
	// Lúc này các lệnh 'defer' sẽ được kích thực để dọn dẹp Kernel Maps và XDP Links.
	log.Println("shutting down")
}