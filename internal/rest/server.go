/**
 * =================================================================================
 * FILE: server.go
 * MÔ TẢ: Khởi tạo và quản lý HTTP REST Server.
 * LUỒNG HOẠT ĐỘNG: 
 *   1. Nhận các Handle (con trỏ) của Firewall và BPF.
 *   2. Đăng ký các tuyến đường (Routes).
 *   3. Lắng nghe và phục vụ các yêu cầu HTTP.
 * =================================================================================
 */

package rest

import (
	"log"
	"net/http"

	"xdpfilter/internal/bpf"
)

/**
 * Server struct lưu trữ mọi "vũ khí" cần thiết để phục vụ yêu cầu.
 */
type Server struct {
	fw  *bpf.Firewall // Để thực hiện thêm/xóa luật
	bpf *bpf.BPF      // Để truy cập trạng thái nạp của driver
	mux *http.ServeMux // Bộ định tuyến của Go chuẩn
}

/**
 * Khởi tạo Server mới (Dependency Injection).
 * TẠI SAO: Chúng ta truyền fw và bpfHandle vào để Server có thể tương tác 
 * trực tiếp với lõi Firewall mà không cần khởi tạo lại, đảm bảo tính duy nhất (Singleton).
 */
func New(fw *bpf.Firewall, bpfHandle *bpf.BPF) *Server {
	s := &Server{
		fw:  fw,
		bpf: bpfHandle,
		mux: http.NewServeMux(),
	}

	// # BƯỚC 1: Đăng ký các Endpoint
	s.routes()
	return s
}

/**
 * Định nghĩa danh sách API.
 * - /rules: Quản lý danh sách luật (GET/POST/DELETE).
 * - /default: Quản lý hành động mặc định khi không khớp luật nào.
 * - /health: Xem tình trạng máy chủ.
 */
func (s *Server) routes() {
	s.mux.HandleFunc("/rules", s.handleRules)
	s.mux.HandleFunc("/default", s.handleDefault)
	s.mux.HandleFunc("/health", s.handleHealth)
	
	// Auto Block API (Suricata/Iptables Threat Intel)
	s.mux.HandleFunc("/autoblock/ips", s.handleAutoBlockedIPs)
	
	// Rate Limiting APIs
	s.mux.HandleFunc("/ratelimit/ips", s.handleRateLimitIPs)
	s.mux.HandleFunc("/ratelimit/config", s.handleRateLimitConfig)
}

/**
 * # BƯỚC 2: Kích hoạt máy chủ
 * addr: Thường là "0.0.0.0:8080" hoặc "localhost:8080".
 * CẠM BẪY: ListenAndServe là hàm chặn (blocking). Nếu bạn gọi nó trong main
 * mà không dùng Goroutine, chương trình sẽ đứng yên tại đây.
 */
func (s *Server) Listen(addr string) error {
	log.Printf("Starting REST server on %s", addr)
	return http.ListenAndServe(addr, s.mux)
}