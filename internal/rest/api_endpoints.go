/**
 * =================================================================================
 * FILE: api_endpoints.go
 * MÔ TẢ: Hiện thực chi tiết các HTTP Handlers cho Firewall.
 * LUỒNG HOẠT ĐỘNG: 
 *   1. Nhận Request (JSON) từ người dùng.
 *   2. Validate dữ liệu (kiểm tra định dạng CIDR, Protocol, Port).
 *   3. Chuyển đổi dữ liệu sang struct nội bộ của tầng BPF.
 *   4. Gọi các hàm của Firewall để cập nhật eBPF Maps.
 *   5. Trả về phản hồi (Status Code/JSON).
 * =================================================================================
 */

package rest 

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"fmt"
	"xdpfilter/internal/bpf"
)

// -----------------------
// --- Rules REST APIs ---
// -----------------------

/**
 * # Cấu trúc RuleRequest
 * Định dạng dữ liệu mà API mong đợi từ phía Client (Frontend/Postman).
 * TẠI SAO: Action ở đây là 'string' ("DROP"/"PASS") để thân thiện với người dùng,
 * sau đó mới được parse thành uint32 cho Kernel.
 */
type RuleRequest struct {
	Subnet string `json:"subnet"` // Định dạng CIDR: "192.168.1.0/24"
	Proto  int32  `json:"proto"`  // 6 cho TCP, 17 cho UDP, 1 cho ICMP
	Port   uint32 `json:"port"`   // Cổng đích
	Action string `json:"action"` // "DROP" hoặc "PASS"
}

/**
 * # Hàm handleRules (Multiplexer)
 * Điều hướng yêu cầu dựa trên HTTP Method.
 */
func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.addRule(w, r)
	case http.MethodDelete:
		s.deleteRule(w, r)
	case http.MethodGet:
		s.listRules(w)
	default:
		// Trả về 405 nếu Client dùng sai Method (vd: PUT)
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

/**
 * # HÀM addRule (POST /rules)
 */
func (s *Server) addRule(w http.ResponseWriter, r *http.Request) {
	// # BƯỚC 1: Giải mã JSON từ body của Request
	var req RuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON format", 400)
		return
	}

	// # BƯỚC 2: Kiểm tra và chuyển đổi Action string -> uint32
	// CẠM BẪY: Tuyệt đối không đẩy trực tiếp chuỗi xuống tầng dưới.
	action, ok := ParseAction(req.Action)
	if !ok {
		http.Error(w, "Action must be PASS or DROP", 400)
		return
	}

	// # BƯỚC 3: Phân tích cú pháp CIDR
	// net.ParseCIDR kiểm tra xem chuỗi có đúng định dạng IP/Mask không.
	ip, ipnet, err := net.ParseCIDR(req.Subnet)
	if err != nil {
		http.Error(w, "Invalid subnet format (e.g., 192.168.1.0/24)", 400)
		return
	}

	// # BƯỚC 4: Chuẩn hóa dữ liệu IPv4
	// To4() đảm bảo đây là địa chỉ IPv4 hợp lệ. Nếu là IPv6, nó trả về nil.
	ip = ip.To4()
	if ip == nil {
		http.Error(w, "Only IPv4 is supported", 400)
		return
	}

	maskLen, bits := ipnet.Mask.Size()
	if bits != 32 {
		http.Error(w, "Invalid IPv4 mask bits", 400)
		return
	}

	// Đưa địa chỉ về dạng mạng chuẩn (Canonical). 
	// Vd: 192.168.1.5/24 -> 192.168.1.0/24
	network := ip.Mask(ipnet.Mask)

	// # BƯỚC 5: Tạo đối tượng Rule và đẩy xuống Kernel thông qua Firewall Core
	rule := bpf.Rule{
		Addr:    network,
		Masklen: uint32(maskLen),
		Port:    req.Port,
		Proto:   req.Proto,
		Action:  uint32(action), 
	}

	if err := s.fw.AddRule(rule); err != nil {
		// Trả về 500 nếu có lỗi khi ghi vào eBPF Map (thường do Map đầy hoặc lỗi Kernel)
		http.Error(w, err.Error(), 500)
		return
	}
	
	w.WriteHeader(http.StatusCreated) // 201 Created
}

/**
 * # HÀM deleteRule (DELETE /rules)
 */
func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request) {
	// Quy trình xử lý tương tự addRule nhưng gọi hàm DeleteRule của core.
	var req RuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	ip, ipnet, err := net.ParseCIDR(req.Subnet)
	if err != nil {
		http.Error(w, "invalid subnet", 400)
		return
	}

	ip = ip.To4()
	if ip == nil {
		http.Error(w, "only IPv4 is supported", 400)
		return
	}

	maskLen, _ := ipnet.Mask.Size()
	network := ip.Mask(ipnet.Mask)

	rule := bpf.Rule{
		Addr:    network,
		Masklen: uint32(maskLen),
		Port:    req.Port,
		Proto:   req.Proto,
	}

	if err := s.fw.DeleteRule(rule); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.WriteHeader(http.StatusOK) // 200 OK
}

/**
 * # HÀM listRules (GET /rules)
 * Liệt kê các luật đang chạy.
 */
func (s *Server) listRules(w http.ResponseWriter) {
	// # BƯỚC 1: Lấy danh sách luật từ tầng BPF (đọc từ eBPF Maps)
	rules, err := s.fw.ListRules()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// # BƯỚC 2: Chuyển đổi dữ liệu để trả về JSON
	resp := make([]RuleRequest, 0, len(rules))

	for _, r := range rules {
		// Chuyển đổi ngược từ mã số XDP sang chuỗi chữ cho người dùng dễ đọc
		actionStr, ok := actionToString[r.Action]
		if !ok {
			actionStr = "UNKNOWN"
		}

		subnet := fmt.Sprintf("%s/%d", r.Addr.String(), r.Masklen)

		resp = append(resp, RuleRequest{
			Subnet: subnet,
			Port:   r.Port,
			Proto:  r.Proto,
			Action: actionStr,
		})
	}

	// # BƯỚC 3: Encode và gửi phản hồi JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// -----------------------------------
// --- Default behaviour REST APIs ---
// -----------------------------------

type DefaultRequest struct {
	Action string `json:"action"`
}

/**
 * # handleDefault
 * Quản lý chính sách mặc định của toàn hệ thống (Default Action).
 */
func (s *Server) handleDefault(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.getDefault(w)
	case http.MethodPost:
		s.setDefault(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) getDefault(w http.ResponseWriter) {
	action, err := s.fw.GetDefaultBehaviour()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	actionStr, ok := actionToString[action]
	if !ok {
		actionStr = "UNKNOWN"
	}

	json.NewEncoder(w).Encode(DefaultRequest{Action: actionStr})
}

func (s *Server) setDefault(w http.ResponseWriter, r *http.Request) {
	var req DefaultRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	action, ok := stringToAction[strings.ToUpper(req.Action)]
	if !ok {
		http.Error(w, "invalid action (must be PASS or DROP)", 400)
		return
	}

	if err := s.fw.SetDefaultBehaviour(action); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// -----------------------------------
// --- Auto Block APIs             ---
// -----------------------------------

func (s *Server) handleAutoBlockedIPs(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		ips, err := s.fw.ListAutoBlockedIPs()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ips)
		return
	}

	if r.Method == http.MethodDelete {
		var req struct {
			CIDR string `json:"cidr"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}

		if err := s.fw.DeleteAutoBlockedIP(req.CIDR); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		w.WriteHeader(http.StatusOK)
		return
	}

	w.WriteHeader(http.StatusMethodNotAllowed)
}

// -----------------------------------
// --- Rate Limiting APIs          ---
// -----------------------------------

func (s *Server) handleRateLimitIPs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	ips, err := s.fw.ListRateLimitedIPs()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ips)
}

type RateLimitConfigRequest struct {
	PPS      uint32 `json:"pps"`
	WindowMs uint32 `json:"window_ms"`
}

func (s *Server) handleRateLimitConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		pps, err1 := s.fw.GetRateLimitThreshold()
		win, err2 := s.fw.GetRateLimitWindow()
		if err1 != nil {
			http.Error(w, err1.Error(), 500)
			return
		}
		if err2 != nil {
			http.Error(w, err2.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RateLimitConfigRequest{
			PPS:      pps,
			WindowMs: win,
		})

	case http.MethodPost:
		var req RateLimitConfigRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", 400)
			return
		}

		if err := s.fw.SetRateLimitThreshold(req.PPS); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		if err := s.fw.SetRateLimitWindow(req.WindowMs); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// ------------------------
// --- Health check API ---
// ------------------------

/**
 * # Cấu trúc HealthStatus
 * Trả về thông tin giám sát hệ thống.
 */
type HealthStatus struct {
	Status      string  `json:"status"`       // Luôn là "ok" nếu server sống
	XDPAttached bool    `json:"xdp_attached"` // Firewall đã được nạp vào card mạng chưa?
	CPUPercent  float64 `json:"cpu_percent"`  // Tải CPU hiện tại
	MemoryMB    uint64  `json:"memory_mb"`    // RAM đã sử dụng
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Lấy thông tin từ các helper trong health.go
	cpuPct, err := getCPUPercent()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	memMB, err := getMemMB()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// Kiểm tra xem Handle XDP Link còn tồn tại không
	attached := false
	if s.bpf != nil && s.bpf.Link != nil {
			attached = true
	}

	health := HealthStatus{
			Status:      "ok",
			XDPAttached: attached,
			CPUPercent:  cpuPct,
			MemoryMB:    memMB,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}