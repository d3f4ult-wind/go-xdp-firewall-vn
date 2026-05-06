/**
 * =================================================================================
 * FILE: action.go
 * MÔ TẢ: Định nghĩa và chuyển đổi các hành động (Actions) của Firewall.
 * LUỒNG HOẠT ĐỘNG: 
 *   Ánh xạ hai chiều giữa mã thực thi XDP (uint32) và chuỗi ký tự (String) của API.
 * TẠI SAO PHẢI CÓ FILE NÀY:
 *   Trong Kernel, XDP_DROP là 1 và XDP_PASS là 2. Nếu trả về số 1 hoặc 2 qua API,
 *   người dùng sẽ rất khó hiểu. File này giúp chuẩn hóa dữ liệu đầu ra/vào.
 * =================================================================================
 */

package rest

import "strings"

// Các hằng số hành động tương ứng với định nghĩa trong Linux Kernel (XDP Actions).
// CẠM BẪY: Đừng tự ý thay đổi các con số này. XDP_ABORTED=0, XDP_DROP=1, XDP_PASS=2.
const (
	ActionDrop uint32 = 1 // Chặn và hủy gói tin ngay lập tức
	ActionPass uint32 = 2 // Cho phép gói tin đi tiếp vào Network Stack của Kernel
)

// Map ánh xạ để tra cứu nhanh khi hiển thị (List Rules).
var actionToString = map[uint32]string{
	ActionDrop: "DROP",
	ActionPass: "PASS",
}

// Map ánh xạ ngược để tra cứu khi nhận dữ liệu từ API (Add Rule).
var stringToAction = map[string]uint32{
	"DROP": ActionDrop,
	"PASS": ActionPass,
}

/**
 * Chuyển số uint32 sang chuỗi mô tả.
 * Nếu là một số lạ (không phải 1 hoặc 2), trả về UNKNOWN để tránh gây crash.
 */
func ActionToString(a uint32) string {
	if s, ok := actionToString[a]; ok {
		return s
	}
	return "UNKNOWN"
}

/**
 * Chuyển chuỗi từ API (vd: "drop", "Pass") sang số mà Kernel hiểu.
 * SỬ DỤNG strings.ToUpper: Để API linh hoạt hơn, chấp nhận cả chữ hoa lẫn chữ thường.
 */
func ParseAction(s string) (uint32, bool) {
	a, ok := stringToAction[strings.ToUpper(s)]
	return a, ok
}

/**
 * Kiểm tra xem một mã hành động có nằm trong phạm vi cho phép không.
 * TẠI SAO: Tránh việc người dùng gửi các giá trị rác xuống Kernel gây lỗi Verifier hoặc logic sai.
 */
func ValidAction(a uint32) bool {
	return a == ActionDrop || a == ActionPass
}