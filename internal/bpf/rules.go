package bpf 

import ( 
	"net"
	"fmt"
	"time"
	"encoding/binary"
	"github.com/cilium/ebpf"
)

/**
 * =================================================================================
 * FILE: rules.go
 * MÔ TẢ: Quản lý logic nghiệp vụ và cập nhật luật vào eBPF Maps.
 * LUỒNG HOẠT ĐỘNG:
 *   1. Chuyển đổi dữ liệu IP/CIDR từ người dùng sang định dạng nhị phân phù hợp với Kernel.
 *   2. Quản lý ánh xạ 2 tầng: 
 *      - Tầng 1: IP/Subnet -> PolicyID (Sử dụng LPM Trie Map).
 *      - Tầng 2: PolicyID + Protocol + Port -> Action (Sử dụng Hash Map).
 * TẠI SAO PHẢI DÙNG 2 TẦNG?
 *   - Để tối ưu bộ nhớ. Một Subnet có thể có hàng trăm luật (Rule). Nếu lưu IP trực tiếp
 *     vào mỗi luật, bộ nhớ Map sẽ phình to rất nhanh. Việc ánh xạ qua PolicyID giúp
 *     gom nhóm các luật theo dải mạng một cách khoa học.
 * =================================================================================
 */

// ------------------------
// --- Helper functions ---
// ------------------------

/**
 * Tra cứu PolicyID dựa trên IP và Mask.
 * TẠI SAO: Giúp kiểm tra xem dải mạng này đã được định nghĩa trong Kernel chưa.
 */
func (fw *Firewall) lookupPolicyID(ip net.IP, masklen uint32) (uint32, error) {
		key := xdp_packet_filterIpv4LpmKey{
				Prefixlen: masklen,
		}
		// Sửa lỗi: eBPF bây giờ dùng mảng [4]byte cho LPM thay vì uint32
		// nên không dùng BigEndian.Uint32 nữa, mà copy trực tiếp từ slice To4()
		copy(key.Addr[:], ip.To4())

		var policyID uint32
		err := fw.ipTrie.Lookup(&key, &policyID)
		if err != nil {
				return 0, err
		}
		return policyID, nil
}

/**
 * Cập nhật luật L4 (Port/Proto) vào Hash Map.
 */
func (fw *Firewall) updateRule(policyID uint32, r Rule) error {
		key := xdp_packet_filterRuleId{
				SubnetId: policyID,
				Proto:    int32(r.Proto),
				Port:     r.Port,
		}
		// ebpf.UpdateAny: Ghi đè nếu đã tồn tại, hoặc tạo mới nếu chưa có.
		return fw.policies.Update(&key, &r.Action, ebpf.UpdateAny)
}

/**
 * Xóa luật L4 khỏi Kernel.
 */
func (fw *Firewall) deleteRule(policyID uint32, r Rule) error {
		key := xdp_packet_filterRuleId{
				SubnetId: policyID,
				Proto:    int32(r.Proto),
				Port:     r.Port,
		}

		return fw.policies.Delete(&key)
}

// -----------------------------------------------------------
// --- CRUD function for maps, these are called by the API ---
// -----------------------------------------------------------

/**
 * # HÀM AddRule: Thêm một luật mới vào hệ thống
 */
func (fw *Firewall) AddRule(r Rule) error {
		// # BƯỚC 1: Kiểm tra tính hợp lệ của dữ liệu đầu vào
		if r.Addr == nil || r.Addr.To4() == nil {
				return fmt.Errorf("only IPv4 is supported")
		}
		if r.Masklen > 32 {
				return fmt.Errorf("invalid mask length %d", r.Masklen)
		}

		// # BƯỚC 2: Chuẩn hóa địa chỉ mạng (Canonical Address)
		// TẠI SAO: Nếu người dùng nhập 192.168.1.5/24, ta phải đưa về 192.168.1.0/24.
		// Nếu không chuẩn hóa, LPM Trie có thể hoạt động không chính xác hoặc tạo ra các entry rác.
		mask := net.CIDRMask(int(r.Masklen), 32)
		network := r.Addr.Mask(mask)

		// Tạo chuỗi prefix làm key để cache ở User-space (vd: "192.168.1.0/24")
		prefix := fmt.Sprintf("%s/%d", network.String(), r.Masklen)

		fw.mu.Lock()
		// # BƯỚC 3: Quản lý PolicyID
		// Kiểm tra xem Subnet này đã có ID chưa (tránh tạo ID trùng lặp cho cùng một dải mạng)
		policyID, exists := fw.prefixToID[prefix]

		if !exists {
				// Cấp phát ID mới nếu dải mạng lần đầu xuất hiện
				policyID = fw.nextID
				fw.nextID++

				// Chuẩn bị key cho Kernel LPM
				lpmKey := xdp_packet_filterIpv4LpmKey{
						Prefixlen: r.Masklen,
				}
				copy(lpmKey.Addr[:], network.To4())

				// # BƯỚC 4: Đẩy dải mạng xuống Kernel LPM Map
				// ebpf.UpdateNoExist: Đảm bảo không ghi đè nếu có sự cố trùng lặp ngoài ý muốn.
				if err := fw.ipTrie.Update(&lpmKey, &policyID, ebpf.UpdateNoExist); err != nil {
						fw.mu.Unlock()
						return fmt.Errorf("failed to insert prefix into LPM trie: %w", err)
				}

				// Lưu vào cache của Firewall để phục vụ tra cứu nhanh và liệt kê luật sau này
				fw.prefixToID[prefix] = policyID
				fw.idToPrefix[policyID] = lpmKey
		}
		fw.mu.Unlock()

		// # BƯỚC 5: Cập nhật luật cụ thể (Port/Proto/Action) xuống Kernel Hash Map
		fmt.Printf("[DEBUG] Đang thêm luật: Subnet=%s/%d, Proto=%d, Port=%d, Action=%d, PolicyID=%d\n",
				network.String(), r.Masklen, r.Proto, r.Port, r.Action, policyID)
		return fw.updateRule(policyID, r)
}

/**
 * # HÀM DeleteRule: Xóa luật
 */
func (fw *Firewall) DeleteRule(r Rule) error {
		// # BƯỚC 1: Tìm PolicyID tương ứng với Subnet
		mask := net.CIDRMask(int(r.Masklen), 32)
		network := r.Addr.Mask(mask)
		prefix := fmt.Sprintf("%s/%d", network.String(), r.Masklen)

		fw.mu.RLock()
		policyID, exists := fw.prefixToID[prefix]
		fw.mu.RUnlock()
		
		if !exists {
				return fmt.Errorf("policyID matching subnet %s/%d not found", network.String(), r.Masklen)
		}

		// # BƯỚC 2: Xóa luật khỏi Hash Map trong Kernel
		// CẠM BẪY: Hiện tại hàm này chỉ xóa luật L4. Nếu đây là luật cuối cùng của Subnet đó,
		// ta vẫn chưa xóa Subnet khỏi ipTrie. Trong một hệ thống thực tế, bạn cần thêm 
		// cơ chế đếm (reference counting) để dọn dẹp ipTrie khi không còn luật nào dùng ID đó.
		fmt.Printf("[DEBUG] Đang xóa luật: Subnet=%s/%d, Proto=%d, Port=%d, PolicyID=%d\n",
				network.String(), r.Masklen, r.Proto, r.Port, policyID)
		return fw.deleteRule(policyID, r)
}

/**
 * # HÀM ListRules: Liệt kê toàn bộ luật đang chạy
 */
func (fw *Firewall) ListRules() ([]Rule, error) {
		fmt.Printf("[DEBUG] Đang lấy danh sách tất cả các luật (ListRules)\n")
		var rules []Rule

		// # BƯỚC 1: Duyệt qua toàn bộ Hash Map (Rule Map) trong Kernel
		// TẠI SAO: Dữ liệu trong Kernel là "Sự thật cuối cùng" (Source of Truth).
		iter := fw.policies.Iterate()
		var key xdp_packet_filterRuleId
		var action uint32

		fw.mu.RLock()
		defer fw.mu.RUnlock()

		for iter.Next(&key, &action) {
				// # BƯỚC 2: Ánh xạ ngược từ SubnetID sang IP/Mask
				// Vì trong Hash Map chỉ lưu ID, ta phải dùng cache idToPrefix để lấy lại IP gốc.
				prefix, ok := fw.idToPrefix[key.SubnetId]
				if !ok {
						continue // Skip nếu ID không tồn tại trong cache (lỗi đồng bộ)
				}

				ip := make(net.IP, 4)
				copy(ip, prefix.Addr[:])

				rules = append(rules, Rule{
						Addr:     ip,
						Masklen:  prefix.Prefixlen,
						Port:     key.Port,
						Proto:    key.Proto,
						Action:   action,
				})
		}

		if err := iter.Err(); err != nil {
				return nil, err
		}

		return rules, nil
}

/**
 * # CẤU HÌNH MẶC ĐỊNH (Default Policy)
 * Tương tác với Array Map (chỉ có 1 phần tử tại index 0).
 */
func (fw *Firewall) SetDefaultBehaviour(action uint32) error {
		fmt.Printf("[DEBUG] Đang thiết lập Default Behaviour = %d\n", action)
		var key uint32 = 0
		return fw.defaultAction.Update(&key, &action, ebpf.UpdateAny)
}

func (fw *Firewall) GetDefaultBehaviour() (uint32, error) {
		fmt.Printf("[DEBUG] Đang lấy Default Behaviour\n")
		var key uint32 = 0
		var val uint32

		if err := fw.defaultAction.Lookup(&key, &val); err != nil {
				return 0, err
		}

		return val, nil
}

/**
 * # LÀM SẠCH (Flush)
 * Xóa bỏ toàn bộ cấu hình để đưa Firewall về trạng thái trắng.
 */
func (fw *Firewall) Flush() error {
		fmt.Printf("[DEBUG] Đang xóa toàn bộ cấu hình (Flush)\n")
		// TODO: Thực hiện vòng lặp xóa tất cả các key trong ipTrie và policies.
		// Cần cẩn thận với race-condition khi đang flush mà có gói tin đi vào.
		return nil
}

// -----------------------------------------------------------
// --- Rate Limiting APIs ---
// -----------------------------------------------------------

func (fw *Firewall) ListRateLimitedIPs() ([]RateLimitEntry, error) {
	fmt.Printf("[DEBUG] Đang quét danh sách IP bị giới hạn tốc độ (ListRateLimitedIPs)\n")
	var threshold uint32
	var configKey uint32 = 0
	if err := fw.rlConfigMap.Lookup(&configKey, &threshold); err != nil || threshold == 0 {
		threshold = 1000 // Fallback giống hệt C
	}

	var entries []RateLimitEntry
	var key uint32
	// per-CPU values: Slice của cấu trúc đã ánh xạ
	var perCPUValues []RlMetrics

	iter := fw.rateLimitMap.Iterate()
	for iter.Next(&key, &perCPUValues) {
		var totalCount uint64
		var windowStart uint64

		for _, cpuVal := range perCPUValues {
			totalCount += uint64(cpuVal.Count)
			// Lấy window start mới nhất làm mốc
			if cpuVal.WindowStartNs > windowStart {
				windowStart = cpuVal.WindowStartNs
			}
		}

		if totalCount > uint64(threshold) {
			// Chuyển key uint32 -> string (Network byte order)
			ipBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(ipBytes, key)
			ip := net.IPv4(ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])

			entries = append(entries, RateLimitEntry{
				SrcIP:       ip.String(),
				TotalCount:  totalCount,
				WindowStart: time.Unix(0, int64(windowStart)),
			})
		}
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("lỗi khi duyệt rate_limit_map: %w", err)
	}

	return entries, nil
}

func (fw *Firewall) SetRateLimitThreshold(pps uint32) error {
	fmt.Printf("[DEBUG] Đang thiết lập Rate Limit Threshold = %d PPS\n", pps)
	if pps == 0 {
		return fmt.Errorf("ngưỡng PPS không được bằng 0")
	}
	var configKey uint32 = 0
	if err := fw.rlConfigMap.Update(&configKey, &pps, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("lỗi khi cập nhật rl_config_map: %w", err)
	}
	return nil
}

func (fw *Firewall) GetRateLimitThreshold() (uint32, error) {
	fmt.Printf("[DEBUG] Đang lấy Rate Limit Threshold\n")
	var configKey uint32 = 0
	var threshold uint32
	if err := fw.rlConfigMap.Lookup(&configKey, &threshold); err != nil {
		return 0, fmt.Errorf("lỗi khi đọc rl_config_map: %w", err)
	}
	if threshold == 0 {
		return 1000, nil
	}
	return threshold, nil
}

func (fw *Firewall) SetRateLimitWindow(ms uint32) error {
	fmt.Printf("[DEBUG] Đang thiết lập Rate Limit Window = %d ms\n", ms)
	if ms == 0 {
		return fmt.Errorf("thời gian window không được bằng 0")
	}
	ns := ms * 1_000_000
	var configKey uint32 = 1
	if err := fw.rlConfigMap.Update(&configKey, &ns, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("lỗi khi cập nhật rl_config_map: %w", err)
	}
	return nil
}

func (fw *Firewall) GetRateLimitWindow() (uint32, error) {
	fmt.Printf("[DEBUG] Đang lấy Rate Limit Window\n")
	var configKey uint32 = 1
	var ns uint32
	if err := fw.rlConfigMap.Lookup(&configKey, &ns); err != nil {
		return 0, fmt.Errorf("lỗi khi đọc rl_config_map: %w", err)
	}
	if ns == 0 {
		return 1000, nil
	}
	return ns / 1_000_000, nil
}