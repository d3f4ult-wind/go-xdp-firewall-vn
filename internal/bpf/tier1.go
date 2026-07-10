package bpf

import (
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

/**
 * =================================================================================
 * FILE: tier1.go
 * MÔ TẢ: Quản lý logic điều khiển Tier 1 (Mitigation & Whitelisting).
 * LUỒNG HOẠT ĐỘNG:
 *   1. Giao tiếp với các eBPF Map chuyên trách của Tier 1 (mitigation_map, trusted_map, geo_trust_map).
 *   2. Cung cấp API để cập nhật mức độ phòng thủ (Level 0-3), tỷ lệ Drop, và đọc thống kê (Telemetry).
 *   3. Cho phép thêm các IP cụ thể vào Whitelist động hoặc dải CIDR vào Geo Trust Map.
 * =================================================================================
 */

// UpdateMitigationMap cập nhật trạng thái Mitigation Tier 1.
func (fw *Firewall) UpdateMitigationMap(level, synDrop, udpDrop, icmpDrop, geoSynDrop, geoUdpDrop, geoIcmpDrop uint32) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	params := []struct {
		idx uint32
		val uint32
	}{
		{0, level},
		{1, synDrop},
		{2, udpDrop},
		{3, icmpDrop},
		{4, geoSynDrop},
		{5, geoUdpDrop},
		{6, geoIcmpDrop},
	}

	for _, p := range params {
		if err := fw.mitigationMap.Put(p.idx, p.val); err != nil {
			return fmt.Errorf("failed to update mitigation_map index %d: %w", p.idx, err)
		}
	}
	return nil
}

/**
 * # HÀM ReadMitigationStats
 * Đọc số liệu thống kê (Telemetry counter) từ xdp-filter.c
 * TẠI SAO PHẢI CỘNG DỒN: Do mitigationStats là PERCPU_ARRAY Map, mỗi nhân CPU sẽ lưu một biến đếm riêng
 * để tránh lock nghẽn cổ chai. Ở User-space, ta phải duyệt qua slice perCPUValues và cộng tổng lại.
 */
func (fw *Firewall) ReadMitigationStats() (map[string]uint64, error) {
	fw.mu.RLock()
	defer fw.mu.RUnlock()

	keys := []string{
		"total_packets",
		"trusted_hits",
		"geo_hits",
		"syn_dropped",
		"udp_dropped",
		"icmp_dropped",
		"tier2_passed",
	}

	result := make(map[string]uint64)
	
	for i, keyName := range keys {
		var perCPUValues []uint64
		idx := uint32(i)
		
		if err := fw.mitigationStats.Lookup(idx, &perCPUValues); err != nil {
			return nil, fmt.Errorf("failed to lookup mitigation_stats index %d: %w", i, err)
		}

		var total uint64 = 0
		for _, val := range perCPUValues {
			total += val
		}
		result[keyName] = total
	}

	return result, nil
}

/**
 * # HÀM AddTrustedIP
 * Thêm một IP đơn lẻ vào Dynamic Whitelist (trusted_map).
 * Các IP trong map này sẽ bỏ qua toàn bộ việc kiểm tra ngẫu nhiên (Probabilistic Drop) của Tier 1.
 */
func (fw *Firewall) AddTrustedIP(ipStr string) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", ipStr)
	}
	
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 is supported for trusted_map")
	}

	// Đổi IP sang network byte order (đảo ngược lại vì eBPF Little Endian lưu kiểu kia)
	// Hoặc dùng trực tiếp uint32
	ipUint32 := binary.LittleEndian.Uint32(ip4)
	
	now := uint64(time.Now().UnixNano())
	
	if err := fw.trustedMap.Put(ipUint32, now); err != nil {
		return fmt.Errorf("failed to put %s into trusted_map: %w", ipStr, err)
	}

	return nil
}

/**
 * # HÀM LookupTrustedIP
 * Kiểm tra một IP (dạng uint32 Little Endian) có trong trusted_map không.
 * Trả về nil nếu tìm thấy (IP đang trong whitelist), error nếu không tìm thấy.
 * Dùng RLock (read-only) để không chặn các thao tác đọc đồng thời từ Watcher.
 * TẠI SAO CẦN: Watcher gọi hàm này mỗi khi nhận alert từ log, để phân biệt:
 *   - IP trong trusted_map → user hợp lệ đã được admin tin cậy → không autoblock.
 *   - IP không trong trusted_map → nguồn lạ đang tấn công → đếm alert, có thể autoblock.
 * ĐÂY LÀ CÂU TRẢ LỜI CHO CÂU HỎI THẦY: "Firewall trống thì nhận diện whitelist thế nào?"
 * → Admin/MCP thêm IP hợp lệ vào trusted_map trước (qua POST /tier1/trusted hoặc MCP tool).
 * → Sau đó Watcher tự động đối chiếu mỗi alert với danh sách này.
 */
func (fw *Firewall) LookupTrustedIP(ipUint32 uint32, ts *uint64) error {
	fw.mu.RLock()
	defer fw.mu.RUnlock()
	return fw.trustedMap.Lookup(ipUint32, ts)
}



/**
 * # HÀM AddGeoPrefix
 * Thêm một dải mạng (CIDR) vào Geo Trust Map (LPM Trie).
 * Gói tin thuộc các dải mạng này sẽ được áp dụng tỷ lệ drop thấp hơn so với mức mặc định của Level hiện hành.
 */
func (fw *Firewall) AddGeoPrefix(cidrStr string) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return fmt.Errorf("invalid CIDR %s: %w", cidrStr, err)
	}
	
	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 is supported for geo_trust_map")
	}

	maskSize, _ := ipNet.Mask.Size()

	var key xdp_packet_filterIpv4LpmKey
	key.Prefixlen = uint32(maskSize)
	copy(key.Addr[:], ip4)

	var score uint32 = 1 // Cờ đánh dấu 1 (có priority)
	
	if err := fw.geoTrustMap.Put(&key, &score); err != nil {
		return fmt.Errorf("failed to add %s to geo_trust_map: %w", cidrStr, err)
	}
	
	return nil
}

/**
 * # HÀM AddGeoCountry
 * Tiện ích hỗ trợ tự động nạp toàn bộ CIDR của một quốc gia (ví dụ: "VN") từ CSDL MaxMind CSV.
 * LƯU Ý: Phụ thuộc vào 2 file CSV trong thư mục internal/geolite/.
 */
func (fw *Firewall) AddGeoCountry(countryIso string) (int, error) {
	countryIso = strings.ToUpper(countryIso)

	locPath := "internal/geolite/GeoLite2-Country-Locations-en.csv"
	blocksPath := "internal/geolite/GeoLite2-Country-Blocks-IPv4.csv"

	// 1. Tìm geoname_id từ Locations CSV
	locFile, err := os.Open(locPath)
	if err != nil {
		return 0, fmt.Errorf("không thể mở %s: %w", locPath, err)
	}
	defer locFile.Close()

	locReader := csv.NewReader(locFile)
	locRecords, err := locReader.ReadAll()
	if err != nil {
		return 0, fmt.Errorf("lỗi đọc %s: %w", locPath, err)
	}

	var targetGeoID string
	// Header: geoname_id, locale_code, continent_code, continent_name, country_iso_code, country_name, is_in_european_union
	for i, row := range locRecords {
		if i == 0 {
			continue // skip header
		}
		if len(row) > 4 && row[4] == countryIso {
			targetGeoID = row[0]
			break
		}
	}

	if targetGeoID == "" {
		return 0, fmt.Errorf("không tìm thấy quốc gia %s trong CSDL", countryIso)
	}

	// 2. Lấy toàn bộ mạng tương ứng từ Blocks CSV
	blkFile, err := os.Open(blocksPath)
	if err != nil {
		return 0, fmt.Errorf("không thể mở %s: %w", blocksPath, err)
	}
	defer blkFile.Close()

	blkReader := csv.NewReader(blkFile)
	blkRecords, err := blkReader.ReadAll()
	if err != nil {
		return 0, fmt.Errorf("lỗi đọc %s: %w", blocksPath, err)
	}

	count := 0
	// Header: network, geoname_id, registered_country_geoname_id, represented_country_geoname_id, is_anonymous_proxy, is_satellite_provider, is_anycast
	for i, row := range blkRecords {
		if i == 0 {
			continue // skip header
		}
		if len(row) > 2 {
			// Kiểm tra cột geoname_id (cột 1) hoặc registered_country_geoname_id (cột 2)
			if row[1] == targetGeoID || row[2] == targetGeoID {
				network := row[0]
				// Gọi thẳng hàm thêm tiền tố mà không đếm lỗi vụn vặt (ví dụ sai định dạng 1 dòng)
				if err := fw.AddGeoPrefix(network); err == nil {
					count++
				}
			}
		}
	}

	return count, nil
}

/**
 * # HÀM ListTrustedIPs
 * Trả về danh sách tất cả các IP đang nằm trong Whitelist (kèm theo timestamp lúc được thêm vào).
 */
func (fw *Firewall) ListTrustedIPs() ([]map[string]interface{}, error) {
	fw.mu.RLock()
	defer fw.mu.RUnlock()
	
	var result []map[string]interface{}
	iter := fw.trustedMap.Iterate()
	var key uint32
	var ts uint64

	for iter.Next(&key, &ts) {
		ipBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(ipBytes, key)
		ip := net.IP(ipBytes)

		result = append(result, map[string]interface{}{
			"ip":        ip.String(),
			"last_seen": ts,
		})
	}

	if err := iter.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

/**
 * # HÀM ListGeoPrefixes
 * Liệt kê toàn bộ CIDR ưu tiên có trong geo_trust_map.
 */
func (fw *Firewall) ListGeoPrefixes() ([]map[string]interface{}, error) {
	fw.mu.RLock()
	defer fw.mu.RUnlock()
	
	var result []map[string]interface{}
	iter := fw.geoTrustMap.Iterate()
	var key xdp_packet_filterIpv4LpmKey
	var score uint32

	for iter.Next(&key, &score) {
		ip := net.IP(key.Addr[:])
		cidr := fmt.Sprintf("%s/%d", ip.String(), key.Prefixlen)

		result = append(result, map[string]interface{}{
			"cidr":  cidr,
			"score": score,
		})
	}

	if err := iter.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

/**
 * # HÀM RemoveTrustedIP
 * Xóa một IP khỏi danh sách Whitelist.
 */
func (fw *Firewall) RemoveTrustedIP(ipStr string) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return fmt.Errorf("invalid IP address")
	}

	key := binary.LittleEndian.Uint32(ip)
	if err := fw.trustedMap.Delete(&key); err != nil {
		return fmt.Errorf("failed to remove trusted IP: %w", err)
	}
	return nil
}

/**
 * # HÀM RemoveGeoPrefix
 * Xóa một CIDR cụ thể khỏi Geo Trust Map.
 */
func (fw *Firewall) RemoveGeoPrefix(cidrStr string) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %w", err)
	}

	ip4 := ipNet.IP.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 is supported")
	}

	maskSize, _ := ipNet.Mask.Size()
	var key xdp_packet_filterIpv4LpmKey
	key.Prefixlen = uint32(maskSize)
	copy(key.Addr[:], ip4)

	if err := fw.geoTrustMap.Delete(&key); err != nil {
		return fmt.Errorf("failed to remove geo CIDR: %w", err)
	}
	return nil
}

/**
 * # HÀM ClearGeoPrefixes
 * Xóa bỏ toàn bộ các dải IP đã thêm vào Geo Trust Map.
 * Hữu ích khi cần reset lại danh sách ưu tiên.
 */
func (fw *Firewall) ClearGeoPrefixes() error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	var keys []xdp_packet_filterIpv4LpmKey
	iter := fw.geoTrustMap.Iterate()
	var key xdp_packet_filterIpv4LpmKey
	var score uint32

	for iter.Next(&key, &score) {
		keys = append(keys, key)
	}

	if err := iter.Err(); err != nil {
		return fmt.Errorf("failed to iterate geo map: %w", err)
	}

	for _, k := range keys {
		_ = fw.geoTrustMap.Delete(&k)
	}

	return nil
}
