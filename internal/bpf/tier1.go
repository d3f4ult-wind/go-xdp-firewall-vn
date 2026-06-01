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

// ReadMitigationStats đọc telemetry counter từ xdp-filter.c
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

// AddTrustedIP thêm một IP đơn lẻ vào Dynamic Whitelist.
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

// AddGeoPrefix thêm một dải mạng (CIDR) vào Geo Trust Map (LPM Trie)
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

// AddGeoCountry tự động nạp toàn bộ CIDR của một quốc gia từ file MaxMind CSV.
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

// ListTrustedIPs liệt kê toàn bộ IP có trong trusted_map
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

// ListGeoPrefixes liệt kê toàn bộ CIDR có trong geo_trust_map
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

// RemoveTrustedIP xóa một IP khỏi trusted_map
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

// RemoveGeoPrefix xóa một CIDR khỏi geo_trust_map
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

// ClearGeoPrefixes xóa toàn bộ các CIDR có trong geo_trust_map
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
