package bpf

import (
	"encoding/binary"
	"fmt"
	"net"
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
	
	// Convert ip4 (byte slice) to uint32 (Network Byte Order)
	// Because eBPF expects the uint32 to be in network byte order in memory,
	// and binary.LittleEndian.Uint32 reads it exactly as it is in memory.
	// We just read the 4 bytes into a uint32 directly without flipping.
	key.Addr = binary.LittleEndian.Uint32(ip4)

	var score uint32 = 1 // Cờ đánh dấu 1 (có priority)
	
	if err := fw.geoTrustMap.Put(&key, &score); err != nil {
		return fmt.Errorf("failed to add %s to geo_trust_map: %w", cidrStr, err)
	}
	
	return nil
}
