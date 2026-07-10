/**
 * =================================================================================
 * FILE: config.go
 * MÔ TẢ: Bộ nạp cấu hình (Configuration Loader).
 * LUỒNG HOẠT ĐỘNG: 
 *   1. Đọc file YAML từ đĩa cứng.
 *   2. Parse CIDR string ("10.0.0.0/8") thành các đối tượng IP và Mask hợp lệ.
 *   3. Kiểm tra tính hợp lệ của dữ liệu (chỉ hỗ trợ IPv4).
 * =================================================================================
 */

package bpf 

import (
	"fmt"
	"net"
	"os"
	"gopkg.in/yaml.v3"
)

// Config ánh xạ trực tiếp từ file init.yaml
type Config struct {
	Interface     string        `yaml:"interface"`      // Card mạng mục tiêu (vd: eth0)
	Mode          string        `yaml:"mode"`           // Chế độ nạp (native/skb)
	DefaultAction uint32        `yaml:"default_action"` // Hành động mặc định (PASS/DROP)
	Watcher       WatcherConfig `yaml:"watcher"`
	Rules         []Rule        `yaml:"rules"`
}

type WatcherConfig struct {
	KernLogPath        string `yaml:"kern_log_path"`
	SuricataLogPath    string `yaml:"suricata_log_path"`
	PollIntervalMs     int    `yaml:"poll_interval_ms"`
	SlidingWindowSize  int    `yaml:"sliding_window_size"`
	CooldownSeconds    int    `yaml:"cooldown_seconds"`
	PpsHighWatermark   uint64 `yaml:"pps_high_watermark"`
	PpsLowWatermark        uint64 `yaml:"pps_low_watermark"`
	AlertHighWatermark     int    `yaml:"alert_high_watermark"`
	AlertLowWatermark      int    `yaml:"alert_low_watermark"`
	ConntrackHighWatermark int    `yaml:"conntrack_high_watermark"`
	// LegitPromoteThreshold: số lần kết nối hợp lệ cần thiết để promote IP vào whitelist.
	// Mặc định 3 nếu không set. IP phải có legit_count >= threshold VÀ attack_count == 0.
	// Giá trị thấp → whitelist nhanh hơn nhưng có thể không chính xác.
	// Giá trị cao → an toàn hơn nhưng cần nhiều lần kết nối trước khi được whitelist.
	LegitPromoteThreshold int `yaml:"legit_promote_threshold"`
}


/**
 * # Hàm LoadConfig
 * Chuyển đổi file cấu hình tĩnh thành cấu trúc dữ liệu mà ứng dụng hiểu được.
 */
func LoadConfig(path string) (*Config, error) {
	// # BƯỚC 1: Đọc dữ liệu thô từ file
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read config file: %w", err)
	}

	// Cấu trúc tạm thời để hứng dữ liệu từ YAML (vì Rules trong YAML dùng SubnetAddr chuỗi)
	var rawCfg struct {
		Interface     string        `yaml:"interface"`
		Mode          string        `yaml:"mode"`
		DefaultAction uint32        `yaml:"default_action"`
		Watcher       WatcherConfig `yaml:"watcher"`
		Rules         []YamlRule    `yaml:"rules"`
	}

	// # BƯỚC 2: Giải mã YAML (Unmarshal)
	if err := yaml.Unmarshal(file, &rawCfg); err != nil {
		return nil, fmt.Errorf("could not parse yaml: %w", err)
	}

	cfg := &Config{
		Interface:     rawCfg.Interface,
		Mode:          rawCfg.Mode,
		DefaultAction: rawCfg.DefaultAction,
		Watcher:       rawCfg.Watcher,
		Rules:         make([]Rule, 0, len(rawCfg.Rules)),
	}

	// # BƯỚC 3: Xử lý và kiểm tra logic cho từng Rule
	for _, r := range rawCfg.Rules {
		// ParseCIDR cực kỳ quan trọng: Nó tách "192.168.1.5/24" thành IP (192.168.1.5) 
		// và IPNet (192.168.1.0/24).
		ip, ipNet, err := net.ParseCIDR(r.SubnetAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %s: %w", r.SubnetAddr, err)
		}

		// Chỉ chấp nhận IPv4 (vì chương trình XDP hiện tại chỉ parse IPv4 header)
		ip = ip.To4()
		if ip == nil {
			return nil, fmt.Errorf("only IPv4 is supported: %s", r.SubnetAddr)
		}

		// Kiểm tra Mask có đúng định dạng 32-bit không
		maskLen, bits := ipNet.Mask.Size()
		if bits != 32 {
			return nil, fmt.Errorf("invalid IPv4 mask: %s", r.SubnetAddr)
		}

		// # BƯỚC 4: Chuẩn hóa Subnet (Canonicalization)
		// TẠI SAO: Nếu user nhập 10.1.1.5/8, IPNet.Mask sẽ giúp ta đưa về đúng 10.0.0.0/8.
		// Việc này đảm bảo tính nhất quán khi nạp vào LPM Trie trong Kernel.
		network := ip.Mask(ipNet.Mask)

		cfg.Rules = append(cfg.Rules, Rule{
			Addr:    network,
			Masklen: uint32(maskLen),
			Port:    r.Port,
			Proto:   r.Proto,
			Action:  r.Action,
		})
	}

	return cfg, nil
}