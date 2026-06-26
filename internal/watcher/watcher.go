package watcher

import (
	"bufio"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"xdpfilter/internal/bpf"
)

type WatcherEngine struct {
	fw     *bpf.Firewall
	config bpf.WatcherConfig

	// Biến đếm Alert
	alertCount atomic.Uint32
}

func NewWatcherEngine(fw *bpf.Firewall, cfg bpf.WatcherConfig) *WatcherEngine {
	return &WatcherEngine{
		fw:     fw,
		config: cfg,
	}
}

func (w *WatcherEngine) Start() {
	log.Println("[Watcher] Bắt đầu khởi động Threat Engine...")

	// Khởi chạy Tailers để đếm Alert từ Suricata và Iptables
	go w.tailFile(w.config.SuricataLogPath, "alert")
	go w.tailFile(w.config.KernLogPath, "[FW-DOS]")

	// Khởi chạy vòng lặp Hysteresis
	go w.hysteresisLoop()
}

// Đọc file log (Tương tự như third_party_code tailer)
func (w *WatcherEngine) tailFile(path string, keyword string) {
	if path == "" {
		return
	}

	log.Printf("[Watcher] Đang đợi đọc file log: %s", path)
	file, err := os.Open(path)
	if err != nil {
		log.Printf("[Watcher] WARNING: Không thể mở file %s: %v", path, err)
		return
	}
	defer file.Close()

	file.Seek(0, io.SeekEnd)
	reader := bufio.NewReader(file)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			time.Sleep(1 * time.Second)
			continue
		}

		if strings.Contains(line, keyword) {
			w.alertCount.Add(1)
		}
	}
}

func (w *WatcherEngine) hysteresisLoop() {
	ticker := time.NewTicker(time.Duration(w.config.PollIntervalMs) * time.Millisecond)
	defer ticker.Stop()

	windowSize := w.config.SlidingWindowSize
	if windowSize <= 0 {
		windowSize = 5
	}

	ppsHistory := make([]uint64, windowSize)
	alertHistory := make([]uint32, windowSize)
	historyIdx := 0

	var lastTotalPackets uint64
	var lastLevelChangeTime time.Time

	// Khởi tạo lấy mẫu lần đầu
	stats, err := w.fw.ReadMitigationStats()
	if err == nil {
		lastTotalPackets = stats["total_packets"]
	}

	for range ticker.C {
		if !w.fw.AutoMode.Load() {
			// Bị ngắt bởi Admin (Manual Override), vẫn chạy lấy mẫu nhưng không ra quyết định
			stats, err := w.fw.ReadMitigationStats()
			if err == nil {
				lastTotalPackets = stats["total_packets"]
			}
			// Xóa sạch biến đếm alert trong lúc bị ngắt để tránh dồn ứ
			w.alertCount.Store(0)
			continue
		}

		// Lấy số liệu mới
		stats, err := w.fw.ReadMitigationStats()
		if err != nil {
			continue
		}
		currentTotalPackets := stats["total_packets"]
		pps := currentTotalPackets - lastTotalPackets
		if currentTotalPackets < lastTotalPackets {
			pps = 0 // Overflow protection
		}
		lastTotalPackets = currentTotalPackets

		// Lấy và reset số alert
		alerts := w.alertCount.Swap(0)

		// Cập nhật Sliding Window
		ppsHistory[historyIdx] = pps
		alertHistory[historyIdx] = alerts
		historyIdx = (historyIdx + 1) % windowSize

		// Tính trung bình / tổng
		var sumPps uint64
		var sumAlerts uint32
		for i := 0; i < windowSize; i++ {
			sumPps += ppsHistory[i]
			sumAlerts += alertHistory[i]
		}
		avgPps := sumPps / uint64(windowSize)

		w.evaluate(avgPps, sumAlerts, &lastLevelChangeTime)
	}
}

func (w *WatcherEngine) evaluate(avgPps uint64, sumAlerts uint32, lastLevelChangeTime *time.Time) {
	currentLevel := w.fw.CurrentLevel.Load()

	// 1. Kiểm tra kịch trần (Tránh evaluate không cần thiết)
	if currentLevel == 3 {
		// Chỉ xem xét hạ cấp
		if avgPps < w.config.PpsLowWatermark && sumAlerts <= uint32(w.config.AlertLowWatermark) {
			if time.Since(*lastLevelChangeTime) >= time.Duration(w.config.CooldownSeconds)*time.Second {
				log.Printf("[Watcher] Hạ cấp độ: Level %d -> %d (PPS: %d, Alerts: %d)", currentLevel, currentLevel-1, avgPps, sumAlerts)
				w.applyWREDConfig(currentLevel - 1)
				w.fw.CurrentLevel.Store(currentLevel - 1)
				*lastLevelChangeTime = time.Now()
			}
		}
		return
	}

	// 2. Logic Tăng Cấp (Escalate)
	// Để tránh False Positive (VD: Flash Sale làm PPS cao nhưng Server vẫn xử lý tốt),
	// chúng ta kiểm tra thêm chỉ số quá tải tại tường lửa (Conntrack Table):
	conntrackCount := getConntrackCount()
	
	// Lấy ngưỡng từ cấu hình, default là 10000 nếu chưa set
	ctWatermark := w.config.ConntrackHighWatermark
	if ctWatermark <= 0 {
		ctWatermark = 10000
	}
	firewallCongested := conntrackCount > ctWatermark // Tường lửa đang theo dõi quá nhiều kết nối

	catalystThreshold := uint64(float64(w.config.PpsHighWatermark) * 0.7)
	
	shouldEscalate := false
	if avgPps >= w.config.PpsHighWatermark && firewallCongested {
		// BẮT BUỘC: PPS vượt đỉnh VÀ Tường lửa đang bị tràn bảng trạng thái
		shouldEscalate = true
	} else if avgPps >= catalystThreshold && sumAlerts >= uint32(w.config.AlertHighWatermark) {
		// XÚC TÁC: PPS mấp mé đỉnh VÀ hệ thống Suricata/Iptables báo động liên tục
		shouldEscalate = true
	}

	if shouldEscalate {
		newLevel := currentLevel + 1
		log.Printf("[Watcher] PHÁT HIỆN TẤN CÔNG! Nâng cấp độ: Level %d -> %d (PPS: %d, Alerts: %d, CT: %d)", currentLevel, newLevel, avgPps, sumAlerts, conntrackCount)
		w.applyWREDConfig(newLevel)
		w.fw.CurrentLevel.Store(newLevel)
		*lastLevelChangeTime = time.Now()
		return
	}

	// 3. Logic Hạ Cấp (De-escalate)
	if currentLevel > 0 {
		if avgPps < w.config.PpsLowWatermark && sumAlerts <= uint32(w.config.AlertLowWatermark) {
			if time.Since(*lastLevelChangeTime) >= time.Duration(w.config.CooldownSeconds)*time.Second {
				newLevel := currentLevel - 1
				log.Printf("[Watcher] An toàn. Hạ cấp độ: Level %d -> %d (PPS: %d, Alerts: %d)", currentLevel, newLevel, avgPps, sumAlerts)
				w.applyWREDConfig(newLevel)
				w.fw.CurrentLevel.Store(newLevel)
				*lastLevelChangeTime = time.Now()
			}
		}
	}
}

func (w *WatcherEngine) applyWREDConfig(level uint32) {
	// Dựa trên bảng WRED tĩnh đã thỏa thuận ở Phase E
	var synDrop, udpDrop, icmpDrop, geoSynDrop, geoUdpDrop, geoIcmpDrop uint32

	switch level {
	case 1:
		synDrop, udpDrop, icmpDrop = 25, 25, 25
		geoSynDrop, geoUdpDrop, geoIcmpDrop = 5, 5, 5
	case 2:
		synDrop, udpDrop, icmpDrop = 50, 50, 50
		geoSynDrop, geoUdpDrop, geoIcmpDrop = 15, 15, 15
	case 3:
		synDrop, udpDrop, icmpDrop = 100, 100, 100
		geoSynDrop, geoUdpDrop, geoIcmpDrop = 50, 50, 50
	default:
		synDrop, udpDrop, icmpDrop = 0, 0, 0
		geoSynDrop, geoUdpDrop, geoIcmpDrop = 0, 0, 0
	}

	// Update Mitigation Map (BPF)
	err := w.fw.UpdateMitigationMap(level, synDrop, udpDrop, icmpDrop, geoSynDrop, geoUdpDrop, geoIcmpDrop)
	if err != nil {
		log.Printf("[Watcher] Lỗi khi cập nhật BPF Map: %v", err)
	}
}

// Đọc số lượng kết nối đang được theo dõi (Conntrack table)
func getConntrackCount() int {
	data, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_count")
	if err != nil {
		return 0
	}
	count, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	return count
}

