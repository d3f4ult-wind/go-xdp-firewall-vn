package watcher

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"xdpfilter/internal/bpf"
)

/**
 * =================================================================================
 * FILE: watcher.go
 * MÔ TẢ: Động cơ giám sát hệ thống (Threat Engine / Watcher).
 *
 * CÓ 2 VÒNG LẶP CHÍNH:
 *   A. hysteresisLoop  — giám sát PPS + alert để Escalate/De-escalate Level Tier 1.
 *   B. legitDetectLoop — học whitelist tự động từ traffic quan sát được.
 *
 * =================================================================================
 * CƠ CHẾ WHITELIST AUTO-LEARNING (LegitDetector)
 * Trả lời câu hỏi thầy: "Firewall trống → nhận diện whitelist thế nào?"
 *
 * Flow đúng (không phải check whitelist trước khi block, mà là TỰ HỌC whitelist):
 *
 *   Bước 1: Client kết nối (ví dụ: curl http://10.10.2.2)
 *           ↓
 *   Bước 2: Iptables ACCEPT + LOG "[FW-DOS] LEGIT-CANDIDATE"
 *           (IP này đã qua bogon_filter, blacklist_check, rate-limit — kết nối hợp lệ)
 *           ↓
 *   Bước 3: Suricata quan sát HTTP flow:
 *           - Nếu có User-Agent + Host header hợp lệ → alert "LEGIT-CLIENT-CANDIDATE" (sid:9900001)
 *           - Nếu có attack pattern → alert các sid attack (9000001–9005003)
 *           ↓
 *   Bước 4: LegitDetector (goroutine trong watcher.go) đọc SONG SONG 2 nguồn:
 *           - Iptables kern.log: đếm số lần IP xuất hiện trong "[FW-DOS] LEGIT-CANDIDATE"
 *           - Suricata eve.json: đếm alert ATTACK vs alert LEGIT-CLIENT-CANDIDATE per IP
 *           ↓
 *   Bước 5: Mỗi 10 giây, LegitDetector đánh giá từng IP trong candidate list:
 *           Điều kiện promote:
 *             legit_count >= LegitPromoteThreshold (mặc định: 3 lần kết nối hợp lệ)
 *             attack_count == 0 (chưa từng trigger attack rule)
 *           ↓
 *   Bước 6: Promote IP vào whitelist:
 *           → fw.AddTrustedIP(ip)             [XDP eBPF trusted_map — Tier 1]
 *           → exec "ipset add ddos_whitelist"  [Iptables ipset — Tier 2]
 *           → log "[Watcher] PROMOTED TO WHITELIST: x.x.x.x"
 *
 * Kết quả: Sau khi `curl http://10.10.2.2` vài lần → IP tự động được thêm
 *          vào trusted_map và ipset mà không cần admin can thiệp thủ công.
 * =================================================================================
 */

// Regex trích xuất IP nguồn từ Iptables kern.log: "SRC=x.x.x.x"
var reIptablesSrc = regexp.MustCompile(`SRC=(\d+\.\d+\.\d+\.\d+)`)

// SID của Suricata rule đánh dấu client hợp lệ (suricata.rules sid:9900001)
const legitClientSID = 9900001

// LegitEntry lưu thông tin reputation của một IP đang được quan sát
type LegitEntry struct {
	LegitCount  int       // Số lần kết nối hợp lệ (từ Iptables LEGIT-CANDIDATE log)
	AttackCount int       // Số lần trigger attack alert (từ Suricata)
	SuricataOK  int       // Số lần Suricata confirm hợp lệ (sid:9900001)
	FirstSeen   time.Time // Lần đầu quan sát
	LastSeen    time.Time // Lần cuối quan sát
	Promoted    bool      // Đã được thêm vào whitelist chưa
}

// LegitDetector theo dõi reputation của IP và tự động promote vào whitelist
type LegitDetector struct {
	fw     *bpf.Firewall
	config bpf.WatcherConfig

	mu          sync.Mutex
	candidates  map[string]*LegitEntry // IP → reputation entry

	// Ngưỡng cấu hình (có thể đọc từ WatcherConfig nếu muốn)
	promoteThreshold int // Số lần legit cần để promote
	evalInterval     time.Duration
}

func newLegitDetector(fw *bpf.Firewall, cfg bpf.WatcherConfig) *LegitDetector {
	threshold := 3 // mặc định: 3 lần kết nối hợp lệ không có attack
	if cfg.LegitPromoteThreshold > 0 {
		threshold = cfg.LegitPromoteThreshold
	}
	return &LegitDetector{
		fw:               fw,
		config:           cfg,
		candidates:       make(map[string]*LegitEntry),
		promoteThreshold: threshold,
		evalInterval:     10 * time.Second,
	}
}

// recordLegit tăng legit_count cho IP (được gọi khi Iptables log "LEGIT-CANDIDATE")
func (ld *LegitDetector) recordLegit(ip string) {
	ld.mu.Lock()
	defer ld.mu.Unlock()

	e, ok := ld.candidates[ip]
	if !ok {
		e = &LegitEntry{FirstSeen: time.Now()}
		ld.candidates[ip] = e
	}
	e.LegitCount++
	e.LastSeen = time.Now()
}

// recordAttack tăng attack_count cho IP (được gọi khi Suricata báo attack alert)
func (ld *LegitDetector) recordAttack(ip string) {
	ld.mu.Lock()
	defer ld.mu.Unlock()

	e, ok := ld.candidates[ip]
	if !ok {
		e = &LegitEntry{FirstSeen: time.Now()}
		ld.candidates[ip] = e
	}
	e.AttackCount++
	e.LastSeen = time.Now()
}

// recordSuricataLegit tăng suricata_ok cho IP (Suricata confirm qua sid:9900001)
func (ld *LegitDetector) recordSuricataLegit(ip string) {
	ld.mu.Lock()
	defer ld.mu.Unlock()

	e, ok := ld.candidates[ip]
	if !ok {
		e = &LegitEntry{FirstSeen: time.Now()}
		ld.candidates[ip] = e
	}
	e.SuricataOK++
	e.LastSeen = time.Now()
}

// promoteLoop chạy định kỳ, đánh giá các candidate và promote nếu đủ điều kiện
func (ld *LegitDetector) promoteLoop() {
	ticker := time.NewTicker(ld.evalInterval)
	defer ticker.Stop()

	for range ticker.C {
		ld.mu.Lock()
		for ip, e := range ld.candidates {
			// Bỏ qua IP đã được promote rồi
			if e.Promoted {
				continue
			}

			// Điều kiện promote whitelist:
			//   1. legit_count >= threshold (đã kết nối hợp lệ đủ lần)
			//   2. attack_count == 0 (chưa từng trigger attack rule)
			//   3. Hoặc: Suricata đã xác nhận (sid:9900001) VÀ attack_count == 0
			shouldPromote := false
			reason := ""

			if e.LegitCount >= ld.promoteThreshold && e.AttackCount == 0 {
				shouldPromote = true
				reason = "iptables legit-candidate"
			} else if e.SuricataOK >= 1 && e.AttackCount == 0 {
				shouldPromote = true
				reason = "suricata confirmed legit"
			}

			if shouldPromote {
				log.Printf("[LegitDetector] PROMOTE WHITELIST: %s (legit=%d, attack=%d, suricata_ok=%d, reason=%s)",
					ip, e.LegitCount, e.AttackCount, e.SuricataOK, reason)

				// --- Tier 1: XDP trusted_map ---
				if err := ld.fw.AddTrustedIP(ip); err != nil {
					log.Printf("[LegitDetector] Lỗi thêm %s vào XDP trusted_map: %v", ip, err)
				} else {
					log.Printf("[LegitDetector] ✓ Tier 1: %s → XDP trusted_map", ip)
				}

				// --- Tier 2: Iptables ipset ddos_whitelist ---
				cmd := exec.Command("ipset", "add", "ddos_whitelist", ip)
				if out, err := cmd.CombinedOutput(); err != nil {
					// "already added" không phải lỗi
					if !strings.Contains(string(out), "already added") {
						log.Printf("[LegitDetector] Lỗi thêm %s vào ipset ddos_whitelist: %v (%s)", ip, err, string(out))
					} else {
						log.Printf("[LegitDetector] ✓ Tier 2: %s đã có trong ipset rồi.", ip)
					}
				} else {
					log.Printf("[LegitDetector] ✓ Tier 2: %s → ipset ddos_whitelist", ip)
				}

				e.Promoted = true
			}
		}
		ld.mu.Unlock()
	}
}

// tailIptablesForLegit đọc kern.log tìm "[FW-DOS] LEGIT-CANDIDATE"
// → gọi recordLegit(ip) cho IP tương ứng
func (ld *LegitDetector) tailIptablesForLegit(kernLogPath string) {
	if kernLogPath == "" {
		return
	}

	log.Printf("[LegitDetector] Bắt đầu đọc Iptables log: %s", kernLogPath)
	file, err := os.Open(kernLogPath)
	if err != nil {
		log.Printf("[LegitDetector] WARNING: Không thể mở %s: %v", kernLogPath, err)
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

		// Chỉ quan tâm đến dòng LEGIT-CANDIDATE (do iptables.rules LOG)
		if strings.Contains(line, "LEGIT-CANDIDATE") {
			if m := reIptablesSrc.FindStringSubmatch(line); len(m) > 1 {
				ip := m[1]
				ld.recordLegit(ip)
				log.Printf("[LegitDetector] Iptables legit hit: %s", ip)
			}
		}
	}
}

// tailSuricataForLegit đọc eve.json, phân loại alert:
//   - sid 9900001 → client hợp lệ, gọi recordSuricataLegit
//   - các sid khác (attack) → gọi recordAttack
func (ld *LegitDetector) tailSuricataForLegit(evePath string) {
	if evePath == "" {
		return
	}

	log.Printf("[LegitDetector] Bắt đầu đọc Suricata eve.json: %s", evePath)
	file, err := os.Open(evePath)
	if err != nil {
		log.Printf("[LegitDetector] WARNING: Không thể mở %s: %v", evePath, err)
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

		if !strings.Contains(line, "\"event_type\":\"alert\"") {
			continue
		}

		// Parse JSON để lấy src_ip và sid
		var ev struct {
			SrcIP string `json:"src_ip"`
			Alert struct {
				SignatureID int `json:"signature_id"`
			} `json:"alert"`
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &ev); err != nil {
			continue
		}

		if ev.SrcIP == "" {
			continue
		}

		if ev.Alert.SignatureID == legitClientSID {
			// Suricata xác nhận: GET + User-Agent + Host hợp lệ → client thực sự
			ld.recordSuricataLegit(ev.SrcIP)
			log.Printf("[LegitDetector] Suricata xác nhận legit: %s (sid:%d)", ev.SrcIP, ev.Alert.SignatureID)
		} else {
			// Attack SID → đây là IP đang tấn công, không nên whitelist
			ld.recordAttack(ev.SrcIP)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// WatcherEngine — Threat Detection + Level Management (Tier 1 Hysteresis)
// ─────────────────────────────────────────────────────────────────────────────

type WatcherEngine struct {
	fw     *bpf.Firewall
	config bpf.WatcherConfig

	// alertCount: đếm attack alerts từ Suricata/Iptables (dùng cho hysteresis)
	alertCount atomic.Uint32
}

func NewWatcherEngine(fw *bpf.Firewall, cfg bpf.WatcherConfig) *WatcherEngine {
	return &WatcherEngine{
		fw:     fw,
		config: cfg,
	}
}

/**
 * # HÀM Start
 * Khởi chạy tất cả các goroutine giám sát song song.
 * Có 2 nhóm:
 *   A. Threat Detection (hysteresis): đọc alert → nâng/hạ Level Tier 1
 *   B. LegitDetector: đọc legit signal → tự động promote whitelist
 */
func (w *WatcherEngine) Start() {
	log.Println("[Watcher] Bắt đầu khởi động Threat Engine...")

	// A. Threat Detection goroutines
	go w.tailAttackLog(w.config.SuricataLogPath)
	go w.tailAttackLog(w.config.KernLogPath)
	go w.hysteresisLoop()

	// B. LegitDetector goroutines (Whitelist Auto-Learning)
	ld := newLegitDetector(w.fw, w.config)
	go ld.tailIptablesForLegit(w.config.KernLogPath)
	go ld.tailSuricataForLegit(w.config.SuricataLogPath)
	go ld.promoteLoop()

	log.Println("[Watcher] LegitDetector khởi động — tự động học whitelist từ traffic.")
}

/**
 * # HÀM tailAttackLog
 * Đọc log từ Suricata hoặc Iptables, đếm attack events vào alertCount.
 * alertCount được dùng bởi hysteresisLoop để quyết định Escalate Level.
 * (Khác với LegitDetector: đây chỉ đếm attack, không phân loại legit/attack)
 */
func (w *WatcherEngine) tailAttackLog(path string) {
	if path == "" {
		return
	}

	log.Printf("[Watcher] Theo dõi log tấn công: %s", path)
	file, err := os.Open(path)
	if err != nil {
		log.Printf("[Watcher] WARNING: Không thể mở %s: %v", path, err)
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

		// ── Phân loại dòng log ──────────────────────────────────────────────────
		//
		// CẠNH TRANH PREFIX (CẦN CHÚ Ý):
		//   Iptables LOG dùng prefix biến LOG_PREFIX="[FW-DOS] ".
		//   Rule LEGIT-CANDIDATE cũng dùng cùng prefix đó (vì cùng biến):
		//     "[FW-DOS] LEGIT-CANDIDATE SRC=10.10.1.3 ..."
		//
		//   → strings.Contains(line, "[FW-DOS]") sẽ match CẢ HAI loại:
		//       [FW-DOS] SYN-FLOOD ...        ← attack thật
		//       [FW-DOS] LEGIT-CANDIDATE ...  ← client hợp lệ
		//
		//   Phải kiểm tra LOẠI TRỪ "LEGIT-CANDIDATE" trước khi đánh là attack.
		// ───────────────────────────────────────────────────────────────────────
		isAttack := false
		if strings.Contains(line, "[FW-DOS]") {
			// Loại trừ dòng LEGIT-CANDIDATE — đây là kết nối hợp lệ, không phải attack
			if !strings.Contains(line, "LEGIT-CANDIDATE") {
				isAttack = true
			}
		} else if strings.Contains(line, "\"event_type\":\"alert\"") {
			// Suricata alert: loại trừ sid:9900001 (LEGIT-CLIENT-CANDIDATE)
			if !strings.Contains(line, "\"signature_id\":9900001") {
				isAttack = true
			}
		}

		if isAttack {
			w.alertCount.Add(1)
		}
	}
}

/**
 * # HÀM hysteresisLoop (Vòng lặp trễ - Cửa sổ trượt)
 * Đo PPS từ XDP + alertCount → quyết định Escalate/De-escalate Tier 1 Level.
 */
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

	stats, err := w.fw.ReadMitigationStats()
	if err == nil {
		lastTotalPackets = stats["total_packets"]
	}

	for range ticker.C {
		if !w.fw.AutoMode.Load() {
			stats, err := w.fw.ReadMitigationStats()
			if err == nil {
				lastTotalPackets = stats["total_packets"]
			}
			w.alertCount.Store(0)
			continue
		}

		stats, err := w.fw.ReadMitigationStats()
		if err != nil {
			continue
		}
		currentTotalPackets := stats["total_packets"]
		pps := currentTotalPackets - lastTotalPackets
		if currentTotalPackets < lastTotalPackets {
			pps = 0
		}
		lastTotalPackets = currentTotalPackets

		alerts := w.alertCount.Swap(0)

		ppsHistory[historyIdx] = pps
		alertHistory[historyIdx] = alerts
		historyIdx = (historyIdx + 1) % windowSize

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

/**
 * # HÀM evaluate
 * Bộ não đánh giá nguy cơ dựa trên avgPPS + sumAlerts + conntrack count.
 */
func (w *WatcherEngine) evaluate(avgPps uint64, sumAlerts uint32, lastLevelChangeTime *time.Time) {
	currentLevel := w.fw.CurrentLevel.Load()

	if currentLevel == 3 {
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

	conntrackCount := getConntrackCount()
	ctWatermark := w.config.ConntrackHighWatermark
	if ctWatermark <= 0 {
		ctWatermark = 10000
	}
	firewallCongested := conntrackCount > ctWatermark
	catalystThreshold := uint64(float64(w.config.PpsHighWatermark) * 0.7)

	shouldEscalate := false
	if avgPps >= w.config.PpsHighWatermark && firewallCongested {
		shouldEscalate = true
	} else if avgPps >= catalystThreshold && sumAlerts >= uint32(w.config.AlertHighWatermark) {
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

/**
 * # HÀM applyWREDConfig
 * Áp dụng WRED profile vào eBPF Map theo Level (0-3).
 */
func (w *WatcherEngine) applyWREDConfig(level uint32) {
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

	err := w.fw.UpdateMitigationMap(level, synDrop, udpDrop, icmpDrop, geoSynDrop, geoUdpDrop, geoIcmpDrop)
	if err != nil {
		log.Printf("[Watcher] Lỗi khi cập nhật BPF Map: %v", err)
	}
}

/**
 * # HÀM getConntrackCount
 * Đọc số kết nối đang theo dõi trong bảng Conntrack của kernel.
 */
func getConntrackCount() int {
	data, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_count")
	if err != nil {
		return 0
	}
	count, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	return count
}
