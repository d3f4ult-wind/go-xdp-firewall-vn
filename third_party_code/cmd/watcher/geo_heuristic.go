/**
 * =================================================================================
 * FILE: geo_heuristic.go
 * MÔ TẢ: Hệ thống Heuristic tự động khóa một quốc gia (Dynamic Geo-Blocking).
 * LUỒNG HOẠT ĐỘNG:
 *   1. Nhận các IP bị cảnh báo từ Iptables hoặc Suricata.
 *   2. Tra cứu cơ sở dữ liệu MaxMind (GeoLite2-Country.mmdb) để tìm mã quốc gia của IP đó.
 *   3. Sử dụng bộ đếm thời gian thực (Sliding Window) để đếm số IP xấu đến từ mỗi quốc gia.
 *   4. Nếu trong một khoảng thời gian ngắn (ví dụ 5s), có quá nhiều IP xấu (ví dụ 4 IP)
 *      từ cùng một quốc gia -> Ra quyết định khóa toàn bộ dải mạng của quốc gia đó.
 * =================================================================================
 */

package main

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

// GeoHeuristic theo dõi số lượng IP xấu đến từ các quốc gia
// và tự động kích hoạt BlockCountry nếu vượt ngưỡng.
type GeoHeuristic struct {
	dbPath     string
	geoMonitor *GeoIPMonitor
	
	// Cấu hình Threshold
	threshold int
	window    time.Duration

	// State nội bộ
	countryHits map[string]int
	mu          sync.Mutex
	db          *geoip2.Reader
}

func NewGeoHeuristic(dbPath string, geoMonitor *GeoIPMonitor) *GeoHeuristic {
	db, err := geoip2.Open(dbPath)
	if err != nil {
		log.Printf("[GeoHeuristic] LỖI: Không thể mở file mmdb: %v\n", err)
		// Không return nil để tránh crash, nhưng các hàm sau sẽ check db != nil
	}

	gh := &GeoHeuristic{
		dbPath:      dbPath,
		geoMonitor:  geoMonitor,
		// TRONG MÔI TRƯỜNG LAB (Cấu hình yếu): Đặt ngưỡng nhỏ để test.
		// Trong môi trường PRODUCT thực tế, vui lòng tăng ngưỡng này lên (vd: 50 IP / 60 giây).
		threshold:   4,
		window:      5 * time.Second,
		countryHits: make(map[string]int),
		db:          db,
	}

	// Chạy tiến trình ngầm để reset bộ đếm theo chu kỳ (Sliding Window)
	go gh.resetLoop()

	return gh
}

/**
 * # HÀM resetLoop
 * Tiến trình nền tự động làm sạch (reset) bộ đếm `countryHits` sau mỗi chu kỳ `window`.
 * Cơ chế này giúp các đợt tấn công nhỏ giọt không bị cộng dồn vĩnh viễn, tránh False Positive.
 */
// resetLoop tự động làm sạch bộ đếm sau mỗi khoảng thời gian (window)
func (gh *GeoHeuristic) resetLoop() {
	ticker := time.NewTicker(gh.window)
	for range ticker.C {
		gh.mu.Lock()
		// Khởi tạo lại map mới để xóa bộ đếm cũ
		gh.countryHits = make(map[string]int)
		gh.mu.Unlock()
	}
}

/**
 * # HÀM ReportBadIP
 * Nhận một địa chỉ IP có hành vi xấu, tra cứu quốc gia của nó, tăng bộ đếm 
 * và kiểm tra ngưỡng (Threshold).
 */
// ReportBadIP được gọi bởi SuricataTailer hoặc IptablesTailer
// mỗi khi phát hiện một IP tấn công.
func (gh *GeoHeuristic) ReportBadIP(ipStr string) {
	if gh.db == nil {
		return // Nếu không load được DB thì bỏ qua
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return
	}

	// Tra cứu Quốc gia siêu tốc (chỉ mất ~10 micro-giây)
	record, err := gh.db.Country(ip)
	if err != nil {
		return // IP không thuộc quốc gia nào (Local IP hoặc Bogon)
	}

	isoCode := record.Country.IsoCode
	if isoCode == "" {
		return
	}

	gh.mu.Lock()
	defer gh.mu.Unlock()

	gh.countryHits[isoCode]++
	count := gh.countryHits[isoCode]

	// Kiểm tra xem đã vượt ngưỡng chưa
	if count == gh.threshold {
		fmt.Printf("[GeoHeuristic] CẢNH BÁO: Phát hiện %d IP tấn công từ quốc gia %s trong %v!\n", count, isoCode, gh.window)
		fmt.Printf("[GeoHeuristic] Kích hoạt phong tỏa toàn bộ quốc gia %s...\n", isoCode)
		
		// Kích hoạt BlockCountry chạy ở luồng riêng để không chặn luồng báo cáo IP hiện tại
		go gh.geoMonitor.BlockCountry(isoCode)
	}
}

// Close giải phóng bộ nhớ của thư viện MaxMind
func (gh *GeoHeuristic) Close() {
	if gh.db != nil {
		gh.db.Close()
	}
}
