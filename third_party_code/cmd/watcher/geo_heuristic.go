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
