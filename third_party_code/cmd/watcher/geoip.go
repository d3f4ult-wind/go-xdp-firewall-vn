package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// GeoIPMonitor cung cấp tính năng chặn toàn bộ một quốc gia.
// Thay vì nạp file 22MB vào RAM, nó sẽ quét file "on-demand" (khi được yêu cầu)
// và gọi HTTP API của Main Firewall để thêm trực tiếp Subnet vào LPM Trie.
type GeoIPMonitor struct {
	bpfManager *BPFManager
	blocksFile string
	locsFile   string
	
	// Cache nhỏ gọn trong RAM (chỉ tốn vài KB)
	countryToGeoID map[string]string // "CN" -> "1814991"
}

func NewGeoIPMonitor(bpfManager *BPFManager, blocksFile, locsFile string) *GeoIPMonitor {
	g := &GeoIPMonitor{
		bpfManager:     bpfManager,
		blocksFile:     blocksFile,
		locsFile:       locsFile,
		countryToGeoID: make(map[string]string),
	}
	g.loadLocations()
	return g
}

// loadLocations đọc file locsFile (rất nhỏ) vào RAM một lần khi khởi động.
func (g *GeoIPMonitor) loadLocations() {
	locFile, err := os.Open(g.locsFile)
	if err != nil {
		fmt.Printf("[GeoIP] WARNING: Khong the mo file locations: %v\n", err)
		return
	}
	defer locFile.Close()

	reader := csv.NewReader(locFile)
	reader.Read() // Bo qua header
	
	count := 0
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		// Column 0: geoname_id, Column 4: country_iso_code
		if len(record) > 4 && record[4] != "" {
			g.countryToGeoID[record[4]] = record[0]
			count++
		}
	}
	fmt.Printf("[GeoIP] Da load %d ma quoc gia vao cache.\n", count)
}

func (g *GeoIPMonitor) Start() {
	fmt.Println("[GeoIP] San sang Block Country (On-demand mode).")
	
	// Ví dụ: Gọi hàm này để chặn TQ. Bạn có thể mở comment để test!
	// go g.BlockCountry("CN") 
}

// BlockCountry quét file 22MB (rất nhanh, chỉ tốn 1-2s) để tìm tất cả Subnet của quốc gia
// và đẩy xuống Go Firewall API (vào LPM Trie).
func (g *GeoIPMonitor) BlockCountry(isoCode string) {
	isoCode = strings.ToUpper(isoCode)
	geoID, exists := g.countryToGeoID[isoCode]
	if !exists {
		fmt.Printf("[GeoIP] Khong tim thay quoc gia %s\n", isoCode)
		return
	}

	fmt.Printf("[GeoIP] Dang quet Subnet cua %s (GeoID: %s)...\n", isoCode, geoID)

	blockFile, err := os.Open(g.blocksFile)
	if err != nil {
		fmt.Printf("[GeoIP] Khong the mo file blocks: %v\n", err)
		return
	}
	defer blockFile.Close()

	reader := csv.NewReader(blockFile)
	reader.Read() // Bo qua header

	subnetCount := 0

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		// Column 0: network, Column 1/2: geoname_id
		if len(record) > 2 {
			if record[1] == geoID || record[2] == geoID {
				network := record[0]
				g.bpfManager.BlockSubnet(network)
				subnetCount++
			}
		}
	}

	fmt.Printf("[GeoIP] Hoan thanh! Da block %d Subnets cua %s (Truc tiep qua XDP Map).\n", subnetCount, isoCode)
}
