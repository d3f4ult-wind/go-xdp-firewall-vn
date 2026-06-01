//go:build ignore
/**
 * =================================================================================
 * FILE: xdp-filter.c
 * MÔ TẢ: Chương trình XDP (eBPF) thực hiện lọc gói tin (Firewall) hiệu năng cao.
 * LUỒNG HOẠT ĐỘNG: 
 *   1. Nhận gói tin từ card mạng (Ingress).
 *   2. Giải mã Header (L2 -> L3).
 *   3. Tìm kiếm Subnet ID của IP nguồn bằng giải thuật Longest Prefix Match (LPM).
 *   4. Dựa trên Subnet ID, kiểm tra luật (Protocol + Port) trong Hash Map.
 *   5. Trả về quyết định: XDP_PASS (cho qua) hoặc XDP_DROP (chặn).
 * CẢI TIẾN: Sử dụng LPM Trie để hỗ trợ chặn theo dải IP (CIDR) thay vì chỉ IP tĩnh.
 * =================================================================================
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "packet-parsers.h"

/* --- Maps (Cấu trúc dữ liệu chia sẻ giữa Kernel và User-space) --- */

// Cấu trúc key cho LPM (Longest Prefix Match)
// CẠM BẪY: prefixlen phải nằm ngay trước dữ liệu IP để eBPF Verifier hiểu đây là LPM key.
struct ipv4_lpm_key {
    __u32 prefixlen; // Độ dài prefix (vd: 24 cho /24)
    __u8 addr[4];    // Địa chỉ IPv4 (dạng mảng byte để giữ đúng thứ tự Network Byte Order)
};

// Cấu trúc định danh luật (Rule ID)
struct rule_id {
    __u32 subnet_id; // ID định danh dải mạng (đã ánh xạ từ subnet_map)
    int proto;       // Giao thức (TCP/UDP/ICMP)
    __u32 port;      // Cổng đích (Destination Port)
};

/**
 * Cấu trúc lưu trữ số lượng gói tin (count) và thời gian bắt đầu tính (window_start_ns)
 * cho mỗi địa chỉ IP nguồn.
 */
struct rl_metrics {
    __u64 window_start_ns;
    __u32 count;
    __u32 pad;
};

/**
 * # AUTO BLOCK MAP (Dành cho Watcher / Suricata / IPTABLES / GeoIP)
 * Lưu trữ các dải IP (Subnet) bị chặn tự động từ hệ thống ngoài.
 * Sử dụng LPM Trie để có thể chặn cả IP đơn lẻ (/32) và dải mạng (/24, /16).
 * Value là timestamp (giây) để hệ thống ngoài dùng làm mốc thả IP (Auto-unban).
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u64);
    __uint(max_entries, 100000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} auto_block_map SEC(".maps");

/**
 * # RATE LIMIT MAP
 * LƯU Ý CHO GO-SIDE: Map này là PERCPU. Khi Go-side đọc map này,
 * nó sẽ nhận được một slice/array chứa các value của từng CPU core.
 * Cần cộng tổng giá trị count của tất cả các CPU lại để ra tổng ước lượng
 * số packet/s của một IP.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __type(key, __u32);
    __type(value, struct rl_metrics);
    __uint(max_entries, 65536);
} rate_limit_map SEC(".maps");

/**
 * # RATE LIMIT & SYSTEM CONFIG MAP
 * Index 0: PPS_THRESHOLD (mặc định: 1000)
 * Index 1: TIME_WINDOW_NS (mặc định: 1000000000 - 1s)
 * Index 2: ENFORCEMENT_FLAG (0: Tắt Firewall (PASS hết), 1: Bật Firewall)
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
	__uint(max_entries, 3);
} rl_config_map SEC(".maps");

/* ==============================================================================
 * TIER 1 MAPS (ADAPTIVE MITIGATION)
 * Các Map này được thiết kế riêng để chống lại Spoofed SYN Flood (rand-source).
 * ============================================================================== */

/**
 * # GEO TRUST MAP (Tier 1)
 * Lưu trữ danh sách CIDR (ví dụ: các IP Việt Nam) để ưu tiên giảm tỷ lệ rớt.
 * Value: __u32 trust_score (thực tế chỉ làm cờ đánh dấu 0/1).
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u32);
    __uint(max_entries, 100000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} geo_trust_map SEC(".maps");

/**
 * # TRUSTED MAP (Tier 1 Dynamic Whitelist)
 * Chỉ chứa các IP ĐƠN LẺ (/32) đã được Go Controller xác minh (ví dụ: qua TCP 3-way handshake).
 * Value: __u64 timestamp (để Controller dọn dẹp các entry cũ).
 * Nếu IP nằm trong này, nó sẽ Bypass toàn bộ Tier 1 Mitigation (nhưng vẫn qua Tier 2).
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32); // Network byte order IPv4
    __type(value, __u64);
    __uint(max_entries, 65536);
} trusted_map SEC(".maps");

/**
 * # MITIGATION MAP (Tier 1 Control)
 * Bảng điều khiển từ Go Controller xuống XDP.
 * Index 0: protection_level (0: Tắt Tier 1, 1-3: Các mức độ tấn công)
 * Index 1: syn_drop_percent (0-100)
 * Index 2: udp_drop_percent (0-100)
 * Index 3: icmp_drop_percent (0-100)
 * Index 4: geo_syn_drop_percent (0-100)
 * Index 5: geo_udp_drop_percent (0-100)
 * Index 6: geo_icmp_drop_percent (0-100)
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 7);
} mitigation_map SEC(".maps");

/**
 * # MITIGATION STATS (Tier 1 Telemetry)
 * Cung cấp số liệu thời gian thực về tình trạng rớt/nhận gói tin ở Tier 1.
 * Index 0: total_packets
 * Index 1: trusted_hits
 * Index 2: geo_hits
 * Index 3: syn_dropped
 * Index 4: udp_dropped
 * Index 5: icmp_dropped
 * Index 6: tier2_passed
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 7);
} mitigation_stats SEC(".maps");

/**
 * # BẢN ĐỒ SUBNET (LPM Trie)
 * Tại sao dùng BPF_MAP_TYPE_LPM_TRIE? 
 * -> Cho phép tìm kiếm IP theo dải (Subnet). Ví dụ: gói tin từ 192.168.1.5 
 *    sẽ khớp với luật của dải 192.168.1.0/24.
 * -> Nếu muốn chặn theo IP tĩnh, chỉ cần đổi prefixlen thành 32 (IPv4). Ví dụ 192.168.1.5/32 sẽ chỉ khớp với đúng IP đó.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u32); // Trả về subnet_id
    __uint(max_entries, 10000);
    __uint(map_flags, BPF_F_NO_PREALLOC); // Tiết kiệm RAM, chỉ cấp phát khi cần
} subnet_map SEC(".maps");

/**
 * # BẢN ĐỒ LUẬT (Hash Map)
 * Lưu trữ các action cụ thể (DROP/PASS) cho từng bộ {Subnet, Proto, Port}.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct rule_id);
    __type(value, __u32); // Trả về XDP_PASS hoặc XDP_DROP
    __uint(max_entries, 65536);
} rule_map SEC(".maps");

/**
 * # CẤU HÌNH MẶC ĐỊNH (Array Map)
 * Chỉ chứa 1 phần tử duy nhất để lưu "Default Action" nếu không khớp bất kỳ luật nào.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} default_action_map SEC(".maps");


/* --- Các hàm xử lý giao thức (Helper Functions) --- */

// __always_inline: Ép trình biên dịch chèn thẳng code vào hàm chính.
// Lý do: Các bản kernel cũ không hỗ trợ gọi hàm con (function call) trong eBPF.
static __always_inline int handle_icmp(struct hdr_cursor *nh, void *data_end, __u32 subnet_id, __u32 *default_rc){
    struct icmphdr *icmph;
    
    // Kiểm tra tính hợp lệ của header để tránh lỗi truy cập vùng nhớ trái phép (OutOfBounds)
    if(parse_icmphdr(nh, data_end, &icmph) == -1 ) return XDP_DROP;
    
    struct rule_id id = {
        .subnet_id = subnet_id,        
        .proto = IPPROTO_ICMP,
        .port = 0 // ICMP không có khái niệm port, mặc định là 0
    };
    
    // Tìm kiếm luật trong rule_map
    __u32 *rc = bpf_map_lookup_elem(&rule_map, &id);

    // Nếu không có luật riêng cho ICMP, dùng hành động mặc định của hệ thống
    if(!rc) return *default_rc;

    return *rc;
}

static __always_inline int handle_tcp(struct hdr_cursor *nh, void *data_end, __u32 subnet_id, __u32 *default_rc){
    struct tcphdr *tcph;
    if(parse_tcphdr(nh, data_end, &tcph) == -1 ) return XDP_DROP;
    
    // Chuyển đổi Network Byte Order sang Host Byte Order (Big-endian -> Little-endian)
    // CẠM BẪY: Nếu quên bước này, số port sẽ bị sai lệch hoàn toàn.
    __u16 dport = bpf_ntohs(tcph->dest);

    struct rule_id id = {
        .subnet_id = subnet_id,        
        .proto = (int)IPPROTO_TCP,
        .port = (__u32)dport
    };
    
    __u32 *rc = bpf_map_lookup_elem(&rule_map, &id);

    if(!rc) return *default_rc;

    return *rc;
}

static __always_inline int handle_udp(struct hdr_cursor *nh, void *data_end, __u32 subnet_id, __u32 *default_rc){
    struct udphdr *udph;
    if(parse_udphdr(nh, data_end, &udph) == -1 ) return XDP_DROP;
    
    __u16 dport = bpf_ntohs(udph->dest);
    
    struct rule_id id = {
        .subnet_id = subnet_id,        
        .proto = IPPROTO_UDP,
        .port = (__u32)dport
    };
    
    __u32 *rc = bpf_map_lookup_elem(&rule_map, &id);

    if(!rc) return *default_rc;
    return *rc;
}


/* --- Điểm nạp chương trình chính (Entry Point) --- */

static __always_inline void update_mitigation_stat(__u32 index) {
    __u64 *val = bpf_map_lookup_elem(&mitigation_stats, &index);
    if (val) {
        *val += 1;
    }
}

SEC("xdp")
int xdp_packet_filter(struct xdp_md *ctx){
    // Trỏ tới điểm bắt đầu và kết thúc của vùng đệm gói tin
    void *data = (void *)(long)ctx->data; 
    void *data_end = (void *)(long)ctx->data_end;

    // # BƯỚC 0: Kiểm tra Enforcement Flag (Công tắc Benchmark)
    // Nếu cờ = 0, Firewall đang ở Phase 2 (Tắt phòng vệ), cho qua toàn bộ gói tin
    __u32 config_key_enforce = 2;
    __u32 *enforce_ptr = bpf_map_lookup_elem(&rl_config_map, &config_key_enforce);
    if (enforce_ptr && *enforce_ptr == 0) {
        return XDP_PASS;
    }

    // # BƯỚC 1: Lấy cấu hình mặc định (Default Action)
    // Nếu map này rỗng (chưa khởi tạo từ User-space), chặn đứng để đảm bảo an toàn.
    __u32 key = 0;
    __u32 *default_rc = bpf_map_lookup_elem(&default_action_map, &key);
    if(!default_rc) return XDP_DROP;

    struct ethhdr *ethh;
    struct iphdr *iph;
    
    // Header cursor giúp theo dõi vị trí đang đọc trong packet
    struct hdr_cursor nh;
    nh.pos = data;
    
    // # BƯỚC 2: Phân giải Ethernet Header (L2)
    if(parse_ethhdr(&nh, data_end, &ethh) == -1){
        return XDP_DROP; // Packet bị lỗi hoặc không đủ độ dài tối thiểu
    }

    // Chỉ xử lý IPv4, các protocol khác (như IPv6, ARP) cho đi qua để tránh treo mạng
    if(ethh->h_proto != bpf_htons(ETH_P_IP)){
        return XDP_PASS;
    }

    // # BƯỚC 3: Phân giải IP Header (L3)
    if(parse_iphdr(&nh, data_end, &iph) == -1){
        return XDP_DROP;
    }

    __u32 src_ip = iph->saddr;
    int protocol = iph->protocol;

    /* ==============================================================================
     * TIER 1: ADAPTIVE MITIGATION (Chống Rand-Source Flood)
     * ============================================================================== */
    update_mitigation_stat(0); // Index 0: total_packets

    __u8 skip_mitigation = 0;
    __u8 geo_priority = 0;

    // 1. Kiểm tra Trusted Map (Dynamic Whitelist)
    __u64 *trusted_ts = bpf_map_lookup_elem(&trusted_map, &src_ip);
    if (trusted_ts) {
        __u64 now = bpf_ktime_get_ns();
        bpf_map_update_elem(&trusted_map, &src_ip, &now, BPF_ANY); // Cập nhật last_seen
        update_mitigation_stat(1); // Index 1: trusted_hits
        skip_mitigation = 1;
    }

    // 2. Kiểm tra Geo Trust Map
    if (!skip_mitigation) {
        struct ipv4_lpm_key geo_key = {};
        geo_key.prefixlen = 32;
        *(__u32 *)geo_key.addr = src_ip;
        
        __u32 *geo_score = bpf_map_lookup_elem(&geo_trust_map, &geo_key);
        if (geo_score) {
            update_mitigation_stat(2); // Index 2: geo_hits
            geo_priority = 1;
        }
    }

    // 3. Probabilistic Drop (Chỉ áp dụng nếu chưa skip và Protection Level > 0)
    if (!skip_mitigation) {
        __u32 key_level = 0;
        __u32 *level = bpf_map_lookup_elem(&mitigation_map, &key_level);
        
        if (level && *level > 0) {
            __u32 drop_percent = 0;
            __u32 stat_idx = 0;
            __u8 should_check_drop = 0;

            if (protocol == IPPROTO_TCP) {
                // Phải check SYN. Nhòm thử header TCP.
                struct hdr_cursor temp_nh = nh;
                struct tcphdr *tcph;
                if (parse_tcphdr(&temp_nh, data_end, &tcph) != -1) {
                    if (tcph->syn == 1 && tcph->ack == 0) {
                        __u32 key_drop = geo_priority ? 4 : 1;
                        __u32 *dp = bpf_map_lookup_elem(&mitigation_map, &key_drop);
                        if (dp) drop_percent = *dp;
                        stat_idx = 3; // syn_dropped
                        should_check_drop = 1;
                    }
                }
            } else if (protocol == IPPROTO_UDP) {
                __u32 key_drop = geo_priority ? 5 : 2;
                __u32 *dp = bpf_map_lookup_elem(&mitigation_map, &key_drop);
                if (dp) drop_percent = *dp;
                stat_idx = 4; // udp_dropped
                should_check_drop = 1;
            } else if (protocol == IPPROTO_ICMP) {
                __u32 key_drop = geo_priority ? 6 : 3;
                __u32 *dp = bpf_map_lookup_elem(&mitigation_map, &key_drop);
                if (dp) drop_percent = *dp;
                stat_idx = 5; // icmp_dropped
                should_check_drop = 1;
            }

            if (should_check_drop && drop_percent > 0) {
                if ((bpf_get_prandom_u32() % 100) < drop_percent) {
                    update_mitigation_stat(stat_idx);
                    return XDP_DROP;
                }
            }
        }
    }

    /* ==============================================================================
     * TIER 2: PER-IP DEFENSE (Rate Limit, Auto Block, Rules)
     * ============================================================================== */

    // # BƯỚC 3.1: Kiểm tra danh sách đen tự động (Auto Block Map từ Watcher)
    // Cấu trúc key giống hệt ipTrie: Tìm kiếm dải mạng cha bao trùm IP này
    struct ipv4_lpm_key auto_key = {};
    auto_key.prefixlen = 32;
    *(__u32 *)auto_key.addr = src_ip;
    
    __u64 *block_ts = bpf_map_lookup_elem(&auto_block_map, &auto_key);
    if (block_ts) {
        return XDP_DROP;
    }

    // # BƯỚC 3.5: Rate Limiting
    __u64 now = bpf_ktime_get_ns();
    
    __u32 config_key_thresh = 0;
    __u32 *thresh_ptr = bpf_map_lookup_elem(&rl_config_map, &config_key_thresh);
    __u32 threshold = (thresh_ptr && *thresh_ptr > 0) ? *thresh_ptr : 1000;
    
    __u32 config_key_window = 1;
    __u32 *window_ptr = bpf_map_lookup_elem(&rl_config_map, &config_key_window);
    __u64 window = (window_ptr && *window_ptr > 0) ? (__u64)(*window_ptr) : 1000000000ULL;

    struct rl_metrics *metrics = bpf_map_lookup_elem(&rate_limit_map, &src_ip);
    if (metrics) {
        if (now - metrics->window_start_ns <= window) {
            metrics->count += 1;
            if (metrics->count > threshold) {
                return XDP_DROP;
            }
        } else {
            metrics->count = 1;
            metrics->window_start_ns = now;
        }
    } else {
        struct rl_metrics new_metrics = {
            .window_start_ns = now,
            .count = 1,
            .pad = 0
        };
        bpf_map_update_elem(&rate_limit_map, &src_ip, &new_metrics, BPF_ANY);
    }

    // # BƯỚC 4: Tìm kiếm Subnet (LPM Matching)
    // KHÔNG chuyển đổi IP nguồn sang host order nữa.
    // Cứ giữ nguyên Network Byte Order để LPM so sánh đúng chuẩn mạng.
    struct ipv4_lpm_key subnet_key = {};
    subnet_key.prefixlen = 32; // Ban đầu tìm kiếm chính xác IP (Host match)
    
    // Ép kiểu mảng addr thành __u32 pointer để gán toàn bộ 4 byte cùng lúc cho tối ưu
    *(__u32 *)subnet_key.addr = iph->saddr;

    // eBPF kernel sẽ tự thực hiện giải thuật Trie để tìm dải mạng phù hợp nhất (Longest Prefix)
    __u32 *subnet_id = bpf_map_lookup_elem(&subnet_map, &subnet_key);
    
    // Nếu IP nguồn không thuộc bất kỳ dải quản lý nào -> Áp dụng Default Action
    // Nếu IP nguồn không thuộc bất kỳ dải quản lý nào -> Áp dụng Default Action
    if(!subnet_id){
        if (*default_rc == XDP_PASS) update_mitigation_stat(6);
        return *default_rc;
    }

    // # BƯỚC 5: Phân giải Layer 4 và áp dụng luật cụ thể
    __u32 sid = *subnet_id;
    int rc = *default_rc;
    
    // Phân nhánh xử lý dựa trên protocol
    if (iph->protocol == IPPROTO_TCP){
        rc = handle_tcp(&nh, data_end, sid, default_rc);
    }
    else if (iph->protocol == IPPROTO_UDP){
        rc = handle_udp(&nh, data_end, sid, default_rc);
    }
    else if (iph->protocol == IPPROTO_ICMP){
        rc = handle_icmp(&nh, data_end, sid, default_rc);
    }

    // Nếu lọt qua toàn bộ firewall mà là PASS
    if (rc == XDP_PASS) {
        update_mitigation_stat(6); // tier2_passed
    }

    return rc;
}

// Bắt buộc phải có license để sử dụng các hàm helper của Kernel (GPL)
char __license[] SEC("license") = "GPL";