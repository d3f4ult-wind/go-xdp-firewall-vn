//go:build ignore

/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause) */
/**
 * =================================================================================
 * FILE: packet-parsers.h
 * MÔ TẢ: Thư viện tiện ích bóc tách Header gói tin (L2 - L4) cho XDP.
 * LUỒNG HOẠT ĐỘNG:
 *   - Sử dụng cấu trúc `hdr_cursor` để duy trì vị trí đọc hiện tại trong bộ đệm gói tin.
 *   - Mỗi hàm parse sẽ: Kiểm tra biên (Bounds Check) -> Dịch chuyển con trỏ -> Trả về Protocol/Port.
 * TẠI SAO PHẢI DÙNG __always_inline:
 *   - eBPF Verifier yêu cầu các hàm phải được chèn trực tiếp (inline) vào mã máy của chương trình chính.
 *   - Điều này giúp tránh việc thực hiện lời gọi hàm (function call) vốn bị hạn chế ở các bản Kernel cũ.
 * =================================================================================
 */

#ifndef __PARSING_HELPERS_H
#define __PARSING_HELPERS_H

#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/**
 * # CẤU TRÚC ĐIỀU HƯỚNG (Cursor)
 * Mục đích: Lưu trữ con trỏ trỏ đến vị trí tiếp theo cần parse trong bộ nhớ.
 * Giống như một "vạch dấu" khi bạn đọc một chuỗi byte dài.
 */
struct hdr_cursor
{
    void *pos;
};

/**
 * # PARSER ETHERNET (L2)
 * BƯỚC 1: Xác định vị trí header dựa trên cursor.
 * BƯỚC 2: Kiểm tra biên (Bounds Check). 
 *         CẠM BẪY: Đây là bước quan trọng nhất. Nếu không kiểm tra `nh->pos + hdrsize > data_end`,
 *         eBPF Verifier sẽ từ chối nạp chương trình vì nguy cơ truy cập vùng nhớ trái phép (OutOfBounds).
 * BƯỚC 3: Dịch chuyển cursor sang header tiếp theo.
 * BƯỚC 4: Trả về Protocol (IPv4, IPv6, ARP...) ở dạng Network Byte Order.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct ethhdr **ethhdr)
{
    struct ethhdr *eth = nh->pos;
    int hdrsize = sizeof(*eth);

    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *ethhdr = eth;

    return eth->h_proto; 
}

/**
 * # PARSER IPv4 (L3)
 * Trả về: Giao thức tầng trên (TCP=6, UDP=17, ICMP=1).
 */
static __always_inline int parse_iphdr(struct hdr_cursor *nh,
                                       void *data_end,
                                       struct iphdr **iphdr)
{
    struct iphdr *ip = nh->pos;
    int hdrsize = sizeof(*ip);

    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *iphdr = ip;

    return ip->protocol;
}

/**
 * # PARSER IPv6 (L3)
 * Tương tự IPv4 nhưng dành cho địa chỉ 128-bit.
 */
static __always_inline int parse_ipv6hdr(struct hdr_cursor *nh,
                                         void *data_end,
                                         struct ipv6hdr **ipv6hdr)
{
    struct ipv6hdr *ipv6 = nh->pos;
    int hdrsize = sizeof(*ipv6);

    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *ipv6hdr = ipv6;

    return ipv6->nexthdr;
}

/**
 * # PARSER ICMP (L4)
 * Trả về: ICMP Type (ví dụ: Echo Request/Reply).
 */
static __always_inline int parse_icmphdr(struct hdr_cursor *nh,
                                          void *data_end,
                                          struct icmphdr **icmphdr)
{
    struct icmphdr *icmp = nh->pos;
    int hdrsize = sizeof(*icmp);

    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *icmphdr = icmp;

    return icmp->type;
}

static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
                                           void *data_end,
                                           struct icmp6hdr **icmp6hdr)
{
    struct icmp6hdr *icmp6 = nh->pos;
    int hdrsize = sizeof(*icmp6);

    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *icmp6hdr = icmp6;

    return icmp6->icmp6_type;
}

/**
 * # PARSER TCP (L4)
 * BƯỚC 1: Lấy thông tin Port đích (Destination Port).
 * CẠM BẪY: Giá trị trả về `tcp->dest` vẫn đang ở Network Byte Order (Big-endian).
 * Để sử dụng trong logic so sánh bình thường, bạn phải dùng `bpf_ntohs()`.
 */
static __always_inline int parse_tcphdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct tcphdr **tcphdr)
{
    struct tcphdr *tcp = nh->pos;
    int hdrsize = sizeof(*tcp);

    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;

    *tcphdr = tcp;

    return tcp->dest;
}

/**
 * # PARSER UDP (L4)
 * Tương tự TCP, trả về cổng đích của gói tin.
 */
static __always_inline int parse_udphdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct udphdr **udphdr)
{
    struct udphdr *udp = nh->pos;
    int hdrsize = sizeof(*udp);

    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;

    *udphdr = udp;

    return udp->dest;
}

#endif /* __PARSING_HELPERS_H */