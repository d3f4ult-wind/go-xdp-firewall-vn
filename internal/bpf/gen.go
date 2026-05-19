//go:build linux

/**
 * =================================================================================
 * FILE: gen.go
 * MÔ TẢ: Chỉ thị biên dịch tự động eBPF.
 * LUỒNG HOẠT ĐỘNG: 
 *   Khi chạy lệnh `go generate ./...`, Go sẽ tìm các dòng có tiền tố `//go:generate`
 *   và thực thi lệnh đó.
 * CÔNG CỤ: bpf2go (từ thư viện cilium/ebpf).
 *   - Nó biên dịch file C (`xdp-filter.c`) thành mã máy eBPF.
 *   - Nó tạo ra các file Go (`_bpfel.go`, `_bpfeb.go`) chứa các struct và hàm helper.
 * -tags linux: eBPF là tính năng đặc thù của Linux Kernel, tag này đảm bảo code chỉ chạy trên Linux.
 * xdp_packet_filter: Tiền tố tên cho các hàm/struct sẽ được sinh ra.
 * xdp-filter.c: File nguồn C chứa logic firewall trong Kernel.
 * =================================================================================
 */

package bpf 

//go:generate go tool bpf2go -tags linux xdp_packet_filter xdp-filter.c