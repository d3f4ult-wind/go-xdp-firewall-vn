================================================================================
        KẾ HOẠCH BENCHMARK - HYBRID FIREWALL (PHIÊN BẢN 2 - TỐI ƯU)
          Dành cho Báo cáo Đồ án Tốt nghiệp
          Môi trường: Ubuntu 24.04
================================================================================


────────────────────────────────────────────────────────────────────────────────
PHẦN 0: MỤC TIÊU & TIÊU CHÍ THÀNH CÔNG
────────────────────────────────────────────────────────────────────────────────

Benchmark này nhằm chứng minh 4 luận điểm cốt lõi của hệ thống:

  (1) Service Availability: Người dùng hợp lệ vẫn truy cập được dịch vụ
      trong suốt quá trình bị tấn công.

  (2) Early Drop Efficiency: XDP loại bỏ gói tin độc hại trước khi chúng
      đi qua toàn bộ kernel networking stack, giúp giảm tải CPU so với
      phương pháp xử lý tại tầng iptables/nftables truyền thống.

  (3) Precision: Chỉ block đúng đối tượng, không gây false positive
      với người dùng hợp lệ.

  (4) Resilience: Hệ thống tự phục hồi sau khi tấn công dừng,
      không có memory leak hay trạng thái bị kẹt.

Tiêu chí thành công (Success Criteria) — đây là ngưỡng khách quan để
đánh giá kết quả thay vì chỉ quan sát định tính:

  - Legitimate request success rate  : >= 95%
  - p99 latency của Normal User      : < 100ms trong Phase 3 (Defense Active)
  - conntrack usage                  : < 80% max capacity trong mọi phase
  - Recovery time sau khi dừng attack: < 10 giây
  - XDP_DROP rate tăng sau khi block : phải cao hơn Phase 2 ít nhất 10x

Nếu bất kỳ chỉ số nào không đạt ngưỡng trên, đó là tín hiệu cần điều
tra thêm — không phải thất bại, mà là phát hiện có giá trị để ghi vào
báo cáo.


────────────────────────────────────────────────────────────────────────────────
PHẦN 1: THÔNG TIN MÔI TRƯỜNG (HARDWARE & KERNEL SNAPSHOT)
────────────────────────────────────────────────────────────────────────────────

Trước khi chạy bất kỳ benchmark nào, script phải tự động thu thập và
ghi vào file system_snapshot.txt các thông tin sau để đảm bảo
reproducibility — tức là người khác có thể tái hiện lại kết quả trong
điều kiện tương tự:

  - CPU model, số core, frequency          →  lscpu
  - RAM tổng                               →  free -h
  - NIC model, driver, firmware version    →  ethtool -i <interface>
  - Số RX/TX queue của NIC                 →  ethtool -l <interface>
  - IRQ affinity hiện tại                  →  cat /proc/interrupts
  - Kernel version                         →  uname -a
  - XDP mode đang dùng (native/generic)    →  ip link show <interface>
  - NIC offload settings                   →  ethtool -k <interface>
  - cpufreq governor                       →  cat /sys/devices/system/cpu/
                                               cpu*/cpufreq/scaling_governor
  - Thời điểm chạy benchmark (UTC)         →  date -u

Lưu ý về cpufreq: nếu governor đang là "ondemand" hoặc "powersave",
CPU sẽ chạy ở tần số thấp lúc đầu và scale up dần, làm lệch số liệu
ở các giây đầu tiên. Nên chuyển sang "performance" trước khi benchmark:
  echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor


────────────────────────────────────────────────────────────────────────────────
PHẦN 2: KIẾN TRÚC ĐO LƯỜNG (TOPOLOGY & SETUP)
────────────────────────────────────────────────────────────────────────────────

Benchmark sử dụng 4 node (hoặc 4 Linux Network Namespace nếu chạy
trên cùng 1 máy vật lý):

  [1] Victim (Web Server)
      Chạy Apache hoặc Nginx với cấu hình mặc định, không có performance
      tuning. Lý do dùng cấu hình mặc định: để phản ánh đúng điều kiện
      triển khai phổ biến trong môi trường tài nguyên hạn chế — đúng với
      target audience của hệ thống.

  [2] Normal User (Netns: whitelist)
      Chạy wrk liên tục từ đầu đến cuối toàn bộ bài test với ~50
      connections. Đây là thước đo quan trọng nhất xuyên suốt: dịch vụ
      còn sống với người dùng hợp lệ hay không?

  [3] Attacker (Netns: blacklist / fake IP)
      Bắn SYN Flood bằng hping3 và chạy script Python giả mạo IP thuộc
      dải GeoIP bị block (ví dụ: dải CIDR của Trung Quốc).

  [4] Blocked User (Netns: IP thuộc dải GeoIP bị block)
      Đóng vai người dùng đến từ quốc gia bị chặn, cố truy cập server.
      Node này cần thiết để chứng minh đồng thời 3 luồng xảy ra song
      song: legitimate user vào được, GeoIP traffic bị drop trước khi
      qua kernel stack, attacker bị rate-limit.

Về đồng bộ thời gian giữa các node: không cần đồng bộ hoàn hảo.
Mỗi node tự ghi Unix timestamp (epoch) vào từng dòng CSV. Khi phân
tích, các file được join theo cột timestamp thực tế thay vì "giây thứ N
kể từ khi bắt đầu". Độ lệch khởi động 1-2 giây giữa các node là hoàn
toàn chấp nhận được với độ phân giải đo 1 giây/lần. Đảm bảo tất cả
node đang sync NTP (kiểm tra bằng timedatectl).

So sánh giữa các chế độ (Comparison Matrix):
Để chứng minh hybrid tốt hơn từng thành phần riêng lẻ, nên chạy
toàn bộ kịch bản cho cả 4 chế độ sau:

  [A] Raw Linux forwarding (không có firewall rule nào)
  [B] iptables only (không có XDP)
  [C] XDP only (không có Suricata/iptables)
  [D] Hybrid mode (hệ thống đầy đủ)

Nếu thời gian không cho phép chạy cả 4, ưu tiên tối thiểu là [B] và
[D] để có so sánh có ý nghĩa: "hybrid tốt hơn iptables thuần túy như
thế nào?"


────────────────────────────────────────────────────────────────────────────────
PHẦN 3: CÁC CHỈ SỐ CẦN THU THẬP (METRICS)
────────────────────────────────────────────────────────────────────────────────

Script benchmark chạy ngầm trên máy Firewall, ghi log ra file CSV
mỗi 1 giây / lần, có cột timestamp Unix ở đầu mỗi dòng.
Nguyên tắc: đo được gì thì đo hết, quyết định dùng hay không sau khi
có dữ liệu.

  3.1 CPU & Hệ thống
  ──────────────────
  CPU tổng thể (%user, %system, %idle) và CPU SoftIRQ (%si) lấy từ
  mpstat. SoftIRQ là chỉ số quan trọng nhất để so sánh XDP với iptables:
  khi XDP hoạt động, gói tin bị loại bỏ trước khi kích hoạt softirq
  handler, nên %si phải giảm rõ rệt dù traffic vẫn cao.
  Context switch per giây lấy từ vmstat, RAM (used/free/buff-cache)
  từ free -m.

  3.2 Network Stack & Conntrack
  ──────────────────────────────
  RX/TX PPS và BPS per NIC từ sar -n DEV. Đặc biệt cần theo dõi sát:

  - nf_conntrack_count và nf_conntrack_max từ /proc/sys/net/netfilter/
    Đây là điểm chết thầm lặng nguy hiểm nhất: khi bị SYN Flood,
    conntrack table có thể đầy → legitimate traffic cũng bị drop dù
    rule không block. conntrack_count tiệm cận conntrack_max là tín
    hiệu nguy hiểm cần ghi nhận rõ trong báo cáo.

  - TCP state summary từ ss -s: theo dõi SYN_RECV tăng vọt là dấu
    hiệu SYN Flood chưa bị chặn kịp.

  - TCP retransmissions và packet loss từ netstat -s hoặc
    /proc/net/snmp: retransmission rate tăng cao là bằng chứng trực
    tiếp của service degradation, quan trọng hơn chỉ số CPU khi đánh
    giá service health.

  - SYN backlog overflow và TCP reset rate từ /proc/net/netstat.

  3.3 XDP / eBPF Counters
  ────────────────────────
  XDP_DROP/s, XDP_PASS/s, XDP_TX/s đọc từ eBPF maps hoặc bpftool /
  perf counters. Đây là bằng chứng trực tiếp rằng gói tin bị loại bỏ
  trước khi đi qua toàn bộ kernel networking stack — luận điểm kỹ thuật
  cốt lõi của thesis.

  Lưu ý wording quan trọng: trong báo cáo nên viết "dropped at the
  XDP layer, before traversing the full kernel networking stack" thay
  vì "dropped at the NIC hardware". XDP native mode chạy ở driver layer,
  không phải hardware offload thực sự. Chỉ XDP offload mode mới xuống
  NIC hardware — và không phải NIC nào cũng hỗ trợ.

  eBPF map update latency (ns) là optional/advanced metric: khó đo
  chính xác và nhiễu nhiều, chỉ collect nếu có công cụ sẵn sàng.

  3.4 nftables / iptables Rule Counters
  ──────────────────────────────────────
  Số lần match mỗi rule/chain từ nft list ruleset với counter enabled.
  Dùng để xác định rule nào đang được hit nhiều nhất, không nên claim
  "chain traversal cost" vì iptables/nftables không dễ đo traversal
  latency chính xác.

  3.5 Suricata IDS Stats
  ───────────────────────
  Đọc từ stats.log của Suricata (tự export mỗi vài giây):
  capture.kernel_drops, decoder.pkts, flow.memcap_delta.
  Dùng để xác định Suricata có bị overwhelm hay không khi traffic
  tăng đột biến.

  3.6 Web Server (Victim)
  ────────────────────────
  Số active connections từ ss -s trên server, response time trung bình
  từ access log của Apache/Nginx, worker process usage từ pidstat.

  3.7 wrk (Normal User)
  ──────────────────────
  Requests/sec, Throughput (MB/s), Latency p50/p95/p99 (bật flag
  --latency), số request timeout và error.
  p99 latency là metric production-grade quan trọng nhất: nó thể hiện
  "người dùng tệ nhất đang trải nghiệm gì" — hội đồng sẽ đánh giá cao
  chỉ số này so với chỉ đo throughput đơn thuần.


────────────────────────────────────────────────────────────────────────────────
PHẦN 4: PHƯƠNG PHÁP CHẠY (REPEATED RUNS & VARIANCE)
────────────────────────────────────────────────────────────────────────────────

Mỗi scenario phải được chạy ít nhất 3 lần độc lập. Networking benchmark
có nhiều nguồn nhiễu tự nhiên: CPU scheduler, cache state, IRQ balancing,
thermal throttling, background kernel activity. Chạy 1 lần duy nhất
không thể phân biệt được kết quả thực sự với nhiễu ngẫu nhiên.

Sau 3 lần chạy, lấy median (không phải average) của từng metric tại
từng giây. Median ít bị ảnh hưởng bởi outlier hơn average — phù hợp
với networking data vốn có spike bất thường.

Nên ghi lại variance (độ lệch giữa các lần chạy) vào báo cáo. Variance
thấp = kết quả ổn định và đáng tin. Variance cao = cần điều tra thêm
nguyên nhân (thường là background process hoặc thermal throttling).

Trước mỗi lần chạy, nên có bước chuẩn bị nhỏ: để hệ thống idle 30
giây, xóa conntrack table (conntrack -F), và để wrk chạy thử 10 giây
không tính vào kết quả chính. Bước này giúp ổn định CPU frequency,
làm ấm cache, và cho phép connection pool của wrk ổn định trước khi
đo chính thức — thay vì thêm hẳn một warmup phase vào timeline.


────────────────────────────────────────────────────────────────────────────────
PHẦN 5: KỊCH BẢN CHẠY (TIMELINE ~165 GIÂY, 5 PHASE)
────────────────────────────────────────────────────────────────────────────────

Tổng timeline một lần chạy (không tính warmup):

  ┌──────────┬──────────┬─────────────┬───────────────┬────────────┐
  │ Phase 0  │ Phase 1  │  Phase 2    │   Phase 3     │  Phase 4   │
  │  Idle    │  Normal  │  Attack /   │ Full Defense  │  Recovery  │
  │  (30s)   │  Load    │ No Defense  │  Active (30s) │   (30s)    │
  │          │  (30s)   │   (30s)     │               │            │
  └──────────┴──────────┴─────────────┴───────────────┴────────────┘
   T=0      T=30       T=60          T=90            T=120        T=150+


  PHASE 0 — System Idle (T=0 → T=30)
  ────────────────────────────────────
  Không chạy bất kỳ thứ gì. Chỉ để hệ thống ở trạng thái hoàn toàn
  nhàn rỗi. Mục đích là ghi lại đường baseline thực sự của máy (CPU
  nền, RAM nền, conntrack_count nền). Đây là tham chiếu cho mọi biểu
  đồ phía sau — không có nó thì không có điểm xuất phát để so sánh.

  Kỳ vọng quan sát (expected observation):
  CPU có thể ở mức ~0-2%, RAM ổn định, không có traffic đáng kể.


  PHASE 1 — Normal Load (T=30 → T=60)
  ──────────────────────────────────────
  Bật wrk từ Normal User với ~50 connections. Chưa có tấn công nào.
  Đây là "trạng thái bình thường lý tưởng" mà hệ thống cần đạt lại
  được sau khi tấn công kết thúc ở Phase 4.

  Kỳ vọng quan sát:
  CPU Firewall có thể ở mức thấp, Server có xu hướng trả HTTP 200 OK,
  wrk latency p99 dự kiến ở mức vài ms, ít hoặc không có timeout.


  PHASE 2 — Attack WITHOUT Defense (T=60 → T=90)
  ──────────────────────────────────────────────────
  Kích hoạt hping3 SYN Flood và script giả IP GeoIP. Normal User (wrk)
  vẫn đang chạy. CHƯA kích hoạt XDP block. Phase này kéo dài 30 giây
  để conntrack pressure có đủ thời gian ổn định và Suricata stress
  trở nên rõ ràng.

  Đây là phase quan trọng nhất về mặt học thuật: nó thể hiện "hệ thống
  trước khi có giải pháp" và là "điểm đau" để justify toàn bộ công
  trình. Không có phase này thì Phase 3 không có giá trị so sánh.

  Kỳ vọng quan sát:
  CPU SoftIRQ có xu hướng tăng, conntrack_count có xu hướng tăng nhanh,
  wrk có thể bắt đầu báo timeout hoặc latency tăng, Suricata có thể
  bắt đầu log cảnh báo và kernel_drops tăng.


  PHASE 3 — Full Defense Active (T=90 → T=120)
  ───────────────────────────────────────────────
  Kích hoạt XDP, GeoIP block, Rate Limit. Attacker vẫn đang bắn.
  Normal User vẫn đang chạy. Blocked User cũng cố kết nối.
  Đây là trái tim của toàn bộ benchmark.

  Kỳ vọng quan sát (theo thời gian):
  Trong khoảng T=90-93: Heuristic engine có xu hướng phát hiện IP GeoIP
  → kích hoạt BlockCountry xuống eBPF map. Rate Limit dự kiến tóm
  SYN Flood và đẩy xuống XDP.
  Từ T=94 trở đi: XDP_DROP/s dự kiến tăng mạnh. CPU SoftIRQ có xu
  hướng giảm so với Phase 2 (gói bị loại bỏ trước khi đi qua kernel
  networking stack, không kích hoạt softirq handler). wrk của Normal
  User dự kiến phục hồi latency về gần mức Phase 1. Blocked User
  dự kiến bị drop hoàn toàn.


  PHASE 4 — Recovery (T=120 → T=150)
  ──────────────────────────────────────
  Dừng tất cả script tấn công. wrk Normal User vẫn chạy.
  Quan sát hệ thống tự ổn định và kiểm tra không có resource leak.

  Kỳ vọng quan sát:
  conntrack_count có xu hướng giảm dần về mức bình thường, XDP counter
  tự reset, RAM dự kiến không tăng (không có memory leak), CPU và wrk
  latency dự kiến trở về mức Phase 1.


────────────────────────────────────────────────────────────────────────────────
PHẦN 6: KẾT QUẢ ĐẦU RA (OUTPUT FILES)
────────────────────────────────────────────────────────────────────────────────

Script tạo thư mục: benchmark_results_YYYYMMDD_HHMMSS/

Mỗi lần chạy tạo một thư mục riêng (run_1/, run_2/, run_3/) để giữ
nguyên dữ liệu thô trước khi tổng hợp median.

  system_snapshot.txt
    → Hardware, kernel, NIC, offload settings thu thập trước khi chạy.

  firewall_cpu_mem.csv
    → Cột: timestamp_unix, cpu_user, cpu_sys, cpu_softirq, cpu_idle,
           ram_used_mb, ram_free_mb, context_switch_per_sec
    → Ghi mỗi 1 giây.

  firewall_net_stack.csv
    → Cột: timestamp_unix, rx_pps, tx_pps, rx_bps, tx_bps,
           conntrack_count, conntrack_max, tcp_syn_recv, tcp_estab,
           tcp_retransmits, tcp_resets, syn_backlog_overflow
    → Ghi mỗi 1 giây.

  firewall_xdp_nft.csv
    → Cột: timestamp_unix, xdp_drop_per_sec, xdp_pass_per_sec,
           xdp_tx_per_sec, nft_chain_hits (per chain)
    → Ghi mỗi 1 giây.

  firewall_suricata.csv
    → Cột: timestamp_unix, kernel_drops, decoder_pkts, flow_memcap_delta
    → Lấy từ Suricata stats.log.

  server_victim.csv
    → Cột: timestamp_unix, active_connections, response_time_avg_ms,
           worker_usage_pct
    → Ghi mỗi 1 giây.

  normal_user_wrk.log
    → Requests/sec, Throughput, p50/p95/p99 latency, timeout_count,
           error_count
    → Ghi theo interval của wrk, có timestamp.

  timeline_events.csv  ← KHÔNG ĐƯỢC BỎ QUA
    → Cột: timestamp_unix, event_name, note
    → Ghi tay timestamp của từng sự kiện: bắt đầu attack, XDP load,
      GeoIP block kích hoạt, dừng attack.
    → Dùng để vẽ đường dọc (vertical marker) trên biểu đồ, giúp người
      đọc báo cáo hiểu ngay "điểm này là lúc firewall phản ứng".
      Không có marker này thì biểu đồ trông như đường ngoằn ngoèo
      khó giải thích.

Xử lý sau khi có dữ liệu từ 3 lần chạy:
  → Dùng Python (Pandas + Matplotlib) để tính median từng metric theo
    timestamp, sau đó vẽ biểu đồ với trục X là thời gian (giây) và
    vertical marker từ timeline_events.csv. Mỗi biểu đồ nên hiển thị
    cả median line và shaded area thể hiện variance giữa 3 lần chạy.


────────────────────────────────────────────────────────────────────────────────
PHẦN 7: GIỚI HẠN CỦA BENCHMARK (LIMITATIONS)
────────────────────────────────────────────────────────────────────────────────

Thừa nhận giới hạn không làm thesis yếu hơn — ngược lại, nó chứng tỏ
tác giả hiểu rõ phạm vi công trình của mình.

  Lab environment: Kết quả được đo trong môi trường kiểm soát, không
  phản ánh hoàn toàn điều kiện sản xuất thực tế với traffic đa dạng
  hơn và phần cứng khác nhau.

  Synthetic traffic: hping3 và script giả IP tạo ra traffic có pattern
  đơn giản và đều đặn hơn tấn công thực tế. Tấn công thực thường có
  packet size đa dạng và timing ngẫu nhiên hơn.

  Limited attacker diversity: Kịch bản chỉ test SYN Flood và GeoIP
  spoofing. Các loại tấn công khác (UDP Flood, HTTP Flood, Slowloris)
  không nằm trong phạm vi benchmark này.

  Namespace limitations: Khi chạy trên cùng một máy vật lý, các
  namespace chia sẻ CPU và RAM. Điều này có thể làm cho tác động của
  tấn công lên server bị phóng đại hoặc thu nhỏ so với môi trường
  multi-machine thực tế.

  GeoIP inaccuracy: Danh sách CIDR GeoIP không hoàn toàn chính xác
  và được cập nhật định kỳ. Một số IP có thể bị phân loại sai quốc gia.

  No WAN latency: Benchmark chạy trên mạng LAN hoặc localhost, không
  có latency của đường truyền Internet thực tế. RTT thực tế sẽ cao
  hơn đáng kể.


================================================================================
                     GHI CHÚ TRIỂN KHAI
================================================================================

Kịch bản này được thiết kế theo nguyên tắc "chạy ổn định kịch bản base
trước". Sau khi base scenario chạy ổn định và cho ra số liệu nhất quán
qua 3 lần chạy, các kịch bản mở rộng (nhiều attacker hơn, tăng số
CIDR rules, test với NIC khác,...) sẽ dựa vào cấu trúc 5 phase này
mà phát triển thêm mà không cần thiết kế lại từ đầu.

================================================================================
                              HẾT TÀI LIỆU — PHIÊN BẢN 2
================================================================================