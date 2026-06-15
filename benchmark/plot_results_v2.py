import pandas as pd
import matplotlib.pyplot as plt
import sys
import glob
import os
import argparse

def main():
    parser = argparse.ArgumentParser(description="Plot benchmark results (Hỗ trợ WRK V2)")
    parser.add_argument("res_dir", help="Directory containing CSV files")
    parser.add_argument("--separate", action="store_true", help="Save separate subplots as well as the combined chart")
    args = parser.parse_args()

    res_dir = args.res_dir
    separate = args.separate
    
    if not os.path.exists(res_dir):
        print(f"Lỗi: Không tìm thấy thư mục {res_dir}")
        sys.exit(1)

    # Tìm các file CSV trong thư mục
    fw_files  = glob.glob(os.path.join(res_dir, "metrics_firewall_*.csv"))
    leg_files = glob.glob(os.path.join(res_dir, "legit_*.csv"))
    wrk_files = glob.glob(os.path.join(res_dir, "wrk_*.csv"))
    evt_file  = os.path.join(res_dir, "timeline_events.csv")
    apache_files = glob.glob(os.path.join(res_dir, "apache_status_*.csv"))

    if not fw_files or not os.path.exists(evt_file):
        print("Lỗi: Không tìm thấy đủ file CSV (firewall, timeline) trong thư mục này.")
        sys.exit(1)

    print(f"[*] Đang đọc dữ liệu từ: {res_dir}")
    df_fw = pd.read_csv(fw_files[0])
    # Bỏ dòng đầu tiên vì script thu thập bị lỗi cộng dồn (cumulative) ở giây 0
    df_fw = df_fw.iloc[1:].reset_index(drop=True)
    
    # Hỗ trợ tương thích ngược với các file CSV cũ
    if 'iptables_drop_pps' not in df_fw.columns:
        df_fw['iptables_drop_pps'] = df_fw.get('iptables_drop_per_sec', 0)
    if 'iptables_accept_pps' not in df_fw.columns:
        df_fw['iptables_accept_pps'] = 0
    if 'iptables_drop_bps' not in df_fw.columns:
        df_fw['iptables_drop_bps'] = 0
    if 'iptables_accept_bps' not in df_fw.columns:
        df_fw['iptables_accept_bps'] = 0
        
    df_evt = pd.read_csv(evt_file)

    df_vic = None
    df_wrk = None
    df_apache = None
    is_wrk_v2 = False # [THAY ĐỔI CHO V2] Cờ đánh dấu nếu file wrk là của phiên bản V2
    if leg_files:
        df_vic = pd.read_csv(leg_files[0])
        print(f"[*] Legit Client log: {leg_files[0]}")
    else:
        print("[!] Không tìm thấy legit_*.csv — bỏ qua biểu đồ Availability.")
        
    if wrk_files:
        df_wrk = pd.read_csv(wrk_files[0])
        df_wrk = df_wrk.dropna()
        print(f"[*] WRK log: {wrk_files[0]}")
        # [THAY ĐỔI CHO V2] Kiểm tra xem CSV có cột success_rate_pct không. Nếu có tức là sinh ra từ wrk_monitor_v2.sh
        if 'success_rate_pct' in df_wrk.columns:
            is_wrk_v2 = True
            print("[*] Phát hiện dữ liệu WRK V2. Sẽ vẽ thêm biểu đồ Success Rate & Errors.")
    else:
        print("[!] Không tìm thấy wrk_*.csv — bỏ qua biểu đồ Throughput.")

    if apache_files:
        df_apache = pd.read_csv(apache_files[0])
        print(f"[*] Apache log: {apache_files[0]}")
    else:
        print("[!] Không tìm thấy apache_status_*.csv — bỏ qua biểu đồ Apache.")

    # Lấy mốc thời gian nhỏ nhất làm giây số 0
    start_time = df_fw['timestamp_unix_ms'].min()
    if df_vic is not None:
        start_time = min(start_time, df_vic['timestamp_unix_ms'].min())
    if df_wrk is not None:
        start_time = min(start_time, df_wrk['timestamp_unix_ms'].min())
    if df_apache is not None:
        start_time = min(start_time, df_apache['timestamp_unix_ms'].min())

    # Chuyển đổi ms sang giây tương đối
    df_fw['time_sec']  = (df_fw['timestamp_unix_ms']  - start_time) / 1000.0
    df_evt['time_sec'] = (df_evt['timestamp_unix_ms'] - start_time) / 1000.0
    if df_vic is not None:
        df_vic['time_sec'] = (df_vic['timestamp_unix_ms'] - start_time) / 1000.0
    if df_wrk is not None:
        df_wrk['time_sec'] = (df_wrk['timestamp_unix_ms'] - start_time) / 1000.0
    if df_apache is not None:
        df_apache['time_sec'] = (df_apache['timestamp_unix_ms'] - start_time) / 1000.0

    # [THAY ĐỔI CHO V2] Ở V2 ta có thêm 1 biểu đồ thứ 8 dành riêng cho Tỉ lệ thành công (Success Rate).
    wrk_subplots = 0
    if df_wrk is not None:
        wrk_subplots = 2 if is_wrk_v2 else 1
        
    apache_subplots = 1 if df_apache is not None else 0

    num_subplots = 5 + (1 if df_vic is not None else 0) + wrk_subplots + apache_subplots
    fig = plt.figure(figsize=(16, 4 * num_subplots))
    plt.rcParams.update({'font.size': 10})
    subplot_idx = [0]
    
    def plot_events(ax):
        for _, row in df_evt.iterrows():
            ax.axvline(x=row['time_sec'], color='grey', linestyle='--', alpha=0.4)

    # Dictionary lưu hàm vẽ cho tuỳ chọn separate
    plot_funcs = {}

    # ==========================================
    # BIỂU ĐỒ 1: Tải trọng CPU
    # ==========================================
    def draw_cpu(ax, title_prefix="1."):
        ax.plot(df_fw['time_sec'], df_fw['cpu_all'], label='Firewall CPU %', color='blue', linewidth=2)
        ax.set_title(f'{title_prefix} Tải trọng CPU (Firewall CPU Usage)', fontsize=14, fontweight='bold')
        ax.set_ylabel('CPU Usage (%)')
        ax.set_ylim(-5, 105)
        ax.legend(loc='upper right')
        ax.grid(True, linestyle='--', alpha=0.7)
        for _, row in df_evt.iterrows():
            ax.axvline(x=row['time_sec'], color='green', linestyle='--', alpha=0.8)
            if title_prefix: 
                ax.text(row['time_sec'] + 0.5, 90, row['event_name'], rotation=90, va='top', color='darkgreen', fontweight='bold')
            else:
                ax.text(row['time_sec'] + 0.5, 90, row['event_name'], rotation=90, va='top', color='darkgreen', fontweight='bold')
            
    plot_funcs['cpu'] = draw_cpu
    subplot_idx[0] += 1
    ax1 = plt.subplot(num_subplots, 1, subplot_idx[0])
    draw_cpu(ax1)

    # ==========================================
    # BIỂU ĐỒ 2: Áp lực xử lý ngắt (IRQ & SoftIRQ)
    # ==========================================
    def draw_irq(ax, title_prefix="2."):
        ax.plot(df_fw['time_sec'], df_fw['nic_ext_irq_per_sec'], label='Hardware IRQ/s', color='red', linewidth=2)
        ax.plot(df_fw['time_sec'], df_fw['softirq_net_rx_per_sec'], label='SoftIRQ NET_RX/s', color='orange', linewidth=2)
        ax.set_title(f'{title_prefix} Áp lực xử lý ngắt (Interrupts / SoftIRQs)', fontsize=14, fontweight='bold')
        ax.set_ylabel('IRQ per sec')
        ax.legend(loc='upper right')
        ax.grid(True, linestyle='--', alpha=0.7)
        plot_events(ax)
        
    plot_funcs['irq'] = draw_irq
    subplot_idx[0] += 1
    ax2 = plt.subplot(num_subplots, 1, subplot_idx[0], sharex=ax1)
    draw_irq(ax2)

    # ==========================================
    # BIỂU ĐỒ 3: Tiêu thụ bộ nhớ RAM
    # ==========================================
    def draw_mem(ax, title_prefix="3."):
        ax.plot(df_fw['time_sec'], df_fw['mem_used_mb'], label='Memory Used (MB)', color='purple', linewidth=2)
        ax.set_title(f'{title_prefix} Mức tiêu thụ bộ nhớ RAM', fontsize=14, fontweight='bold')
        ax.set_ylabel('Memory (MB)')
        ax.legend(loc='upper right')
        ax.grid(True, linestyle='--', alpha=0.7)
        plot_events(ax)
        
    plot_funcs['mem'] = draw_mem
    subplot_idx[0] += 1
    ax3 = plt.subplot(num_subplots, 1, subplot_idx[0], sharex=ax1)
    draw_mem(ax3)

    # ==========================================
    # BIỂU ĐỒ 4: Năng lực xử lý gói tin (PPS)
    # ==========================================
    def draw_pps(ax, title_prefix="4."):
        ax.plot(df_fw['time_sec'], df_fw['ext_rx_pps'], label='Total RX PPS (Gói tin vào)', color='black', alpha=0.5, linestyle=':')
        ax.plot(df_fw['time_sec'], df_fw['xdp_run_pps'], label='XDP Run PPS', color='orange', linewidth=1.5)
        ax.plot(df_fw['time_sec'], df_fw['xdp_drop_pps'], label='XDP Drop PPS (Đã chặn ở eBPF)', color='green', linewidth=2)
        ax.plot(df_fw['time_sec'], df_fw['iptables_drop_pps'], label='Iptables Drop PPS', color='red', linewidth=2)
        ax.plot(df_fw['time_sec'], df_fw['iptables_accept_pps'], label='Iptables Accept PPS', color='blue', linewidth=1.5, linestyle='--')
        ax.set_title(f'{title_prefix} Năng lực đánh chặn (Packet Processing & Drops)', fontsize=14, fontweight='bold')
        ax.set_ylabel('Packets per second (PPS)')
        ax.legend(loc='upper right')
        ax.grid(True, linestyle='--', alpha=0.7)
        plot_events(ax)
        
    plot_funcs['pps'] = draw_pps
    subplot_idx[0] += 1
    ax4 = plt.subplot(num_subplots, 1, subplot_idx[0], sharex=ax1)
    draw_pps(ax4)

    # ==========================================
    # BIỂU ĐỒ 5: Trạng thái Conntrack
    # ==========================================
    def draw_conntrack(ax, title_prefix="5."):
        ax.plot(df_fw['time_sec'], df_fw['conntrack_count'], label='Total Conntrack Entries', color='purple', linewidth=2)
        ax.plot(df_fw['time_sec'], df_fw['conntrack_syn_sent'], label='SYN_SENT (Half-open)', color='magenta', linestyle='--')
        ax.set_title(f'{title_prefix} Quá tải bảng trạng thái (Conntrack Table Size)', fontsize=14, fontweight='bold')
        ax.set_ylabel('Số lượng kết nối')
        ax.legend(loc='upper right')
        ax.grid(True, linestyle='--', alpha=0.7)
        plot_events(ax)
        
    plot_funcs['conntrack'] = draw_conntrack
    subplot_idx[0] += 1
    ax5 = plt.subplot(num_subplots, 1, subplot_idx[0], sharex=ax1)
    draw_conntrack(ax5)

    # ==========================================
    # BIỂU ĐỒ 6: Victim Response Time
    # ==========================================
    if df_vic is not None:
        def draw_vic(ax, title_prefix=None):
            if title_prefix is None: title_prefix = f"{subplot_idx[0]}."
            ax.plot(df_vic['time_sec'], df_vic['response_time_ms'],
                     label='Response Time (ms) — 1 req/200ms', color='teal', linewidth=1.5, alpha=0.8)
            unavail = df_vic[df_vic['available'] == 0]
            if not unavail.empty:
                ax.scatter(unavail['time_sec'], unavail['response_time_ms'],
                            color='red', s=20, label='Timeout / Lỗi (available=0)', zorder=5)
            ax.axhline(y=3000, color='red', linestyle=':', alpha=0.6, label='Timeout threshold (3000ms)')
            ax.set_title(f'{title_prefix} Availability của Legit Client (legit_client.py — Sequential Requests)', fontsize=14, fontweight='bold')
            ax.set_ylabel('Response Time (ms)')
            ax.set_ylim(-100, 3500)
            ax.legend(loc='upper right')
            ax.grid(True, linestyle='--', alpha=0.7)
            plot_events(ax)
            
        plot_funcs['vic'] = draw_vic
        subplot_idx[0] += 1
        ax6 = plt.subplot(num_subplots, 1, subplot_idx[0], sharex=ax1)
        draw_vic(ax6, f"{subplot_idx[0]}.")

    # ==========================================
    # BIỂU ĐỒ 7: WRK Throughput
    # ==========================================
    if df_wrk is not None:
        def draw_wrk(ax, title_prefix=None):
            if title_prefix is None: title_prefix = f"{subplot_idx[0]}."
            color_req = 'darkgreen'
            ax.plot(df_wrk['time_sec'], pd.to_numeric(df_wrk['req_per_sec'], errors='coerce').fillna(0),
                     label='Throughput (Req/s)', color=color_req, linewidth=2)
            ax.set_ylabel('Requests / second', color=color_req)
            ax.tick_params(axis='y', labelcolor=color_req)

            axb = ax.twinx()
            axb.plot(df_wrk['time_sec'], pd.to_numeric(df_wrk['p99_latency_ms'], errors='coerce').fillna(0),
                      label='P99 Latency (ms)', color='darkorange', linewidth=1.5, linestyle='--')
            axb.set_ylabel('P99 Latency (ms)', color='darkorange')
            axb.tick_params(axis='y', labelcolor='darkorange')

            # [THAY ĐỔI CHO V2] Cập nhật Text cho chuẩn với tải thực tế của V2
            title_text = 'Throughput của Legit Client (WRK V2 — 4 threads, 10 conns)' if is_wrk_v2 else 'Throughput của Legit Client (WRK V1)'
            ax.set_title(f'{title_prefix} {title_text}', fontsize=14, fontweight='bold')
            ax.grid(True, linestyle='--', alpha=0.7)

            lines1, labels1 = ax.get_legend_handles_labels()
            lines2, labels2 = axb.get_legend_handles_labels()
            ax.legend(lines1 + lines2, labels1 + labels2, loc='upper right')
            plot_events(ax)
                
        plot_funcs['wrk'] = draw_wrk
        subplot_idx[0] += 1
        ax7 = plt.subplot(num_subplots, 1, subplot_idx[0], sharex=ax1)
        draw_wrk(ax7, f"{subplot_idx[0]}.")

        # ==========================================
        # BIỂU ĐỒ 8: WRK V2 Success Rate & Errors 
        # ==========================================
        # [THAY ĐỔI CHO V2] Biểu đồ hoàn toàn mới, bóc tách lỗi và vẽ Tỉ lệ thành công 
        # Rất quan trọng để chứng minh "khi bị tấn công, server không phản hồi lỗi Timeout hay là lỗi Connect?"
        if is_wrk_v2:
            def draw_wrk_v2_errors(ax, title_prefix=None):
                if title_prefix is None: title_prefix = f"{subplot_idx[0]}."
                color_succ = 'blue'
                ax.plot(df_wrk['time_sec'], pd.to_numeric(df_wrk['success_rate_pct'], errors='coerce').fillna(0),
                         label='Success Rate (%)', color=color_succ, linewidth=2, linestyle='-')
                ax.set_ylabel('Success Rate (%)', color=color_succ)
                ax.tick_params(axis='y', labelcolor=color_succ)
                ax.set_ylim(-5, 105)

                # Dùng trục Y phụ (twinx) để vẽ số đếm lỗi bằng biểu đồ dạng cột (stacked bar)
                axb = ax.twinx()
                width = 1.5 # Độ rộng cột bar
                
                conn_err = pd.to_numeric(df_wrk['connect_err'], errors='coerce').fillna(0)
                to_err = pd.to_numeric(df_wrk['timeout_err'], errors='coerce').fillna(0)
                rw_err = pd.to_numeric(df_wrk['read_write_err'], errors='coerce').fillna(0)
                
                # Stack các lỗi lên nhau: Connect -> Timeout -> Read/Write
                p1 = axb.bar(df_wrk['time_sec'], conn_err, width, label='Connect Errors', color='red', alpha=0.5)
                p2 = axb.bar(df_wrk['time_sec'], to_err, width, bottom=conn_err, label='Timeout Errors', color='orange', alpha=0.5)
                p3 = axb.bar(df_wrk['time_sec'], rw_err, width, bottom=conn_err + to_err, label='Read/Write Errors', color='purple', alpha=0.5)
                
                axb.set_ylabel('Total Errors Count', color='red')
                axb.tick_params(axis='y', labelcolor='red')

                ax.set_title(f'{title_prefix} Phân tích Lỗi và Tỉ lệ Thành Công (WRK V2)', fontsize=14, fontweight='bold')
                ax.grid(True, linestyle='--', alpha=0.7)

                # Gom chú thích của cả 2 trục
                lines1, labels1 = ax.get_legend_handles_labels()
                # Đối với BarContainer (kết quả của axb.bar), nó không hỗ trợ trực tiếp trong get_legend_handles_labels dễ dàng,
                # ta gọi thủ công các patch
                handles = [p1, p2, p3]
                labels = ['Connect Errors', 'Timeout Errors', 'Read/Write Errors']
                ax.legend(lines1 + handles, labels1 + labels, loc='center left')
                
                plot_events(ax)

            plot_funcs['wrk_v2_errors'] = draw_wrk_v2_errors
            subplot_idx[0] += 1
            ax8 = plt.subplot(num_subplots, 1, subplot_idx[0], sharex=ax1)
            draw_wrk_v2_errors(ax8)

    # ==========================================
    # BIỂU ĐỒ: Apache Status
    # ==========================================
    if df_apache is not None:
        def draw_apache(ax, title_prefix=None):
            if title_prefix is None: title_prefix = f"{subplot_idx[0]}."
            ax.plot(df_apache['time_sec'], pd.to_numeric(df_apache['active_workers'], errors='coerce').fillna(0), label='Active Workers', color='red', linewidth=2)
            ax.plot(df_apache['time_sec'], pd.to_numeric(df_apache['idle_workers'], errors='coerce').fillna(0), label='Idle Workers', color='green', linewidth=2, linestyle='--')
            ax.set_title(f'{title_prefix} Trạng thái Apache (Active/Idle Workers)', fontsize=14, fontweight='bold')
            ax.set_ylabel('Workers Count')
            ax.grid(True, linestyle='--', alpha=0.7)

            if 'requests_per_sec' in df_apache.columns:
                axb = ax.twinx()
                axb.plot(df_apache['time_sec'], pd.to_numeric(df_apache['requests_per_sec'], errors='coerce').fillna(0), label='Requests/s', color='blue', alpha=0.5)
                axb.set_ylabel('Req/s', color='blue')
                lines1, labels1 = ax.get_legend_handles_labels()
                lines2, labels2 = axb.get_legend_handles_labels()
                ax.legend(lines1 + lines2, labels1 + labels2, loc='upper left')
            else:
                ax.legend(loc='upper left')

            plot_events(ax)
            
        plot_funcs['apache'] = draw_apache
        subplot_idx[0] += 1
        ax_apache = plt.subplot(num_subplots, 1, subplot_idx[0], sharex=ax1)
        draw_apache(ax_apache)

    # Đặt xlabel cho subplot cuối cùng
    plt.xlabel('Thời gian thử nghiệm (Giây)', fontsize=12)

    # Lưu biểu đồ tổng quát
    plt.tight_layout()
    out_img = os.path.join(res_dir, "benchmark_charts_v2.png")
    fig.savefig(out_img, dpi=300, bbox_inches='tight')
    print(f"[OK] Đã vẽ xong biểu đồ tổng quát: {out_img}")
    plt.close(fig)

    # ==========================================
    # Lưu các biểu đồ con tách rời nếu có tuỳ chọn --separate
    # ==========================================
    if separate:
        print("[*] Đang vẽ các biểu đồ con tách rời...")
        for name, func in plot_funcs.items():
            fig_sep = plt.figure(figsize=(12, 5))
            ax_sep = fig_sep.add_subplot(1, 1, 1)
            # Truyền prefix rỗng để ẩn số "1.", "2." trong tiêu đề biểu đồ con
            func(ax_sep, title_prefix="") 
            ax_sep.set_xlabel('Thời gian thử nghiệm (Giây)', fontsize=12)
            plt.tight_layout()
            out_sep = os.path.join(res_dir, f"chart_{name}.png")
            fig_sep.savefig(out_sep, dpi=300, bbox_inches='tight')
            plt.close(fig_sep)
            print(f"  -> Lưu: {out_sep}")

if __name__ == "__main__":
    main()
