import pandas as pd
import matplotlib.pyplot as plt
import sys
import glob
import os

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 plot_results.py <thu_muc_results>")
        print("Ví dụ: python3 plot_results.py firewall/results_sc1_botnet_20260605_163101")
        sys.exit(1)

    res_dir = sys.argv[1]
    
    if not os.path.exists(res_dir):
        print(f"Lỗi: Không tìm thấy thư mục {res_dir}")
        sys.exit(1)

    # Tìm các file CSV trong thư mục
    fw_files  = glob.glob(os.path.join(res_dir, "metrics_firewall_*.csv"))
    leg_files = glob.glob(os.path.join(res_dir, "legit_*.csv"))
    wrk_files = glob.glob(os.path.join(res_dir, "wrk_*.csv"))
    evt_file  = os.path.join(res_dir, "timeline_events.csv")

    if not fw_files or not os.path.exists(evt_file):
        print("Lỗi: Không tìm thấy đủ file CSV (firewall, timeline) trong thư mục này.")
        sys.exit(1)

    print(f"[*] Đang đọc dữ liệu từ: {res_dir}")
    df_fw = pd.read_csv(fw_files[0])
    df_evt = pd.read_csv(evt_file)

    df_vic = None
    df_wrk = None
    if leg_files:
        df_vic = pd.read_csv(leg_files[0])
        print(f"[*] Legit Client log: {leg_files[0]}")
    else:
        print("[!] Không tìm thấy legit_*.csv — bỏ qua biểu đồ Availability.")
    if wrk_files:
        df_wrk = pd.read_csv(wrk_files[0])
        df_wrk = df_wrk.dropna()
        print(f"[*] WRK log: {wrk_files[0]}")
    else:
        print("[!] Không tìm thấy wrk_*.csv — bỏ qua biểu đồ Throughput.")

    # Lấy mốc thời gian nhỏ nhất làm giây số 0
    start_time = df_fw['timestamp_unix_ms'].min()
    if df_vic is not None:
        start_time = min(start_time, df_vic['timestamp_unix_ms'].min())
    if df_wrk is not None:
        start_time = min(start_time, df_wrk['timestamp_unix_ms'].min())

    # Chuyển đổi ms sang giây tương đối
    df_fw['time_sec']  = (df_fw['timestamp_unix_ms']  - start_time) / 1000.0
    df_evt['time_sec'] = (df_evt['timestamp_unix_ms'] - start_time) / 1000.0
    if df_vic is not None:
        df_vic['time_sec'] = (df_vic['timestamp_unix_ms'] - start_time) / 1000.0
    if df_wrk is not None:
        df_wrk['time_sec'] = (df_wrk['timestamp_unix_ms'] - start_time) / 1000.0

    # Thiết lập kích thước bảng vẽ
    num_subplots = 3 + (1 if df_vic is not None else 0) + (1 if df_wrk is not None else 0)
    plt.figure(figsize=(16, 4 * num_subplots))
    plt.rcParams.update({'font.size': 10})
    subplot_idx = [0]  # mục đích đếm subplot hiện tại

    def next_subplot(sharex=None):
        subplot_idx[0] += 1
        if sharex:
            return plt.subplot(num_subplots, 1, subplot_idx[0], sharex=sharex)
        return plt.subplot(num_subplots, 1, subplot_idx[0])

    # ==========================================
    # BIỂU ĐỒ 1: Tải trọng CPU (Firewall vs Victim)
    # ==========================================
    ax1 = plt.subplot(num_subplots, 1, 1)
    plt.plot(df_fw['time_sec'], df_fw['cpu_all'], label='Firewall CPU %', color='blue', linewidth=2)
    plt.title('1. Tải trọng CPU (Firewall CPU Usage)', fontsize=14, fontweight='bold')
    plt.ylabel('CPU Usage (%)')
    plt.ylim(-5, 105)
    plt.legend(loc='upper right')
    plt.grid(True, linestyle='--', alpha=0.7)

    # Vẽ các đường mốc thời gian (Events)
    for _, row in df_evt.iterrows():
        plt.axvline(x=row['time_sec'], color='green', linestyle='--', alpha=0.8)
        plt.text(row['time_sec'] + 0.5, 90, row['event_name'], rotation=90, va='top', color='darkgreen', fontweight='bold')

    # ==========================================
    # BIỂU ĐỒ 2: Năng lực xử lý gói tin (Mitigation PPS)
    # ==========================================
    plt.subplot(num_subplots, 1, 2, sharex=ax1)
    plt.plot(df_fw['time_sec'], df_fw['ext_rx_pps'], label='Total RX PPS (Gói tin vào)', color='black', alpha=0.5, linestyle=':')
    plt.plot(df_fw['time_sec'], df_fw['xdp_run_pps'], label='XDP Run PPS', color='orange', linewidth=1.5)
    plt.plot(df_fw['time_sec'], df_fw['xdp_drop_pps'], label='XDP Drop PPS (Đã chặn ở eBPF)', color='green', linewidth=2)
    plt.plot(df_fw['time_sec'], df_fw['iptables_drop_per_sec'], label='Iptables Drop PPS', color='red', linewidth=2)
    plt.title('2. Năng lực đánh chặn (Packet Processing & Drops)', fontsize=14, fontweight='bold')
    plt.ylabel('Packets per second (PPS)')
    plt.legend(loc='upper right')
    plt.grid(True, linestyle='--', alpha=0.7)

    for _, row in df_evt.iterrows():
        plt.axvline(x=row['time_sec'], color='grey', linestyle='--', alpha=0.4)

    # ==========================================
    # BIỂU ĐỒ 3: Trạng thái Conntrack
    # ==========================================
    plt.subplot(num_subplots, 1, 3, sharex=ax1)
    plt.plot(df_fw['time_sec'], df_fw['conntrack_count'], label='Total Conntrack Entries', color='purple', linewidth=2)
    plt.plot(df_fw['time_sec'], df_fw['conntrack_syn_sent'], label='SYN_SENT (Half-open)', color='magenta', linestyle='--')
    plt.title('3. Quá tải bảng trạng thái (Conntrack Table Size)', fontsize=14, fontweight='bold')
    plt.ylabel('Số lượng kết nối')
    plt.legend(loc='upper right')
    plt.grid(True, linestyle='--', alpha=0.7)

    for _, row in df_evt.iterrows():
        plt.axvline(x=row['time_sec'], color='grey', linestyle='--', alpha=0.4)

    # ==========================================
    # BIỂU ĐỒ 4: Victim Response Time (Nếu có)
    # ==========================================
    if df_vic is not None:
        plt.subplot(num_subplots, 1, 4, sharex=ax1)
        plt.plot(df_vic['time_sec'], df_vic['response_time_ms'],
                 label='Response Time (ms) — 1 req/200ms', color='teal', linewidth=1.5, alpha=0.8)
        unavail = df_vic[df_vic['available'] == 0]
        if not unavail.empty:
            plt.scatter(unavail['time_sec'], unavail['response_time_ms'],
                        color='red', s=20, label='Timeout / Lỗi (available=0)', zorder=5)
        plt.axhline(y=3000, color='red', linestyle=':', alpha=0.6, label='Timeout threshold (3000ms)')
        plt.title('4. Availability của Legit Client (legit_client.py — Sequential Requests)', fontsize=14, fontweight='bold')
        plt.ylabel('Response Time (ms)')
        plt.ylim(-100, 3500)
        plt.legend(loc='upper right')
        plt.grid(True, linestyle='--', alpha=0.7)
        for _, row in df_evt.iterrows():
            plt.axvline(x=row['time_sec'], color='grey', linestyle='--', alpha=0.4)

    # ==========================================
    # BIỂU ĐỒ 5: WRK Throughput (Concurrent Load từ Legit)
    # ==========================================
    if df_wrk is not None:
        subplot_num = 5 if df_vic is not None else 4
        ax5 = plt.subplot(num_subplots, 1, subplot_num, sharex=ax1)

        color_req = 'darkgreen'
        ax5.plot(df_wrk['time_sec'], pd.to_numeric(df_wrk['req_per_sec'], errors='coerce').fillna(0),
                 label='Throughput (Req/s)', color=color_req, linewidth=2)
        ax5.set_ylabel('Requests / second', color=color_req)
        ax5.tick_params(axis='y', labelcolor=color_req)

        # Trục Y phụ cho P99 Latency
        ax5b = ax5.twinx()
        ax5b.plot(df_wrk['time_sec'], pd.to_numeric(df_wrk['p99_latency_ms'], errors='coerce').fillna(0),
                  label='P99 Latency (ms)', color='darkorange', linewidth=1.5, linestyle='--')
        ax5b.set_ylabel('P99 Latency (ms)', color='darkorange')
        ax5b.tick_params(axis='y', labelcolor='darkorange')

        ax5.set_title('5. Throughput của Legit Client dưới tải (wrk — 2 threads, 10 conns)', fontsize=14, fontweight='bold')
        ax5.set_xlabel('Thời gian thử nghiệm (Giây)', fontsize=12)
        ax5.grid(True, linestyle='--', alpha=0.7)

        lines1, labels1 = ax5.get_legend_handles_labels()
        lines2, labels2 = ax5b.get_legend_handles_labels()
        ax5.legend(lines1 + lines2, labels1 + labels2, loc='upper right')

        for _, row in df_evt.iterrows():
            ax5.axvline(x=row['time_sec'], color='grey', linestyle='--', alpha=0.4)
    elif df_vic is None:
        # Không có cả legit lẫn wrk — thêm xlabel cho subplot 3
        plt.subplot(num_subplots, 1, 3)
        plt.xlabel('Thời gian thử nghiệm (Giây)', fontsize=12)

    # Lưu biểu đồ
    plt.tight_layout()
    out_img = os.path.join(res_dir, "benchmark_charts.png")
    plt.savefig(out_img, dpi=300, bbox_inches='tight')
    print(f"[OK] Đã vẽ xong biểu đồ! Xem tại: {out_img}")


if __name__ == "__main__":
    main()
