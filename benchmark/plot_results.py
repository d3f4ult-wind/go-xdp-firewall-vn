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
    fw_files = glob.glob(os.path.join(res_dir, "metrics_firewall_*.csv"))
    vic_files = glob.glob(os.path.join(res_dir, "log_victim_*.csv"))
    evt_file = os.path.join(res_dir, "timeline_events.csv")

    if not fw_files or not vic_files or not os.path.exists(evt_file):
        print("Lỗi: Không tìm thấy đủ 3 file CSV (firewall, victim, timeline) trong thư mục này.")
        sys.exit(1)

    print(f"[*] Đang đọc dữ liệu từ: {res_dir}")
    df_fw = pd.read_csv(fw_files[0])
    df_vic = pd.read_csv(vic_files[0])
    df_evt = pd.read_csv(evt_file)

    # Lấy mốc thời gian nhỏ nhất làm giây số 0
    start_time = min(df_fw['timestamp_unix_ms'].min(), df_vic['timestamp_unix_ms'].min())
    
    # Chuyển đổi ms sang giây tương đối (Relative seconds)
    df_fw['time_sec'] = (df_fw['timestamp_unix_ms'] - start_time) / 1000.0
    df_vic['time_sec'] = (df_vic['timestamp_unix_ms'] - start_time) / 1000.0
    df_evt['time_sec'] = (df_evt['timestamp_unix_ms'] - start_time) / 1000.0

    # Thiết lập kích thước bảng vẽ
    plt.figure(figsize=(16, 12))
    plt.rcParams.update({'font.size': 10})

    # ==========================================
    # BIỂU ĐỒ 1: Tải trọng CPU (Firewall vs Victim)
    # ==========================================
    ax1 = plt.subplot(3, 1, 1)
    plt.plot(df_fw['time_sec'], df_fw['cpu_all'], label='Firewall CPU %', color='blue', linewidth=2)
    plt.plot(df_vic['time_sec'], df_vic['cpu_usage'], label='Victim CPU %', color='red', linewidth=2)
    plt.title('1. Tải trọng CPU (CPU Usage Comparison)', fontsize=14, fontweight='bold')
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
    plt.subplot(3, 1, 2, sharex=ax1)
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
    plt.subplot(3, 1, 3, sharex=ax1)
    plt.plot(df_fw['time_sec'], df_fw['conntrack_count'], label='Total Conntrack Entries', color='purple', linewidth=2)
    plt.plot(df_fw['time_sec'], df_fw['conntrack_syn_sent'], label='SYN_SENT (Half-open)', color='magenta', linestyle='--')
    plt.title('3. Quá tải bảng trạng thái (Conntrack Table Size)', fontsize=14, fontweight='bold')
    plt.xlabel('Thời gian thử nghiệm (Giây)', fontsize=12)
    plt.ylabel('Số lượng kết nối')
    plt.legend(loc='upper right')
    plt.grid(True, linestyle='--', alpha=0.7)

    for _, row in df_evt.iterrows():
        plt.axvline(x=row['time_sec'], color='grey', linestyle='--', alpha=0.4)

    # Lưu biểu đồ
    plt.tight_layout()
    out_img = os.path.join(res_dir, "benchmark_charts.png")
    plt.savefig(out_img, dpi=300, bbox_inches='tight')
    print(f"[OK] Đã vẽ xong biểu đồ cực nét! Xem tại: {out_img}")

if __name__ == "__main__":
    main()
