import os
import json
import requests
import subprocess
from mcp.server.fastmcp import FastMCP

# Khởi tạo MCP Server với tên "xdp-firewall-mcp"
mcp = FastMCP("xdp-firewall-mcp")

FIREWALL_API_URL = "http://localhost:8080"

@mcp.tool()
def block_ip(ip: str, reason: str = "") -> str:
    """Chặn một địa chỉ IP (Admin rule)."""
    payload = {"subnet": f"{ip}/32", "proto": 0, "port": 0, "action": "DROP"}
    try:
        response = requests.post(f"{FIREWALL_API_URL}/rules", json=payload)
        if response.status_code == 201: return f"✅ Đã chặn IP {ip}. Lý do: {reason}"
        return f"❌ Lỗi: {response.text}"
    except Exception as e: return f"❌ Lỗi: {str(e)}"

@mcp.tool()
def unblock_ip(ip: str) -> str:
    """Bỏ chặn một địa chỉ IP đã bị chặn bởi Admin."""
    payload = {"subnet": f"{ip}/32", "proto": 0, "port": 0}
    try:
        response = requests.delete(f"{FIREWALL_API_URL}/rules", json=payload)
        if response.status_code == 200: return f"✅ Đã bỏ chặn IP {ip}."
        return f"❌ Lỗi: {response.text}"
    except Exception as e: return f"❌ Lỗi: {str(e)}"

@mcp.tool()
def check_firewall_health() -> str:
    """Kiểm tra tình trạng hoạt động (health) của Firewall (CPU, RAM, XDP)."""
    try:
        response = requests.get(f"{FIREWALL_API_URL}/health")
        if response.status_code == 200:
            data = response.json()
            return f"Status: {data.get('status')}, XDP Attached: {data.get('xdp_attached')}, CPU: {data.get('cpu_percent')}%, RAM: {data.get('memory_mb')} MB"
        return f"Error: {response.text}"
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def list_active_rules() -> str:
    """Lấy danh sách các IP đang bị chặn (Admin rules)."""
    try:
        response = requests.get(f"{FIREWALL_API_URL}/rules")
        if response.status_code == 200:
            rules = response.json()
            if not rules: return "Không có luật nào đang áp dụng."
            return "\n".join([f"- {r.get('subnet')} | Hành động: {r.get('action')}" for r in rules])
        return "Lỗi lấy danh sách luật."
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def get_tier1_status() -> str:
    """Kiểm tra trạng thái Tier 1 (chống DoS rand-src): mức độ phòng thủ, tỷ lệ drop."""
    try:
        stats = requests.get(f"{FIREWALL_API_URL}/tier1/stats").json()
        watcher = requests.get(f"{FIREWALL_API_URL}/tier1/watcher").json()
        return f"Mức độ phòng vệ (Level): {watcher.get('current_level')}, Auto mode: {watcher.get('auto_mode')}\nThống kê: {json.dumps(stats)}"
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def set_tier1_level(level: int, syn_drop: int = 0, udp_drop: int = 0, icmp_drop: int = 0) -> str:
    """Cập nhật mức độ phòng thủ Tier 1 và tỷ lệ rớt (drop rate 0-100%). Ví dụ: level=1, syn_drop=25, udp_drop=25, icmp_drop=25."""
    try:
        payload = {
            "level": level,
            "syn_drop": syn_drop,
            "udp_drop": udp_drop,
            "icmp_drop": icmp_drop,
            "geo_syn_drop": syn_drop // 5 if syn_drop > 0 else 0,
            "geo_udp_drop": udp_drop // 5 if udp_drop > 0 else 0,
            "geo_icmp_drop": icmp_drop // 5 if icmp_drop > 0 else 0,
        }
        response = requests.post(f"{FIREWALL_API_URL}/tier1/mitigation", json=payload)
        if response.status_code == 200: return f"✅ Đã cập nhật cấu hình phòng thủ Tier 1 lên level {level}."
        return f"❌ Lỗi: {response.text}"
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def add_whitelist(ip: str) -> str:
    """Thêm một IP vào Whitelist (Tier 1 Trusted Map). IP này sẽ bypass kiểm tra Tier 1."""
    try:
        response = requests.post(f"{FIREWALL_API_URL}/tier1/trusted", json={"ip": ip})
        if response.status_code == 200: return f"✅ Đã thêm {ip} vào Whitelist."
        return f"❌ Lỗi: {response.text}"
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def remove_whitelist(ip: str) -> str:
    """Xóa một IP khỏi Whitelist."""
    try:
        response = requests.delete(f"{FIREWALL_API_URL}/tier1/trusted", json={"ip": ip})
        if response.status_code == 200: return f"✅ Đã xóa {ip} khỏi Whitelist."
        return f"❌ Lỗi: {response.text}"
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def set_rate_limit(pps: int, time_window_ms: int) -> str:
    """Cài đặt giới hạn rate-limit (Tier 2). Ví dụ: pps=1000, time_window_ms=1000."""
    try:
        payload = {"pps": pps, "window_ms": time_window_ms}
        response = requests.post(f"{FIREWALL_API_URL}/ratelimit/config", json=payload)
        if response.status_code == 200: return f"✅ Đã cấu hình rate limit: {pps} pps / {time_window_ms} ms."
        return f"❌ Lỗi: {response.text}"
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def list_autoblocked_ips() -> str:
    """Liệt kê danh sách các IP đang bị block tự động (từ Suricata/Iptables)."""
    try:
        response = requests.get(f"{FIREWALL_API_URL}/autoblock/ips")
        if response.status_code == 200:
            ips = response.json()
            if not ips: return "Không có IP nào bị autoblock."
            return "\n".join([f"- {ip.get('ip')}/{ip.get('prefix_len')} (Hết hạn lúc: {ip.get('banned_at')})" for ip in ips])
        return "Lỗi lấy danh sách autoblock."
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def unban_autoblock_ip(ip: str) -> str:
    """Xóa IP khỏi danh sách autoblock (bỏ ban sớm)."""
    try:
        response = requests.delete(f"{FIREWALL_API_URL}/autoblock/ips", json={"cidr": f"{ip}/32"})
        if response.status_code == 200: return f"✅ Đã xóa {ip} khỏi danh sách autoblock."
        return f"❌ Lỗi: {response.text}"
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def toggle_watcher_automode(enabled: bool) -> str:
    """Bật/tắt chế độ tự động nâng mức phòng thủ của Tier 1 Watcher."""
    try:
        response = requests.post(f"{FIREWALL_API_URL}/tier1/watcher", json={"auto_mode": enabled})
        if response.status_code == 200: return f"✅ Đã {'bật' if enabled else 'tắt'} auto mode cho Tier 1 Watcher."
        return f"❌ Lỗi: {response.text}"
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def run_iptables_block(ip: str) -> str:
    """Chặn IP ở tầng iptables song song với XDP (Yêu cầu quyền root)."""
    try:
        res = subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True, text=True)
        if res.returncode == 0: return f"✅ Đã chặn {ip} ở tầng Iptables."
        return f"❌ Lỗi iptables: {res.stderr}"
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def list_iptables_rules() -> str:
    """Đọc danh sách các rule của Iptables."""
    try:
        res = subprocess.run(["iptables", "-L", "-n"], capture_output=True, text=True)
        return res.stdout if res.returncode == 0 else f"Lỗi: {res.stderr}"
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def reload_suricata_rules() -> str:
    """Gửi signal SIGUSR2 tới Suricata để reload rules mà không cần restart."""
    try:
        res = subprocess.run(["pkill", "-USR2", "suricata"], capture_output=True, text=True)
        if res.returncode == 0: return "✅ Đã reload rules Suricata thành công."
        return f"❌ Lỗi (có thể suricata không chạy hoặc thiếu quyền root): {res.stderr}"
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def get_suricata_stats() -> str:
    """Đọc file /var/log/suricata/stats.log để báo cáo số lượng cảnh báo/giây."""
    log_path = "/var/log/suricata/stats.log"
    if not os.path.exists(log_path): return f"Không tìm thấy log tại {log_path}."
    try:
        with open(log_path, 'r') as f: lines = f.readlines()[-20:]
        return "\n".join(lines) if lines else "File rỗng."
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def read_suricata_logs() -> str:
    """Đọc 50 cảnh báo gần nhất từ Suricata."""
    log_path = "/var/log/suricata/eve.json"
    if not os.path.exists(log_path): return f"Không tìm thấy log tại {log_path}."
    try:
        with open(log_path, 'r') as f: lines = f.readlines()[-50:]
        alerts = []
        for line in lines:
            try:
                data = json.loads(line)
                if data.get('event_type') == 'alert':
                    alerts.append(f"{data.get('timestamp')} - {data.get('src_ip')} -> {data.get('dest_ip')}: {data.get('alert', {}).get('signature')}")
            except: pass
        return "\n".join(alerts) if alerts else "Không có cảnh báo tấn công."
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def read_iptables_logs() -> str:
    """Đọc 50 dòng log iptables gần nhất."""
    log_paths = ["/var/log/syslog", "/var/log/kern.log"]
    log_path = next((p for p in log_paths if os.path.exists(p)), None)
    if not log_path: return "Không tìm thấy syslog/kern.log."
    try:
        with open(log_path, 'r') as f: lines = f.readlines()[-200:]
        fw_logs = [l.strip() for l in lines if "FW-" in l or "DROP" in l or "iptables" in l.lower()]
        return "\n".join(fw_logs[-50:]) if fw_logs else "Không có log iptables."
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def generate_security_report() -> str:
    """AI tự động tổng hợp báo cáo an ninh mạng (lấy health, tier1, iptables và suricata logs) và phân tích."""
    return json.dumps({
        "health": check_firewall_health(),
        "tier1": get_tier1_status(),
        "iptables_log_sample": read_iptables_logs()[:500],
        "suricata_log_sample": read_suricata_logs()[:500]
    })

if __name__ == "__main__":
    mcp.run()
