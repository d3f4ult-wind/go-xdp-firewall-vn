import os
import json
import requests
import subprocess
import logging
import ipaddress
from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Khởi tạo MCP Server với tên "xdp-firewall-mcp"
mcp = FastMCP("xdp-firewall-mcp")

FIREWALL_API_URL = "http://localhost:8080"

VALID_PROTOS = {1: "ICMP", 6: "TCP", 17: "UDP"}

def _validate_rule(ip: str, proto: int, port: int) -> str | None:
    """Trả về thông báo lỗi nếu tham số không hợp lệ, None nếu OK."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return f"❌ IP không hợp lệ: {ip}"
    if proto not in VALID_PROTOS:
        return f"❌ proto={proto} không hợp lệ. Chỉ hỗ trợ: 1=ICMP, 6=TCP, 17=UDP."
    if proto in (6, 17) and port == 0:
        return f"❌ {VALID_PROTOS[proto]} yêu cầu chỉ định port (không được để 0)."
    return None

@mcp.tool()
def block_ip(ip: str, proto: int, port: int, reason: str = "") -> str:
    """Chặn một địa chỉ IP theo proto và port cụ thể (Admin rule).
    proto: 1=ICMP, 6=TCP, 17=UDP. KHÔNG hỗ trợ proto=0.
    port: Với ICMP luôn là 0. Với TCP/UDP phải chỉ định rõ (VD: 80, 443).
    Ví dụ đúng: block_ip("1.2.3.4", proto=6, port=80)
    Ví dụ sai: block_ip("1.2.3.4", proto=0, port=0)"""
    err = _validate_rule(ip, proto, port)
    if err: return err
    
    logging.info(f"Call block_ip: {ip}, proto={proto}, port={port}")
    payload = {"subnet": f"{ip}/32", "proto": proto, "port": port, "action": "DROP"}
    try:
        response = requests.post(f"{FIREWALL_API_URL}/rules", json=payload, timeout=30)
        if response.status_code == 201: return f"✅ Đã chặn IP {ip}. Lý do: {reason}"
        return f"❌ Lỗi: {response.text}"
    except Exception as e: return f"❌ Lỗi: {str(e)}"

@mcp.tool()
def unblock_ip(ip: str, proto: int, port: int) -> str:
    """Bỏ chặn IP. proto và port phải khớp chính xác với rule đã tạo.
    proto: 1=ICMP, 6=TCP, 17=UDP. KHÔNG hỗ trợ proto=0."""
    err = _validate_rule(ip, proto, port)
    if err: return err
    
    logging.info(f"Call unblock_ip: {ip}, proto={proto}, port={port}")
    payload = {"subnet": f"{ip}/32", "proto": proto, "port": port}
    try:
        response = requests.delete(f"{FIREWALL_API_URL}/rules", json=payload, timeout=30)
        if response.status_code == 200: return f"✅ Đã bỏ chặn IP {ip}."
        return f"❌ Lỗi: {response.text}"
    except Exception as e: return f"❌ Lỗi: {str(e)}"

@mcp.tool()
def check_firewall_health() -> str:
    """Kiểm tra tình trạng hoạt động (health) của Firewall (CPU, RAM, XDP)."""
    logging.info("Call check_firewall_health")
    try:
        response = requests.get(f"{FIREWALL_API_URL}/health", timeout=30)
        if response.status_code == 200:
            data = response.json()
            return f"Status: {data.get('status')}, XDP Attached: {data.get('xdp_attached')}, CPU: {data.get('cpu_percent')}%, RAM: {data.get('memory_mb')} MB"
        return f"Error: {response.text}"
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def list_active_rules() -> str:
    """Lấy danh sách các IP đang bị chặn (Admin rules)."""
    logging.info("Call list_active_rules")
    try:
        response = requests.get(f"{FIREWALL_API_URL}/rules", timeout=30)
        if response.status_code == 200:
            rules = response.json()
            if not rules: return "Không có luật nào đang áp dụng."
            return "\n".join([f"- {r.get('subnet')} | Hành động: {r.get('action')}" for r in rules])
        return "Lỗi lấy danh sách luật."
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def get_tier1_status() -> str:
    """Kiểm tra trạng thái Tier 1 (chống DoS rand-src): mức độ phòng thủ, tỷ lệ drop."""
    logging.info("Call get_tier1_status")
    try:
        stats = requests.get(f"{FIREWALL_API_URL}/tier1/stats", timeout=30).json()
        watcher = requests.get(f"{FIREWALL_API_URL}/tier1/watcher", timeout=30).json()
        return f"Mức độ phòng vệ (Level): {watcher.get('current_level')}, Auto mode: {watcher.get('auto_mode')}\nThống kê: {json.dumps(stats)}"
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def set_tier1_level(level: int, syn_drop: int = 0, udp_drop: int = 0, icmp_drop: int = 0) -> str:
    """Cập nhật mức độ phòng thủ Tier 1 và tỷ lệ rớt (drop rate 0-100%). Ví dụ: level=1, syn_drop=25, udp_drop=25, icmp_drop=25."""
    logging.info(f"Call set_tier1_level: level={level}")
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
        response = requests.post(f"{FIREWALL_API_URL}/tier1/mitigation", json=payload, timeout=30)
        if response.status_code == 200: return f"✅ Đã cập nhật cấu hình phòng thủ Tier 1 lên level {level}."
        return f"❌ Lỗi: {response.text}"
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def add_whitelist(ip: str) -> str:
    """Thêm một IP vào Whitelist (Tier 1 Trusted Map). IP này sẽ bypass kiểm tra Tier 1."""
    logging.info(f"Call add_whitelist: {ip}")
    try:
        response = requests.post(f"{FIREWALL_API_URL}/tier1/trusted", json={"ip": ip}, timeout=30)
        if response.status_code == 200: return f"✅ Đã thêm {ip} vào Whitelist."
        return f"❌ Lỗi: {response.text}"
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def remove_whitelist(ip: str) -> str:
    """Xóa một IP khỏi Whitelist."""
    logging.info(f"Call remove_whitelist: {ip}")
    try:
        response = requests.delete(f"{FIREWALL_API_URL}/tier1/trusted", json={"ip": ip}, timeout=30)
        if response.status_code == 200: return f"✅ Đã xóa {ip} khỏi Whitelist."
        return f"❌ Lỗi: {response.text}"
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def set_rate_limit(pps: int, time_window_ms: int) -> str:
    """Cài đặt giới hạn rate-limit (Tier 2). Ví dụ: pps=1000, time_window_ms=1000."""
    logging.info(f"Call set_rate_limit: {pps} pps")
    try:
        payload = {"pps": pps, "window_ms": time_window_ms}
        response = requests.post(f"{FIREWALL_API_URL}/ratelimit/config", json=payload, timeout=30)
        if response.status_code == 200: return f"✅ Đã cấu hình rate limit: {pps} pps / {time_window_ms} ms."
        return f"❌ Lỗi: {response.text}"
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def list_autoblocked_ips() -> str:
    """Liệt kê danh sách các IP đang bị block tự động (từ Suricata/Iptables)."""
    logging.info("Call list_autoblocked_ips")
    try:
        response = requests.get(f"{FIREWALL_API_URL}/autoblock/ips", timeout=30)
        if response.status_code == 200:
            ips = response.json()
            if not ips: return "Không có IP nào bị autoblock."
            return "\n".join([f"- {ip.get('ip')}/{ip.get('prefix_len')} (Thời điểm ban lúc: {ip.get('banned_at')})" for ip in ips])
        return "Lỗi lấy danh sách autoblock."
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def unban_autoblock_ip(ip: str) -> str:
    """Xóa IP khỏi danh sách autoblock (bỏ ban sớm)."""
    logging.info(f"Call unban_autoblock_ip: {ip}")
    try:
        response = requests.delete(f"{FIREWALL_API_URL}/autoblock/ips", json={"cidr": f"{ip}/32"}, timeout=30)
        if response.status_code == 200: return f"✅ Đã xóa {ip} khỏi danh sách autoblock."
        return f"❌ Lỗi: {response.text}"
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def toggle_watcher_automode(enabled: bool) -> str:
    """Bật/tắt chế độ tự động nâng mức phòng thủ của Tier 1 Watcher."""
    logging.info(f"Call toggle_watcher_automode: {enabled}")
    try:
        response = requests.post(f"{FIREWALL_API_URL}/tier1/watcher", json={"auto_mode": enabled}, timeout=30)
        if response.status_code == 200: return f"✅ Đã {'bật' if enabled else 'tắt'} auto mode cho Tier 1 Watcher."
        return f"❌ Lỗi: {response.text}"
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def run_iptables_block(ip: str) -> str:
    """Chặn IP ở tầng iptables song song với XDP (Yêu cầu quyền root)."""
    logging.info(f"Call run_iptables_block: {ip}")
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return f"❌ IP không hợp lệ: {ip}"
    try:
        res = subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True, text=True)
        if res.returncode == 0: return f"✅ Đã chặn {ip} ở tầng Iptables."
        return f"❌ Lỗi iptables: {res.stderr}"
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def list_iptables_rules() -> str:
    """Đọc danh sách các rule của Iptables."""
    logging.info("Call list_iptables_rules")
    try:
        res = subprocess.run(["iptables", "-L", "-n"], capture_output=True, text=True)
        return res.stdout if res.returncode == 0 else f"Lỗi: {res.stderr}"
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def reload_suricata_rules() -> str:
    """Gửi signal SIGUSR2 tới Suricata để reload rules mà không cần restart."""
    logging.info("Call reload_suricata_rules")
    try:
        res = subprocess.run(["pkill", "-USR2", "suricata"], capture_output=True, text=True)
        if res.returncode == 0: return "✅ Đã reload rules Suricata thành công."
        return f"❌ Lỗi (có thể suricata không chạy hoặc thiếu quyền root): {res.stderr}"
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def get_suricata_stats() -> str:
    """Đọc file /var/log/suricata/stats.log để báo cáo số lượng cảnh báo/giây."""
    logging.info("Call get_suricata_stats")
    log_path = "/var/log/suricata/stats.log"
    if not os.path.exists(log_path): return f"Không tìm thấy log tại {log_path}."
    try:
        with open(log_path, 'r') as f: lines = f.readlines()[-20:]
        return "\n".join(lines) if lines else "File rỗng."
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def read_suricata_logs(n: int = 50) -> str:
    """Đọc n cảnh báo gần nhất từ Suricata."""
    logging.info(f"Call read_suricata_logs: n={n}")
    log_path = "/var/log/suricata/eve.json"
    if not os.path.exists(log_path): return f"Không tìm thấy log tại {log_path}."
    try:
        with open(log_path, 'r') as f: lines = f.readlines()[-n:]
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
def read_iptables_logs(n: int = 50) -> str:
    """Đọc n dòng log iptables gần nhất."""
    logging.info(f"Call read_iptables_logs: n={n}")
    log_paths = ["/var/log/syslog", "/var/log/kern.log"]
    log_path = next((p for p in log_paths if os.path.exists(p)), None)
    if not log_path: return "Không tìm thấy syslog/kern.log."
    try:
        with open(log_path, 'r') as f: lines = f.readlines()[-n*4:]
        fw_logs = [l.strip() for l in lines if "FW-" in l or "DROP" in l or "iptables" in l.lower()]
        return "\n".join(fw_logs[-n:]) if fw_logs else "Không có log iptables."
    except Exception as e: return f"Lỗi: {str(e)}"

@mcp.tool()
def generate_security_report() -> str:
    """AI tự động tổng hợp báo cáo an ninh mạng (lấy health, tier1, iptables và suricata logs) và phân tích."""
    logging.info("Call generate_security_report")
    report = {}
    try: report["health"] = check_firewall_health()
    except Exception as e: report["health"] = f"Lỗi: {e}"
    
    try: report["tier1"] = get_tier1_status()
    except Exception as e: report["tier1"] = f"Lỗi: {e}"
    
    try: report["iptables_log_sample"] = read_iptables_logs(n=50)
    except Exception as e: report["iptables_log_sample"] = f"Lỗi: {e}"
    
    try: report["suricata_log_sample"] = read_suricata_logs(n=50)
    except Exception as e: report["suricata_log_sample"] = f"Lỗi: {e}"
    
    return json.dumps(report)

if __name__ == "__main__":
    mcp.run()
