"""
=================================================================================
FILE: mcp_server.py
MÔ TẢ: Máy chủ Model Context Protocol (MCP) cho XDP Firewall.
LUỒNG HOẠT ĐỘNG:
  1. Khởi tạo một FastMCP server.
  2. Định nghĩa các "Tool" (Công cụ) đại diện cho các tính năng của Firewall 
     (như chặn IP, xem thống kê, điều chỉnh WRED Tier 1, đọc log Iptables/Suricata).
  3. Khi AI (như Gemini/Claude) kết nối vào, nó có thể đọc mô tả của các Tool này (qua docstring)
     và tự động gọi chúng dựa trên yêu cầu bằng ngôn ngữ tự nhiên của người dùng.
TẠI SAO DÙNG MCP?
  - Cho phép quản trị viên vận hành Firewall thông qua Chatbot thay vì phải nhớ 
    lệnh CLI phức tạp hay click tay trên giao diện UI.
  - Hỗ trợ báo cáo an ninh tự động (AI tự đọc log, tự phân tích và báo cáo).
=================================================================================
"""

import os
import json
import requests
import subprocess
import logging
import ipaddress
from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Khởi tạo MCP Server với tên "xdp-firewall-mcp"
# Đối tượng này sẽ tự động expose các hàm được bọc bởi @mcp.tool()
mcp = FastMCP("xdp-firewall-mcp")

# Địa chỉ của Go Controller (REST API nội bộ)
FIREWALL_API_URL = "http://localhost:8080"

# Từ điển chuẩn hóa giao thức L4
VALID_PROTOS = {1: "ICMP", 6: "TCP", 17: "UDP"}

# -------------------------------------------------------------------------
# --- HÀM TIỆN ÍCH (HELPER) ---
# -------------------------------------------------------------------------

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

# -------------------------------------------------------------------------
# --- CÁC CÔNG CỤ (TOOLS) CHO AI ĐIỀU KHIỂN TIER 2 & CƠ BẢN ---
# Chú ý: Các chuỗi docstring ("""...""") bên trong hàm là cực kỳ quan trọng. 
# AI Agent sẽ đọc các chuỗi này để hiểu chức năng của hàm và cách truyền tham số!
# -------------------------------------------------------------------------

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

# -------------------------------------------------------------------------
# --- CÁC CÔNG CỤ CHO AI ĐIỀU KHIỂN TIER 1 (CHỐNG DOS) ---
# Cho phép AI đọc chỉ số PPS và linh hoạt thay đổi Level phòng thủ.
# -------------------------------------------------------------------------

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

# -------------------------------------------------------------------------
# --- CÁC CÔNG CỤ GIAO TIẾP VỚI HỆ THỐNG NGOÀI (IPTABLES/SURICATA) ---
# Cho phép AI gọi lệnh hệ thống (subprocess) hoặc đọc file log trực tiếp.
# -------------------------------------------------------------------------

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

# -------------------------------------------------------------------------
# --- CÔNG CỤ TỰ ĐỘNG HÓA SOC (BÁO CÁO AN NINH) ---
# -------------------------------------------------------------------------

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

# -------------------------------------------------------------------------
# --- WHITELIST MANAGEMENT TOOLS (Tier 1 XDP + Tier 2 Iptables) ---
#
# Trả lời câu hỏi thầy phản biện:
#   "Nếu firewall khởi động trạng thái trống (không có rule nào),
#    làm sao hệ thống nhận diện đâu là whitelist, đâu là blacklist?"
#
# Câu trả lời: Admin hoặc AI (MCP) CHỦ ĐỘNG thêm IP hợp lệ vào whitelist
# TRƯỚC khi tấn công xảy ra. Hệ thống có 2 lớp whitelist:
#   - Tier 1: XDP trusted_map (eBPF Map, bypass probabilistic drop)
#   - Tier 2: Iptables ipset ddos_whitelist (rate-limit threshold cao hơn)
# Watcher sẽ đọc trusted_map để tránh autoblock IP hợp lệ khi có alert.
# -------------------------------------------------------------------------

@mcp.tool()
def add_trusted_tier1(ip: str) -> str:
    """Thêm IP vào Tier 1 Whitelist (XDP trusted_map).
    IP trong danh sách này sẽ bypass toàn bộ kiểm tra probabilistic drop của Tier 1.
    Watcher cũng dùng danh sách này để tránh autoblock nhầm IP hợp lệ khi có alert.
    Ví dụ: add_trusted_tier1("10.10.1.3") — thêm legit client vào whitelist XDP.
    Khác với add_whitelist (cũ) ở chỗ: đây là lớp XDP kernel, không phải Iptables."""
    logging.info(f"Call add_trusted_tier1: {ip}")
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return f"❌ IP không hợp lệ: {ip}"
    try:
        response = requests.post(f"{FIREWALL_API_URL}/tier1/trusted", json={"ip": ip}, timeout=30)
        if response.status_code == 200:
            return f"✅ Đã thêm {ip} vào Tier 1 XDP Whitelist (trusted_map). IP này sẽ bypass probabilistic drop và Watcher sẽ không autoblock khi có alert từ IP này."
        return f"❌ Lỗi: {response.text}"
    except Exception as e:
        return f"❌ Lỗi kết nối firewall API: {str(e)}"

@mcp.tool()
def remove_trusted_tier1(ip: str) -> str:
    """Xóa IP khỏi Tier 1 Whitelist (XDP trusted_map).
    Sau khi xóa, IP đó sẽ bị áp dụng probabilistic drop như mọi IP lạ khác."""
    logging.info(f"Call remove_trusted_tier1: {ip}")
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return f"❌ IP không hợp lệ: {ip}"
    try:
        response = requests.delete(f"{FIREWALL_API_URL}/tier1/trusted", json={"ip": ip}, timeout=30)
        if response.status_code == 200:
            return f"✅ Đã xóa {ip} khỏi Tier 1 XDP Whitelist."
        return f"❌ Lỗi: {response.text}"
    except Exception as e:
        return f"❌ Lỗi: {str(e)}"

@mcp.tool()
def list_tier1_whitelist() -> str:
    """Liệt kê tất cả IP đang có trong Tier 1 XDP Whitelist (trusted_map).
    Đây là danh sách các IP sẽ bypass Tier 1 và được Watcher bỏ qua khi có alert."""
    logging.info("Call list_tier1_whitelist")
    try:
        response = requests.get(f"{FIREWALL_API_URL}/tier1/trusted", timeout=30)
        if response.status_code == 200:
            entries = response.json()
            if not entries:
                return "Tier 1 Whitelist trống. Dùng add_trusted_tier1(ip) để thêm IP hợp lệ."
            lines = [f"Tier 1 XDP Whitelist ({len(entries)} mục):"]
            for e in entries:
                lines.append(f"  - {e.get('ip')} (added: {e.get('last_seen', 'N/A')})")
            return "\n".join(lines)
        return f"❌ Lỗi: {response.text}"
    except Exception as e:
        return f"❌ Lỗi: {str(e)}"

@mcp.tool()
def add_whitelist_iptables(ip: str) -> str:
    """Thêm IP vào Tier 2 Whitelist (Iptables ipset ddos_whitelist).
    IP trong ipset này được áp dụng rate-limit cao hơn: SYN 100/s (thay vì 30/s), UDP 500/s.
    Dùng khi cần bảo vệ một IP hợp lệ khỏi bị iptables rate-limit chặn nhầm.
    Yêu cầu quyền root trên server firewall."""
    logging.info(f"Call add_whitelist_iptables: {ip}")
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return f"❌ IP không hợp lệ: {ip}"
    try:
        res = subprocess.run(
            ["ipset", "add", "ddos_whitelist", ip],
            capture_output=True, text=True, timeout=10
        )
        if res.returncode == 0:
            return f"✅ Đã thêm {ip} vào Iptables ipset ddos_whitelist (Tier 2 Whitelist). IP này sẽ được áp dụng rate-limit cao hơn."
        # "already added" không phải lỗi
        if "already added" in res.stderr.lower():
            return f"ℹ️ {ip} đã có trong ddos_whitelist rồi."
        return f"❌ Lỗi ipset: {res.stderr}"
    except subprocess.TimeoutExpired:
        return "❌ Timeout khi chạy ipset."
    except Exception as e:
        return f"❌ Lỗi: {str(e)}"

@mcp.tool()
def remove_whitelist_iptables(ip: str) -> str:
    """Xóa IP khỏi Tier 2 Whitelist (Iptables ipset ddos_whitelist).
    Sau khi xóa, IP đó sẽ bị áp dụng ngưỡng rate-limit thấp hơn như mọi IP lạ (30 SYN/s)."""
    logging.info(f"Call remove_whitelist_iptables: {ip}")
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return f"❌ IP không hợp lệ: {ip}"
    try:
        res = subprocess.run(
            ["ipset", "del", "ddos_whitelist", ip],
            capture_output=True, text=True, timeout=10
        )
        if res.returncode == 0:
            return f"✅ Đã xóa {ip} khỏi Iptables ddos_whitelist."
        return f"❌ Lỗi ipset: {res.stderr}"
    except Exception as e:
        return f"❌ Lỗi: {str(e)}"

@mcp.tool()
def list_whitelist_iptables() -> str:
    """Liệt kê tất cả IP trong Tier 2 Whitelist (Iptables ipset ddos_whitelist)."""
    logging.info("Call list_whitelist_iptables")
    try:
        res = subprocess.run(
            ["ipset", "list", "ddos_whitelist"],
            capture_output=True, text=True, timeout=10
        )
        if res.returncode == 0:
            return res.stdout if res.stdout else "Ipset ddos_whitelist trống."
        return f"❌ Lỗi: {res.stderr} (ipset có thể chưa được khởi tạo)"
    except Exception as e:
        return f"❌ Lỗi: {str(e)}"

@mcp.tool()
def analyze_logs_suggest_whitelist(n: int = 100) -> str:
    """AI đọc n dòng log gần nhất từ Suricata và Iptables, phân tích và đề xuất:
    - IP nào đang bị alert nhưng có vẻ là client hợp lệ (xuất hiện ít, không flood).
    - IP nào đang bị block nhưng có thể nên được whitelist.
    - IP nào nên được thêm vào blacklist vì hành vi bất thường rõ ràng.
    Đây là tool AI-driven để trả lời câu hỏi: 'IP này nên whitelist hay blacklist?'"""
    logging.info(f"Call analyze_logs_suggest_whitelist: n={n}")

    suricata_log = "/var/log/suricata/eve.json"
    kern_log_candidates = ["/var/log/kern.log", "/var/log/syslog"]
    kern_log = next((p for p in kern_log_candidates if os.path.exists(p)), None)

    # Thu thập alert IPs từ Suricata
    alert_ips: dict[str, int] = {}
    if os.path.exists(suricata_log):
        try:
            with open(suricata_log, 'r') as f:
                lines = f.readlines()[-n:]
            for line in lines:
                try:
                    data = json.loads(line)
                    if data.get("event_type") == "alert":
                        src = data.get("src_ip", "")
                        if src:
                            alert_ips[src] = alert_ips.get(src, 0) + 1
                except:
                    pass
        except Exception as e:
            pass

    # Thu thập drop IPs từ Iptables log
    drop_ips: dict[str, int] = {}
    if kern_log:
        try:
            with open(kern_log, 'r') as f:
                lines = f.readlines()[-n * 4:]
            import re
            src_re = re.compile(r"SRC=(\d+\.\d+\.\d+\.\d+)")
            for line in lines:
                if "[FW-DOS]" in line or "DROP" in line:
                    m = src_re.search(line)
                    if m:
                        ip = m.group(1)
                        drop_ips[ip] = drop_ips.get(ip, 0) + 1
        except Exception as e:
            pass

    # Phân tích và đề xuất
    report_lines = ["=== PHÂN TÍCH LOG — ĐỀ XUẤT WHITELIST/BLACKLIST ===\n"]

    # IP xuất hiện nhiều trong drop log → khả năng tấn công
    high_drop = {ip: cnt for ip, cnt in drop_ips.items() if cnt >= 5}
    low_drop  = {ip: cnt for ip, cnt in drop_ips.items() if cnt < 5}

    if high_drop:
        report_lines.append("🔴 IP CÓ KHẢ NĂNG TẤN CÔNG (nên xem xét thêm vào auto_block / blacklist):")
        for ip, cnt in sorted(high_drop.items(), key=lambda x: -x[1])[:10]:
            report_lines.append(f"   - {ip}: bị drop {cnt} lần trong log gần nhất")

    if alert_ips:
        report_lines.append("\n🟠 IP CÓ ALERT SURICATA (nên xem xét block hoặc tăng giám sát):")
        for ip, cnt in sorted(alert_ips.items(), key=lambda x: -x[1])[:10]:
            report_lines.append(f"   - {ip}: {cnt} alert(s) — có thể dùng block_ip() hoặc theo dõi thêm")

    if low_drop:
        report_lines.append("\n🟡 IP BỊ DROP ÍT (có thể là client hợp lệ bị rate-limit nhầm, xem xét whitelist):")
        for ip, cnt in sorted(low_drop.items(), key=lambda x: -x[1])[:5]:
            report_lines.append(f"   - {ip}: chỉ bị drop {cnt} lần — có thể dùng add_trusted_tier1() hoặc add_whitelist_iptables()")

    report_lines.append("\n📌 GỢI Ý:")
    report_lines.append("   - Để whitelist IP hợp lệ ở Tier 1 (XDP): gọi add_trusted_tier1(ip)")
    report_lines.append("   - Để whitelist IP ở Tier 2 (Iptables): gọi add_whitelist_iptables(ip)")
    report_lines.append("   - Để block IP tấn công: gọi block_ip(ip, proto=6, port=80)")
    report_lines.append("   - Để xem whitelist hiện tại: gọi list_tier1_whitelist()")

    if not high_drop and not alert_ips and not low_drop:
        return "Không tìm thấy log đủ để phân tích. Kiểm tra lại đường dẫn log hoặc tăng n."

    return "\n".join(report_lines)

# -------------------------------------------------------------------------
# --- ENTRY POINT ---
# -------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
