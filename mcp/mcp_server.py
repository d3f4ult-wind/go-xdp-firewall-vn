import os
import json
import requests
from mcp.server.fastmcp import FastMCP

# Khởi tạo MCP Server với tên "xdp-firewall-mcp"
# FastMCP là một wrapper giúp viết MCP server bằng Python cực kỳ đơn giản.
mcp = FastMCP("xdp-firewall-mcp")

# URL của Go Firewall API (được khai báo trong main.go và server.go)
FIREWALL_API_URL = "http://localhost:8080"

@mcp.tool()
def block_ip(ip: str, reason: str = "") -> str:
    """
    Chặn một địa chỉ IP bằng cách gửi yêu cầu xuống Go XDP Firewall.
    
    Args:
        ip: Địa chỉ IPv4 cần chặn (ví dụ: "192.168.1.100").
        reason: Lý do chặn (AI nên cung cấp lý do dựa trên phân tích).
    """
    # Endpoint POST /rules của firewall mong đợi JSON payload:
    # {"subnet": "ip/32", "proto": 0, "port": 0, "action": "DROP"}
    payload = {
        "subnet": f"{ip}/32",
        "proto": 0,    # 0 = All protocols
        "port": 0,     # 0 = All ports
        "action": "DROP"
    }
    
    try:
        response = requests.post(f"{FIREWALL_API_URL}/rules", json=payload)
        
        if response.status_code == 201:
            return f"✅ Đã chặn IP {ip} thành công ở tầng XDP. Lý do: {reason}"
        else:
            return f"❌ Lỗi khi chặn IP {ip}. Firewall trả về mã {response.status_code}: {response.text}"
    except requests.exceptions.ConnectionError:
        return "❌ Không thể kết nối tới Go Firewall. Đảm bảo chương trình main.go đang chạy ở cổng 8080."
    except Exception as e:
        return f"❌ Lỗi không xác định: {str(e)}"

@mcp.tool()
def check_firewall_health() -> str:
    """
    Kiểm tra tình trạng hoạt động (health) của Firewall (CPU, RAM, XDP Attached status).
    """
    try:
        response = requests.get(f"{FIREWALL_API_URL}/health")
        if response.status_code == 200:
            data = response.json()
            return (
                f"Tình trạng Firewall:\n"
                f"- Trạng thái: {data.get('status')}\n"
                f"- XDP Đã nạp: {'Có' if data.get('xdp_attached') else 'Không'}\n"
                f"- CPU Sử dụng: {data.get('cpu_percent')}%\n"
                f"- RAM Sử dụng: {data.get('memory_mb')} MB"
            )
        return f"Lỗi lấy thông tin health: {response.text}"
    except Exception as e:
        return f"Lỗi kết nối: {str(e)}"

@mcp.tool()
def list_active_rules() -> str:
    """
    Lấy danh sách các IP đang bị chặn hoặc các luật đang áp dụng.
    """
    try:
        response = requests.get(f"{FIREWALL_API_URL}/rules")
        if response.status_code == 200:
            rules = response.json()
            if not rules:
                return "Hiện tại không có luật nào đang được áp dụng."
            
            result = "Danh sách các luật:\n"
            for r in rules:
                result += f"- {r.get('subnet')} | Giao thức: {r.get('proto')} | Cổng: {r.get('port')} | Hành động: {r.get('action')}\n"
            return result
        return "Lỗi khi lấy danh sách luật."
    except Exception as e:
        return f"Lỗi kết nối: {str(e)}"

@mcp.resource("file:///var/log/suricata/eve.json")
def read_suricata_logs() -> str:
    """
    Đọc 50 cảnh báo (alerts) gần nhất từ Suricata.
    Đây là một tài nguyên (resource) để AI lấy dữ liệu phân tích.
    """
    log_path = "/var/log/suricata/eve.json"
    
    if not os.path.exists(log_path):
        return f"Không tìm thấy file log tại {log_path}. Có thể Suricata chưa được cài đặt hoặc thư mục bị sai."
        
    try:
        # Đọc ngược file (tail) để lấy log mới nhất
        with open(log_path, 'r') as f:
            lines = f.readlines()
            
        recent_lines = lines[-50:] # Lấy 50 dòng cuối cùng
        
        alerts = []
        for line in recent_lines:
            try:
                data = json.loads(line)
                if data.get('event_type') == 'alert':
                    alerts.append(json.dumps({
                        "timestamp": data.get("timestamp"),
                        "src_ip": data.get("src_ip"),
                        "dest_ip": data.get("dest_ip"),
                        "alert": data.get("alert", {}).get("signature")
                    }))
            except:
                pass
                
        if not alerts:
            return "Không có cảnh báo tấn công nào trong 50 dòng log gần nhất."
            
        return "\n".join(alerts)
    except Exception as e:
        return f"Lỗi khi đọc file log: {str(e)}"

@mcp.resource("file:///var/log/syslog")
def read_iptables_logs() -> str:
    """
    Đọc 50 dòng log gần nhất từ iptables (thường ghi vào syslog hoặc kern.log).
    Đây là tài nguyên để AI phân tích các kết nối bị rớt ở tầng Iptables.
    """
    log_paths = ["/var/log/syslog", "/var/log/kern.log"]
    log_path = None
    
    # Tìm file log hệ thống phù hợp
    for path in log_paths:
        if os.path.exists(path):
            log_path = path
            break
            
    if not log_path:
        return "Không tìm thấy file log syslog hoặc kern.log trên hệ thống."
        
    try:
        with open(log_path, 'r') as f:
            lines = f.readlines()
            
        # Đọc 200 dòng cuối cùng
        recent_lines = lines[-200:]
        
        fw_logs = []
        for line in recent_lines:
            # Lọc các dòng log liên quan đến Firewall. 
            # Iptables thường log với tiền tố prefix mà bạn cấu hình. 
            # Giả định ở đây chứa từ khoá "FW-", "DROP", "BLOCK"
            if "FW-" in line or "DROP" in line or "iptables" in line.lower():
                fw_logs.append(line.strip())
                
        if not fw_logs:
            return "Không tìm thấy cảnh báo iptables/firewall nào trong 200 dòng syslog gần nhất."
            
        # Trả về tối đa 50 dòng mới nhất để AI đọc
        return "\n".join(fw_logs[-50:])
    except Exception as e:
        return f"Lỗi khi đọc file syslog: {str(e)}"

if __name__ == "__main__":
    # Để chạy server này, sử dụng: mcp run mcp_server.py
    # Hoặc để tích hợp vào Claude Desktop, xem hướng dẫn của FastMCP.
    mcp.run()
