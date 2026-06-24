"""
=================================================================================
FILE: app.py (Flask UI Backend)
MÔ TẢ: Đóng vai trò là Proxy/Gateway trung gian giữa Trình duyệt và Go Firewall API.
LUỒNG HOẠT ĐỘNG: 
  1. Tiếp nhận các yêu cầu từ giao diện Web (Frontend).
  2. Chuyển tiếp (Forward) các yêu cầu này đến Go REST Server (thông thường chạy tại cổng 8080).
  3. Tổng hợp kết quả, xử lý ngoại lệ (Timeout, Connection Refused) và trả về cho người dùng.
TẠI SAO CÓ LỚP NÀY: Giúp tách biệt logic hiển thị và logic điều khiển Firewall, 
đồng thời tránh các vấn đề về CORS (Cross-Origin Resource Sharing) khi Frontend gọi trực tiếp Backend.
=================================================================================
"""

from flask import Flask, request, jsonify, send_from_directory
import requests
import subprocess
import os
import ipaddress

# Địa chỉ của Go Control Plane. 
# CẠM BẪY: Nếu triển khai trên Docker, 127.0.0.1 sẽ trỏ về chính container Flask. 
# Cần đổi thành tên service của Go nếu chạy đa container.
FIREWALL_API = "http://127.0.0.1:8080"

# Khoảng thời gian chờ tối đa để Backend phản hồi.
# TẠI SAO: Tránh việc người dùng phải chờ vô tận nếu Go Server bị treo hoặc quá tải.
TIMEOUT = 3  # seconds

app = Flask(__name__)

def call_firewall_api(method, path, json=None):
    """
    Hàm helper trung tâm để giao tiếp với Go API.
    MỤC ĐÍCH: Tập trung hóa việc xử lý lỗi (DRY - Don't Repeat Yourself).
    """
    url = f"{FIREWALL_API}{path}"

    try:
        # # BƯỚC 1: Thực hiện request đến Backend
        r = requests.request(
            method,
            url,
            json=json,
            timeout=TIMEOUT
        )

        # # BƯỚC 2: Kiểm tra mã trạng thái HTTP
        # raise_for_status sẽ ném ra ngoại lệ nếu mã trả về là 4xx hoặc 5xx.
        r.raise_for_status() 

        try:
            return r.json(), r.status_code
        except ValueError:
            # Trường hợp Backend trả về mã 200 nhưng body không phải JSON hợp lệ.
            return {
                "error": "Invalid JSON from firewall API"
            }, 502 # Bad Gateway: Lỗi do server phía sau trả dữ liệu sai cấu trúc.

    except requests.exceptions.Timeout:
        # CẠM BẪY: eBPF nạp luật rất nhanh, nhưng nếu hệ thống đang Flush map lớn, 
        # API có thể phản hồi chậm dẫn đến Timeout tại đây.
        return {
            "error": "Firewall API timeout"
        }, 504 # Gateway Timeout

    except requests.exceptions.ConnectionError:
        # Xảy ra khi Go Server chưa khởi động hoặc bị sập.
        return {
            "error": "Firewall API unreachable"
        }, 503 # Service Unavailable

    except requests.exceptions.HTTPError as e:
        # # BƯỚC 3: Forward lỗi từ Backend về Frontend
        # Nếu Backend trả về 400 (Bad Request) kèm thông báo lỗi IP sai, 
        # chúng ta cần đưa nguyên văn thông báo đó cho người dùng UI thấy.
        try:
            return r.json(), r.status_code
        except Exception:
            return {
                "error": "Firewall API error",
                "status": r.status_code
            }, r.status_code

    except Exception as e:
        return {
            "error": "Unexpected error",
            "details": str(e)
        }, 500

@app.route("/")
def index():
    """Phục vụ file HTML tĩnh cho giao diện người dùng."""
    return send_from_directory("static", "index.html")

@app.route("/ratelimit")
def ratelimit_page():
    """Phục vụ file HTML cấu hình Rate Limiting."""
    return send_from_directory("static", "ratelimit.html")

@app.route("/rules", methods=["GET"])
def list_rules():
    """Lấy danh sách các luật hiện có từ Kernel thông qua Go API."""
    data, status = call_firewall_api("GET", "/rules")
    return jsonify(data), status

@app.route("/rules", methods=["POST"])
def add_rule():
    """Tiếp nhận thông tin luật mới từ UI và gửi xuống Backend."""
    try:
        # # BƯỚC 1: Chuyển tiếp nguyên văn JSON payload từ Frontend sang Go API.
        r = requests.post(
            f"{FIREWALL_API}/rules",
            json=request.json,
            timeout=2
        )

        # 201 Created: Backend đã nạp luật thành công vào eBPF Map.
        if r.status_code == 201:
            return jsonify({"status": "ok"}), 201

        return jsonify({
            "error": "Firewall rejected rule",
            "status_code": r.status_code,
            "body": r.text
        }), r.status_code

    except requests.RequestException:
        return jsonify({"error": "Firewall API unreachable"}), 503

@app.route("/rules", methods=["DELETE"])
def delete_rule():
    """Yêu cầu Backend xóa luật dựa trên bộ nhận diện (Subnet/Port/Proto)."""
    try:
        # # BƯỚC 1: Chuyển tiếp yêu cầu DELETE.
        # Lưu ý: Một số Proxy có thể chặn body trong DELETE request, 
        # nhưng ở đây ta dùng HTTP chuẩn nên vẫn cho phép gửi JSON body.
        r = requests.delete(
            f"{FIREWALL_API}/rules",
            json=request.json,
            timeout=2
        )

        if r.status_code == 200:
            return jsonify({"status": "ok"}), 200

        return jsonify({
            "error": "Firewall failed to delete rule",
            "status_code": r.status_code,
            "body": r.text
        }), r.status_code

    except requests.RequestException:
        return jsonify({"error": "Firewall API unreachable"}), 503

@app.route("/ratelimit/ips", methods=["GET"])
def get_ratelimit_ips():
    """Lấy danh sách các IP đang bị rate limit."""
    data, status = call_firewall_api("GET", "/ratelimit/ips")
    return jsonify(data), status

@app.route("/autoblock/ips", methods=["GET", "DELETE"])
def handle_autoblock_ips():
    """Lấy danh sách hoặc Xóa các IP bị block tự động bởi Threat Intel."""
    if request.method == "GET":
        data, status = call_firewall_api("GET", "/autoblock/ips")
        return jsonify(data), status
    
    if request.method == "DELETE":
        try:
            r = requests.delete(
                f"{FIREWALL_API}/autoblock/ips",
                json=request.json,
                timeout=2
            )
            if r.status_code == 200:
                return jsonify({"status": "ok"}), 200

            return jsonify({
                "error": "Failed to unban IP",
                "status_code": r.status_code,
                "body": r.text
            }), r.status_code
        except requests.RequestException:
            return jsonify({"error": "Firewall API unreachable"}), 503

@app.route("/ratelimit/config", methods=["GET", "POST"])
def ratelimit_config():
    """Lấy hoặc cập nhật cấu hình Rate Limiting."""
    try:
        if request.method == "GET":
            r = requests.get(f"{FIREWALL_API}/ratelimit/config", timeout=2)
        else:
            r = requests.post(
                f"{FIREWALL_API}/ratelimit/config",
                json=request.json,
                timeout=2
            )
        
        # Forward y nguyên JSON và status code về UI
        return jsonify(r.json()), r.status_code

    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Firewall API unreachable"}), 503
    except requests.exceptions.Timeout:
        return jsonify({"error": "Firewall API timeout"}), 504
    except ValueError:
        return jsonify({"error": "Invalid response from Firewall API"}), 502

@app.route("/health")
def health():
    """Kiểm tra sức khỏe hệ thống (CPU, RAM và trạng thái nạp XDP)."""
    data, status = call_firewall_api("GET", "/health")
    return jsonify(data), status

@app.route("/default", methods=["GET", "POST"])
def default_action():
    """Quản lý chính sách mặc định (Default Action: DROP/PASS)."""
    try:
        if request.method == "GET":
            r = requests.get(f"{FIREWALL_API}/default", timeout=2)
        else:
            r = requests.post(
                f"{FIREWALL_API}/default",
                json=request.json,
                timeout=2
            )

        return jsonify(r.json()), r.status_code

    except requests.exceptions.ConnectionError:
        return jsonify({
            "status": "error",
            "message": "Firewall API unreachable"
        }), 503

    except requests.exceptions.Timeout:
        return jsonify({
            "status": "error",
            "message": "Firewall API timeout"
        }), 504

    except ValueError:
        return jsonify({
            "status": "error",
            "message": "Invalid response from Firewall API"
        }), 502

@app.route("/tier1")
def tier1_page():
    """Phục vụ file HTML cấu hình Adaptive Tier 1."""
    return send_from_directory("static", "tier1.html")

@app.route("/api/tier1/mitigation", methods=["POST"])
def tier1_mitigation():
    data, status = call_firewall_api("POST", "/tier1/mitigation", json=request.json)
    return jsonify(data), status

@app.route("/api/tier1/stats", methods=["GET"])
def tier1_stats():
    data, status = call_firewall_api("GET", "/tier1/stats")
    return jsonify(data), status

@app.route("/api/tier1/trusted", methods=["POST", "DELETE"])
def tier1_trusted():
    data, status = call_firewall_api(request.method, "/tier1/trusted", json=request.json)
    return jsonify(data), status

@app.route("/api/tier1/trusted/list", methods=["GET"])
def tier1_trusted_list():
    data, status = call_firewall_api("GET", "/tier1/trusted/list")
    return jsonify(data), status

@app.route("/api/tier1/geo", methods=["POST", "DELETE"])
def tier1_geo():
    data, status = call_firewall_api(request.method, "/tier1/geo", json=request.json)
    return jsonify(data), status

@app.route("/api/tier1/geo/list", methods=["GET"])
def tier1_geo_list():
    data, status = call_firewall_api("GET", "/tier1/geo/list")
    return jsonify(data), status

@app.route("/api/tier1/geo/clear", methods=["DELETE"])
def tier1_geo_clear():
    data, status = call_firewall_api("DELETE", "/tier1/geo/clear")
    return jsonify(data), status

@app.route("/api/tier1/geo_country", methods=["POST"])
def tier1_geo_country():
    data, status = call_firewall_api("POST", "/tier1/geo_country", json=request.json)
    return jsonify(data), status

@app.route("/api/tier1/watcher", methods=["GET", "POST"])
def tier1_watcher():
    data, status = call_firewall_api(request.method, "/tier1/watcher", json=request.json if request.method == "POST" else None)
    return jsonify(data), status

@app.route("/mcp")
def mcp_page():
    """Phục vụ file HTML cấu hình MCP AI Chat."""
    return send_from_directory("static", "mcp.html")

@app.route("/api/system/run_iptables_block", methods=["POST"])
def api_run_iptables_block():
    ip = request.json.get("ip")
    if not ip: return jsonify({"error": "Thiếu IP"}), 400
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": f"IP không hợp lệ: {ip}"}), 400
    try:
        res = subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True, text=True)
        if res.returncode == 0: return jsonify({"status": "ok", "msg": f"✅ Đã chặn {ip} ở tầng Iptables."})
        return jsonify({"error": res.stderr}), 500
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/api/system/list_iptables_rules", methods=["GET"])
def api_list_iptables_rules():
    try:
        res = subprocess.run(["iptables", "-L", "-n"], capture_output=True, text=True)
        return jsonify({"rules": res.stdout})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/api/system/reload_suricata_rules", methods=["POST"])
def api_reload_suricata_rules():
    try:
        res = subprocess.run(["pkill", "-USR2", "suricata"], capture_output=True, text=True)
        if res.returncode == 0: return jsonify({"status": "ok", "msg": "✅ Đã reload rules Suricata thành công."})
        return jsonify({"error": res.stderr}), 500
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/api/system/get_suricata_stats", methods=["GET"])
def api_get_suricata_stats():
    log_path = "/var/log/suricata/stats.log"
    if not os.path.exists(log_path): return jsonify({"stats": f"Không tìm thấy log tại {log_path}."})
    try:
        with open(log_path, 'r') as f: lines = f.readlines()[-20:]
        return jsonify({"stats": "\n".join(lines)})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/api/system/read_suricata_logs", methods=["GET"])
def api_read_suricata_logs():
    n = request.args.get("n", 50, type=int)
    log_path = "/var/log/suricata/eve.json"
    if not os.path.exists(log_path): return jsonify({"logs": f"Không tìm thấy log tại {log_path}."})
    try:
        with open(log_path, 'r') as f: lines = f.readlines()[-n:]
        import json
        alerts = []
        for line in lines:
            try:
                data = json.loads(line)
                if data.get('event_type') == 'alert':
                    alerts.append(f"{data.get('timestamp')} - {data.get('src_ip')} -> {data.get('dest_ip')}: {data.get('alert', {}).get('signature')}")
            except: pass
        return jsonify({"logs": "\n".join(alerts) if alerts else "Không có cảnh báo tấn công."})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route("/api/system/read_iptables_logs", methods=["GET"])
def api_read_iptables_logs():
    n = request.args.get("n", 50, type=int)
    log_paths = ["/var/log/syslog", "/var/log/kern.log"]
    log_path = next((p for p in log_paths if os.path.exists(p)), None)
    if not log_path: return jsonify({"logs": "Không tìm thấy syslog/kern.log."})
    try:
        with open(log_path, 'r') as f: lines = f.readlines()[-n*4:]
        fw_logs = [l.strip() for l in lines if "FW-" in l or "DROP" in l or "iptables" in l.lower()]
        return jsonify({"logs": "\n".join(fw_logs[-n:]) if fw_logs else "Không có log iptables."})
    except Exception as e: return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    print("[+] Firewall UI (Flask) starting...")
    print(f"[+] Forwarding requests to: {FIREWALL_API}")
    
    # debug=False: Trong môi trường firewall thực tế, không bao giờ bật debug mode.
    # LÝ DO: Debug mode của Flask cho phép thực thi mã Python tùy ý nếu có lỗi, 
    # tạo ra lỗ hổng bảo mật nghiêm trọng (RCE).
    app.run(host="0.0.0.0", port=8000, debug=False)