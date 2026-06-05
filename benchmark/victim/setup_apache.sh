#!/bin/bash
# =============================================================
# File: setup_apache.sh
# Chạy trên: VM victim (10.10.2.2)
# Mục đích: Cài đặt và cấu hình Apache sử dụng mpm_prefork.
#           Thiết lập MaxRequestWorkers=50 để dễ bị quá tải (Slowloris).
#           Tạo 2 endpoint: / (HTML) và /health (JSON).
# Input: Không
# Output: Khởi động service apache2
# Gọi bởi: Chạy độc lập 1 lần trước khi test
# =============================================================

if [ "$EUID" -ne 0 ]; then
  echo "Vui lòng chạy bằng quyền root (sudo)"
  exit 1
fi

echo "[*] Đang cài đặt Apache2 và PHP..."
apt-get update
apt-get install -y apache2 php libapache2-mod-php

echo "[*] Tắt các MPM module khác, bật mpm_prefork..."
a2dismod mpm_event mpm_worker 2>/dev/null
a2enmod mpm_prefork
a2enmod status

echo "[*] Cấu hình mpm_prefork (MaxRequestWorkers = 50)..."
# Ghi đè file cấu hình mpm_prefork
cat <<EOF > /etc/apache2/mods-available/mpm_prefork.conf
<IfModule mpm_prefork_module>
    StartServers             5
    MinSpareServers          5
    MaxSpareServers         10
    MaxRequestWorkers       50
    MaxConnectionsPerChild   0
</IfModule>
EOF

echo "[*] Bật mod_status và ExtendedStatus..."
# Cho phép local và các máy đo lường được xem server-status
cat <<EOF > /etc/apache2/mods-available/status.conf
<IfModule mod_status.c>
    ExtendedStatus On
    <Location /server-status>
        SetHandler server-status
        Require all granted
    </Location>
</IfModule>
EOF

echo "[*] Tạo Endpoint / (HTML tĩnh có PHP Timestamp)..."
cat <<'EOF' > /var/www/html/index.php
<!DOCTYPE html>
<html>
<head><title>Victim Server</title></head>
<body>
    <h1>Welcome to Victim Server</h1>
    <p>Server Time (Unix): <?php echo time(); ?></p>
</body>
</html>
EOF
rm -f /var/www/html/index.html

echo "[*] Tạo Endpoint /health (JSON Health-check)..."
cat <<'EOF' > /var/www/html/health.php
<?php
header('Content-Type: application/json');
$status = "ok";
$time = time();

// Đọc số worker bận từ server-status (rất cơ bản)
$status_url = "http://127.0.0.1/server-status?auto";
$status_data = @file_get_contents($status_url);
$busy_workers = 0;
if ($status_data !== false) {
    if (preg_match('/BusyWorkers:\s*(\d+)/i', $status_data, $matches)) {
        $busy_workers = intval($matches[1]);
    }
}

echo json_encode([
    "status" => $status,
    "workers_busy" => $busy_workers,
    "time" => $time
]);
?>
EOF

echo "[*] Restarting Apache2..."
systemctl restart apache2
systemctl enable apache2

echo "[OK] Setup Apache hoàn tất. Bạn có thể truy cập http://10.10.2.2/ và http://10.10.2.2/health.php"
