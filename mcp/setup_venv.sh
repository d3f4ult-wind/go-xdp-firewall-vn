#!/bin/bash
# ===========================================================
# FILE: setup_venv.sh
# MÔ TẢ: Script cài đặt môi trường Python cho MCP Server.
# CÁCH CHẠY: chmod +x setup_venv.sh && ./setup_venv.sh
#
# DỰ PHÒNG: Script thử pip thường trước, nếu lỗi thì dùng venv.
# LÝ DO: Một số hệ thống Linux mới (Ubuntu 23+) chặn pip install
#        trực tiếp (PEP 668), bắt buộc phải dùng virtual environment.
# ===========================================================

set -e  # Dừng ngay nếu có lỗi

echo "======================================"
echo "  MCP Server - Cài đặt môi trường"
echo "======================================"

# Thư mục chứa script này
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"

# --- BƯỚC 1: Thử cài pip trực tiếp (cách nhanh nhất) ---
echo "[1/3] Thử cài đặt bằng pip trực tiếp..."
if pip install -r "$SCRIPT_DIR/requirements.txt" 2>/dev/null; then
    echo "✅ Cài pip trực tiếp thành công!"
    echo ""
    echo "Cách chạy MCP server:"
    echo "  cd $SCRIPT_DIR && python mcp_server.py"
    exit 0
fi

# --- BƯỚC 2: Thử pip3 ---
echo "[1/3] pip thường thất bại, thử pip3..."
if pip3 install -r "$SCRIPT_DIR/requirements.txt" 2>/dev/null; then
    echo "✅ Cài pip3 trực tiếp thành công!"
    echo ""
    echo "Cách chạy MCP server:"
    echo "  cd $SCRIPT_DIR && python3 mcp_server.py"
    exit 0
fi

# --- BƯỚC 3: Dùng venv (phương án dự phòng) ---
echo "[2/3] Tạo môi trường ảo (virtual environment) tại: $VENV_DIR"
python3 -m venv "$VENV_DIR"

echo "[3/3] Cài đặt thư viện vào venv..."
"$VENV_DIR/bin/pip" install -r "$SCRIPT_DIR/requirements.txt"

echo ""
echo "======================================"
echo "✅ Cài đặt venv thành công!"
echo ""
echo "Để chạy MCP server với venv, dùng lệnh:"
echo "  source $VENV_DIR/bin/activate"
echo "  cd $SCRIPT_DIR && python mcp_server.py"
echo ""
echo "Hoặc dùng wrapper script:"
echo "  $SCRIPT_DIR/run_mcp.sh"
echo "======================================"

# Tạo wrapper script tiện lợi để chạy server
cat > "$SCRIPT_DIR/run_mcp.sh" << EOF
#!/bin/bash
# Script chạy MCP server với virtual environment
source "$VENV_DIR/bin/activate"
cd "$SCRIPT_DIR"
python mcp_server.py
EOF
chmod +x "$SCRIPT_DIR/run_mcp.sh"
echo "✅ Đã tạo run_mcp.sh"
