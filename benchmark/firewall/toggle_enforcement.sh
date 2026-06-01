#!/bin/bash
# ==============================================================================
# Script: toggle_enforcement.sh
# Mục đích: Đổi trạng thái cờ Enforcement của XDP siêu nhanh
# ==============================================================================

STATE=$1
if [ "$STATE" == "1" ]; then
    curl -s -X POST http://localhost:8080/enforcement -H "Content-Type: application/json" -d '{"enabled": true}' > /dev/null
    # echo "Đã bật Enforcement = 1"
else
    curl -s -X POST http://localhost:8080/enforcement -H "Content-Type: application/json" -d '{"enabled": false}' > /dev/null
    # echo "Đã tắt Enforcement = 0"
fi
