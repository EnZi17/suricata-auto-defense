# Cài đặt mô hình một máy ảo Ubuntu 24.04

Trần Trung Việt phụ trách cài đặt và tích hợp. Mô hình sử dụng network namespace
để tạo nguồn tấn công riêng ngay trong một máy Ubuntu:

```text
namespace suricata-attacker                  Ubuntu host
suri-peer: 10.203.0.2/30  <--- veth --->  suri-host: 10.203.0.1/30
                                               Suricata + SSH + nginx + UFW
```

Suricata giám sát `suri-host`. Chạy lệnh tạo traffic bằng `ip netns exec`, không
chạy trực tiếp trong namespace mặc định. UFW chặn nguồn `10.203.0.2`; IP quản trị
của máy ảo vẫn dùng interface hiện có. Namespace không có default route hay NAT.
Script từ chối tạo mạng nếu subnet `10.203.0.0/30` trùng route đang có.

## Cài đặt

Trên Ubuntu 24.04 có systemd và Internet, từ thư mục repository:

```bash
cp -n config/suricata-defense.conf.example config/suricata-defense.conf
sudo bash scripts/00_run_all.sh
```

Có thể chạy riêng `sudo bash scripts/01_setup_suricata.sh` để cài môi trường,
chưa khởi động Auto Defense. Script cài Suricata, UFW, SSH server, nginx và nmap;
mở cổng 22, 80 và cổng SSH của phiên hiện tại khi có `SSH_CONNECTION`, sau đó bật
UFW. Nếu dùng SSH tùy chỉnh và biến này không được sudo giữ lại, mở trước cổng
quản trị bằng `sudo ufw allow <port>/tcp`.

Cấu hình chung chứa whitelist, ngưỡng severity và ALERT_COOLDOWN. File `config/suricata-defense.conf` được Git
bỏ qua; script giữ nội dung hiện có. Không thêm `10.203.0.2` vào whitelist.
Các module runtime và bản sao cấu hình quyền 600 được cài tại
`/opt/suricata-auto-defense`; service không phụ thuộc đường dẫn clone.
Sau khi sửa module 03, 04 hoặc cấu hình trong repo, chạy lại setup để triển khai.

Setup giữ cấu hình YAML gốc bằng backup có timestamp; cập nhật HOME_NET về subnet
lab, AF_PACKET, local.rules và EVE alert. Nếu kiểm tra cấu hình thất bại, khôi phục
YAML và local.rules trước đó. Script không rollback gói apt hoặc thay đổi UFW.
Chạy lại sẽ dùng mạng lab hiện có, không xóa namespace hay reset firewall.
Các luật trong repo được triển khai lại: lưu thay đổi local.rules bên ngoài repo
trước khi chạy setup. Service mạng được enable để dựng lại namespace sau reboot.

## Kiểm tra trên máy ảo

```bash
sudo systemctl is-active suricata-lab-network suricata suricata-defense ssh nginx
sudo ip netns exec suricata-attacker ip -4 addr show suri-peer
sudo ip netns exec suricata-attacker ping -c 3 10.203.0.1
sudo jq -c 'select(.event_type=="alert") | {src_ip,alert}' /var/log/suricata/eve.json
sudo ip netns exec suricata-attacker nmap -sS -p 1-200 10.203.0.1
sudo ufw status
sudo journalctl -u suricata-defense -n 30 --no-pager
sudo bash /opt/suricata-auto-defense/scripts/03_auto_defense.sh --unban 10.203.0.2
```

Ping thường chỉ có severity 3 và không bị chặn. Nmap phải tạo alert nguồn
`10.203.0.2`, sau đó UFW có rule DENY cho IP đó. Sau khi bị chặn, gỡ chặn trước
khi thử HTTP/SSH. Đăng nhập SSH quản trị vẫn phải hoạt động.

Chạy setup hai lần và reboot rồi lặp lại kiểm tra để xác nhận tính ổn định.
Nếu lỗi, xem `journalctl -u suricata -u suricata-lab-network -u suricata-defense`.

## Phạm vi hiện tại

`simulate_attacks.sh` thuộc phần
việc của Nguyễn Ngọc Thái; tạm dùng các lệnh namespace ở trên. IP được gỡ chặn thủ công bằng --unban. Chưa có kết quả chạy thực tế trên Ubuntu từ
môi trường phát triển Windows; cần thực hiện checklist trên máy ảo trước demo.

Kiểm tra cấu hình không cần root: `python3 -m unittest discover -s tests -p test_lab_config.py`.
