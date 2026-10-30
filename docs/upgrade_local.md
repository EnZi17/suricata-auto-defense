# Cập nhật máy Ubuntu đang chạy

Giải nén bản ZIP mới vào một thư mục mới, không chép gộp với bản cũ, để tránh
giữ lại các module đã loại bỏ. Mở Terminal tại thư mục có scripts, config, rules.

```bash
sudo bash scripts/00_run_all.sh
```

Script triển khai module phòng thủ mới vào /opt/suricata-auto-defense và restart
service. Các file module cũ còn nằm trong thư mục cũ hoặc /opt sẽ không được gọi.
Không thay thế rules/local.rules bằng bản ZIP nếu nhóm đã chỉnh thêm luật mà
chưa lưu lại; sao lưu các thay đổi của nhóm trước khi cài lại.

Kiểm tra cú pháp và test không thay đổi firewall:

```bash
bash tests/test_defense_offline.sh
python3 -m unittest discover -s tests -p test_lab_config.py
```

Kiểm tra thực tế trên Ubuntu:

```bash
sudo systemctl is-active suricata-lab-network suricata suricata-defense
sudo bash /opt/suricata-auto-defense/scripts/03_auto_defense.sh --unban 10.203.0.2
sudo ip netns exec suricata-attacker nmap -sS -p 1-200 10.203.0.1
sudo ufw status numbered
sudo journalctl -u suricata-defense -n 30 --no-pager
```

Nếu IP chưa bị chặn, unban có thể báo không có rule. Sau quét, cần có DENY nguồn
10.203.0.2 và log tương ứng. Gỡ chặn trước khi chạy lại từng bài test.
