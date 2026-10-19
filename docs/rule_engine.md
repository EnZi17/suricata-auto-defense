# Rule Engine – Nguyễn Ngọc Thái

Luật Suricata tự viết (`rules/local.rules`) và script quản lý luật (`scripts/02_rule_manager.sh`).

- Server: `192.168.1.100` · Attacker: `192.168.1.200`
- File luật trên hệ thống: `/etc/suricata/rules/local.rules` (khai báo trong `rule-files` của `/etc/suricata/suricata.yaml`)
- `priority` của luật = `alert.severity` trong `eve.json`. `03_auto_defense.sh` chặn IP khi `severity <= MIN_SEVERITY` (mặc định 2), nên luật priority 3 chỉ cảnh báo, luật priority 1–2 sẽ bị chặn.

## Dải SID

| Nhóm | Dải SID | Số luật |
|---|---|---|
| ICMP | 1000001 – 1000009 | 3 |
| Nmap scan | 1000010 – 1000019 | 4 |
| SSH brute-force | 1000020 – 1000029 | 3 |
| Path Traversal | 1000030 – 1000039 | 4 |

## Bảng rule → hành vi tấn công → lệnh test

Chạy các lệnh dưới đây trên máy Attacker. Kiểm tra trên Server bằng:

```bash
sudo tail -f /var/log/suricata/fast.log
sudo jq -c 'select(.event_type=="alert") | {src_ip, sid: .alert.signature_id, sev: .alert.severity, sig: .alert.signature}' /var/log/suricata/eve.json
```

| SID | Luật | Hành vi tấn công | Điều kiện phát hiện | Severity | Lệnh tạo traffic (Attacker) |
|---|---|---|---|---|---|
| 1000001 | LOCAL ICMP Ping detected | Dò máy sống bằng ping | ICMP echo request (`itype:8`), tối đa 1 alert / 60s / IP | 3 (chỉ cảnh báo) | `ping -c 3 192.168.1.100` |
| 1000002 | LOCAL ICMP Ping Flood | Làm ngập Server bằng ping | ≥ 20 echo request trong 5s (`threshold: both`) | 2 | `ping -c 40 -i 0.1 192.168.1.100` (hoặc `sudo ping -f -c 200 ...`) |
| 1000003 | LOCAL ICMP Large Packet | Ping of Death / gói ICMP quá lớn | `dsize:>1000` | 2 | `ping -c 2 -s 1200 192.168.1.100` |
| 1000010 | LOCAL Nmap SYN Scan | Quét cổng SYN | ≥ 20 gói SYN trong 10s từ 1 IP | 2 | `sudo nmap -sS -p 1-1000 192.168.1.100` |
| 1000011 | LOCAL Nmap NULL Scan | Quét NULL | Gói TCP không bật cờ nào (`flags:0`) | 2 | `sudo nmap -sN -p 1-100 192.168.1.100` |
| 1000012 | LOCAL Nmap FIN Scan | Quét FIN | Chỉ bật cờ FIN (`flags:F`) | 2 | `sudo nmap -sF -p 1-100 192.168.1.100` |
| 1000013 | LOCAL Nmap XMAS Scan | Quét XMAS | Bật FIN + PSH + URG (`flags:FPU`) | 2 | `sudo nmap -sX -p 1-100 192.168.1.100` |
| 1000020 | LOCAL SSH Brute-force Attempt | Dò mật khẩu SSH | ≥ 5 kết nối mới tới cổng 22 trong 60s (`detection_filter`) | 1 | `for i in $(seq 1 6); do ssh -o BatchMode=yes fake$i@192.168.1.100; done` hoặc `hydra -l root -P pass.txt ssh://192.168.1.100` |
| 1000021 | LOCAL SSH Brute-force Tool Banner (libssh) | Tool dò mật khẩu dùng libssh (hydra) | `ssh.software` chứa `libssh` | 1 | `hydra -l root -P pass.txt ssh://192.168.1.100` hoặc `(printf 'SSH-2.0-libssh_0.10.6\r\n'; sleep 1) \| nc 192.168.1.100 22` |
| 1000022 | LOCAL SSH Brute-force Tool Banner (paramiko) | Script Python dò mật khẩu (paramiko) | `ssh.software` chứa `paramiko` | 1 | `(printf 'SSH-2.0-paramiko_3.4.0\r\n'; sleep 1) \| nc 192.168.1.100 22` |
| 1000030 | LOCAL Path Traversal ../ in URI | Đọc file ngoài web root bằng `../` | `http.uri.raw` chứa `../` | 1 | `curl --path-as-is http://192.168.1.100/../../etc/passwd` |
| 1000031 | LOCAL Path Traversal encoded %2e%2e | Path traversal mã hóa URL | `http.uri.raw` chứa `%2e%2e` | 1 | `curl "http://192.168.1.100/%2e%2e%2f%2e%2e%2fetc/hosts"` |
| 1000032 | LOCAL Path Traversal encoded ..%2f | Path traversal mã hóa một nửa | `http.uri.raw` chứa `..%2f` | 1 | `curl --path-as-is "http://192.168.1.100/..%2f..%2fetc/shadow"` |
| 1000033 | LOCAL Path Traversal /etc/passwd access | Cố đọc `/etc/passwd` | `http.uri` (đã chuẩn hóa) chứa `/etc/passwd` | 1 | `curl --path-as-is http://192.168.1.100/../../etc/passwd` |

> Path Traversal dùng `http.uri.raw` vì Suricata chuẩn hóa `http.uri` (xóa `../`) trước khi so khớp. `curl` mặc định cũng tự xóa `../`, nên cần `--path-as-is`.

### Kết quả đã kiểm thử

Đã kiểm thử trên Ubuntu 24.04 (ARM64), Suricata 7.0.3. Máy tấn công là host `10.211.55.2`, Server là `10.211.55.3`:

```
1000001 sev=3 10.211.55.2 -> 10.211.55.3  LOCAL ICMP Ping detected
1000002 sev=2 10.211.55.2 -> 10.211.55.3  LOCAL ICMP Ping Flood
1000003 sev=2 10.211.55.2 -> 10.211.55.3  LOCAL ICMP Large Packet
1000010 sev=2 10.211.55.2 -> 10.211.55.3  LOCAL Nmap SYN Scan
1000011 sev=2 10.211.55.3 -> 10.211.55.1  LOCAL Nmap NULL Scan
1000012 sev=2 10.211.55.3 -> 10.211.55.1  LOCAL Nmap FIN Scan
1000013 sev=2 10.211.55.3 -> 10.211.55.1  LOCAL Nmap XMAS Scan
1000020 sev=1 10.211.55.2 -> 10.211.55.3  LOCAL SSH Brute-force Attempt
1000021 sev=1 10.211.55.2 -> 10.211.55.3  LOCAL SSH Brute-force Tool Banner (libssh)
1000022 sev=1 10.211.55.2 -> 10.211.55.3  LOCAL SSH Brute-force Tool Banner (paramiko)
1000030 sev=1 10.211.55.2 -> 10.211.55.3  LOCAL Path Traversal ../ in URI
1000031 sev=1 10.211.55.2 -> 10.211.55.3  LOCAL Path Traversal encoded %2e%2e
1000032 sev=1 10.211.55.2 -> 10.211.55.3  LOCAL Path Traversal encoded ..%2f
1000033 sev=1 10.211.55.2 -> 10.211.55.3  LOCAL Path Traversal /etc/passwd access
```

## 02_rule_manager.sh

```bash
sudo ./scripts/02_rule_manager.sh --install          # chép local.rules vào /etc/suricata/rules, thêm vào rule-files
sudo ./scripts/02_rule_manager.sh --list             # liệt kê SID / trạng thái / priority / msg
sudo ./scripts/02_rule_manager.sh --show 1000010     # xem nội dung một luật
sudo ./scripts/02_rule_manager.sh --add "<rule>"     # thêm luật (sai cú pháp bị từ chối)
sudo ./scripts/02_rule_manager.sh --disable 1000001  # tắt luật (comment bằng sed)
sudo ./scripts/02_rule_manager.sh --enable 1000001   # bật lại luật
sudo ./scripts/02_rule_manager.sh --reload           # suricata -T -> lỗi thì khôi phục, đúng thì reload
```

Cơ chế an toàn:

- Trước mỗi lần sửa, script sao lưu file luật ra `local.rules.bak`.
- `--add`, `--enable` và `--disable` chạy `suricata -T -S local.rules` ngay sau khi sửa. Nếu lỗi thì khôi phục file `.bak`.
- `--reload` cũng chạy `suricata -T` trước. Nếu file đang lỗi (ví dụ do sửa tay) thì khôi phục bản hợp lệ gần nhất và không reload. Nếu đúng thì reload bằng `suricatasc -c reload-rules` (dự phòng: `systemctl reload suricata`).
- `--add` kiểm tra luật có `msg`, có `sid`, SID nằm trong dải 1000000–1999999 và chưa tồn tại.
- Mọi thao tác được ghi vào `/var/log/suricata_rule_manager.log`.

Ví dụ thêm luật sai cú pháp:

```
$ sudo ./scripts/02_rule_manager.sh --add 'alert tcp any any -> any any (msg:"LOCAL bad"; foo:1; sid:1000041; rev:1;)'
[+] Đã thêm luật SID 1000041, đang kiểm tra cú pháp...
[-] suricata -T báo lỗi:
    E: detect-parse: unknown rule keyword 'foo'.
[!] Đã khôi phục file luật từ backup: /etc/suricata/rules/local.rules.bak
[-] Luật bị từ chối.
```

## Kiểm thử

```bash
sudo ./tests/test_rules.sh             # 26 test: cú pháp, dải SID, threshold, mọi lệnh của 02_rule_manager.sh
sudo ./tests/test_rules.sh --live 180  # chờ Attacker tấn công, kiểm tra 4 nhóm luật có alert trong eve.json
```

`test_rules.sh` chạy các lệnh của `02_rule_manager.sh` trên một bản sao tạm của file luật, nên không ảnh hưởng tới `/etc/suricata/rules/local.rules`.
