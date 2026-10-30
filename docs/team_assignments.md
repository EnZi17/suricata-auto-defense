# Phân công Nhóm 12

## Trần Trung Việt

- Kiến trúc và cấu hình mô hình một máy ảo; namespace tấn công và interface giám sát.
- scripts/01_setup_suricata.sh, scripts/00_run_all.sh, scripts/lab_network.sh,
  scripts/configure_lab.py; cấu hình chung và service mạng lab.
- Tích hợp, kiểm thử toàn hệ thống, hướng dẫn cài đặt và thu thập minh chứng.
- tests/test_lab_config.py; phối hợp tests/test_defense_offline.sh với Thông.
- Khoảng 6 slide Architecture, Integration & Validation kèm speaker notes.

## Nguyễn Ngọc Thái

- rules/local.rules, scripts/02_rule_manager.sh, tests/test_rules.sh.
- attacker/simulate_attacks.sh: Ping, Nmap, SSH, Path Traversal và Run all.
- Chạy traffic bằng ip netns exec suricata-attacker; đích 10.203.0.1,
  nguồn 10.203.0.2. Phối hợp kiểm thử và giải thích các trường hợp báo giả.
- docs/rule_engine.md; khoảng 6 slide Rule Engine & Attack Simulation.

## Võ Minh Thông

- scripts/03_auto_defense.sh, config/suricata-defense.service, tests/test_block.sh.
- Đọc eve.json, whitelist, severity, UFW, chống chặn trùng, log, --unban và service.
- Phối hợp tests/test_defense_offline.sh với Việt; quản lý GitHub, review và merge.
- Soạn kịch bản demo 3 người, điều phối chạy thử và video dự phòng.
- Khoảng 6 slide Dynamic Defense & Demo kèm speaker notes.

Mỗi người thực hiện phần demo theo chức năng phụ trách. Luồng nghiệm thu:
tạo traffic → Suricata cảnh báo → UFW chặn IP → ghi log → --unban.
simulated traffic cần được kiểm tra với log để tránh khẳng định sai loại tấn công.
Script giả lập hiện chưa có nội dung; vẫn là đầu việc cần hoàn thiện của Thái.

Mã của Thái giữ nguyên theo commit 6ea5232. Module 03 của Thông chỉ bỏ lời gọi kênh thông báo đã loại khỏi phạm vi; giữ nguyên ALERT_COOLDOWN và logic UFW. File service gốc giữ nguyên; script cài đặt của Việt tạo drop-in đường dẫn triển khai trên máy Ubuntu.
