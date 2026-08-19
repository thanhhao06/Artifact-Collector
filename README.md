# Artifact Collector 2.0 (Forensic & Incident Response Suite)

> 🛡️ **Công cụ điều tra số & phản ứng sự cố (DFIR Triage Engine)** toàn diện, thu thập, phân tích và trực quan hóa hơn 17 nhóm bằng chứng số (Artifacts) trên Windows và Linux/WSL.  
> 👤 **Created by Azaki**

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20WSL-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active%20v2.0-brightgreen)

---

## 🌟 Các tính năng nổi bật (Key Features)

### 1. 📊 Báo Cáo Trực Quan Tương Tác Đỉnh Cao (`report.html`)
- **Visual Analytics Charts**: Biểu đồ phân bố mức độ nghiêm trọng mối đe dọa (Threat Severity) và Top tiến trình tiêu tốn RAM nhất.
- **⚡ Tìm kiếm toàn cục thông minh (Spotlight Search `Ctrl + K`)**: Gõ phím tắt `Ctrl + K` để tìm kiếm tức thì một IP, mã băm SHA256, PID hoặc từ khóa trên toàn bộ các file telemetry cùng lúc.
- **🔍 Cửa sổ soi chi tiết bản ghi (Record Inspector Modal)**: Bấm vào bất kỳ dòng nào trên bảng để xem chi tiết tất cả các trường dữ liệu và copy câu lệnh dài / mã băm.
- **Tương tác dữ liệu**: Bộ lọc nhanh, sắp xếp đa cột, phân trang, chuyển đổi giao diện Sáng/Tối (Dark/Light mode).
- **Độc lập 100% (Air-gapped)**: Không cần kết nối internet hay thư viện ngoài (CDN).

### 2. 📑 Xuất Báo Cáo Excel Đa Tầng (`forensic_report.xls`)
- Tự động xuất file Excel đầy đủ các Sheet: `Executive Summary`, `Threat Findings`, `Master Timeline`, `Processes`, `Network Sockets`, `Persistence`, `PowerShell History`, `Execution History`, `Firewall Rules`, `Kernel Drivers`, `RDP History`, `Services`, `USB History`, `Browser History`, v.v. kèm đánh dấu màu sắc cảnh báo.

### 3. 📦 Hơn 17 Module Bằng Chứng Số Chuyên Sâu
1. **Tiến trình & Cây phân cấp (`processes`)**: PPID/PID, mã băm SHA-256 nhị phân, RAM/CPU, phát hiện thực thi từ Temp/Downloads.
2. **Lịch sử Terminal PowerShell (`powershell_history`)**: Quét `ConsoleHost_history.txt` của mọi user, phát hiện lệnh tải mã độc, IEX, bypass, Mimikatz.
3. **Bằng chứng chạy file trong quá khứ (`execution_history`)**: Tự động giải mã **UserAssist ROT13** trong Registry và **Prefetch**, lấy số lần chạy (Run count) và thời điểm chạy gần nhất (ngay cả khi file `.exe` đã bị xóa).
4. **Mạng, DNS & ARP (`network`)**: Bảng cổng socket đang mở, DNS Resolver cache (`ipconfig /displaydns`), bảng ARP (`arp -a`).
5. **Quy tắc Tường lửa (`firewall_rules`)**: Đánh giá các cổng nhạy cảm đang mở ra ngoài (RDP 3389, SMB 445, WinRM 5985, SSH 22...).
6. **Kernel Drivers (`system_drivers`)**: Danh sách driver nạp vào nhân kernel, ngày biên dịch (Compile Date) và đường dẫn file `.sys` để phát hiện Rootkit / BYOVD.
7. **Khởi động cùng hệ thống (`persistence`)**: Registry Run/RunOnce (HKCU, HKLM, WOW6432Node), Startup folders, Winlogon, IFEO debugger hijacks.
8. **Lịch sử Kết nối từ xa (`rdp_history`)**: Lịch sử RDP MRU, máy chủ RDP đã lưu, PuTTY SSH, FileZilla FTP, AnyDesk.
9. **Nhật ký Sự kiện Bảo mật (`event_logs`)**: Event ID 4624/4625 (Đăng nhập), 4688 (Chạy tiến trình), 7045 (Cài service), 1102 (Xóa log).
10. **Lịch sử Thiết bị USB (`usb_history`)**: Quét `USBSTOR` và `MountedDevices` (Tên thiết bị, Vendor, Serial, Ký tự ổ đĩa).
11. **Lịch sử Trình duyệt & Tải về (`browser_history`)**: Chrome, Edge, Firefox, Brave, Opera, Opera GX, Vivaldi trên mọi user profile.
12. **Tác vụ Lên lịch (`scheduled_tasks`)**: Danh sách scheduled tasks và cron jobs.
13. **Dịch vụ Hệ thống (`services`)**: Quét phát hiện lỗ hổng Unquoted Service Path (CWE-428).
14. **Phần mềm Đã cài đặt (`installed_apps`)**: Danh mục toàn bộ ứng dụng cài trên máy.
15. **Tài khoản & Phân quyền (`users`)**: Tài khoản người dùng, nhóm Administrators/Sudo.
16. **Tập tin Truy cập Gần đây (`recent_files`)**: Recent Files & LNK shortcuts.
17. **Chuỗi Bằng chứng Pháp lý (`manifest.json` & `checksums.sha256`)**: Toàn bộ dữ liệu được băm mã hóa SHA-256 và MD5.

---

## 🚀 Hướng dẫn Cài đặt & Sử dụng (Usage Guide)

### 1. Cài đặt môi trường

Cài đặt các thư viện cơ bản:
```bash
pip install -r requirements.txt
```

Nếu phân tích ảnh đĩa ngoại tuyến (`.E01`, `.dd`, `.raw`), cài thêm:
```bash
pip install -r requirements-image.txt
```

---

### 2. Cách chạy công cụ

#### 🖥️ Cách 1: Giao diện Đồ họa Desktop GUI (Khuyên dùng)
Mở giao diện trực quan Cyberpunk:
```bash
python main.py --gui
# hoặc
python gui.py
```
- Chọn chế độ **Live Host** hoặc **Offline Image**.
- Tích chọn các Module cần thu thập.
- Điền Case ID, Examiner và bấm **Start Triage**.

---

#### ⚡ Cách 2: Chạy trực tiếp dòng lệnh CLI (Windows / Linux / WSL)

**Thu thập toàn diện trên máy hiện tại:**
```bash
python main.py --mode local
```

**Tùy chỉnh thư mục xuất và thông tin vụ việc:**
```bash
python main.py --mode local --output cases/case_01 --case-id CASE-2026-001 --examiner "Azaki"
```

**Chỉ chạy các module chỉ định:**
```bash
python main.py --mode local --modules system,processes,powershell,execution,network,persistence,firewall,drivers
```

---

#### 💽 Cách 3: Phân tích file ảnh đĩa Disk Image (.E01, .dd, .raw)
```bash
python main.py --mode file --image /path/to/evidence.E01 --output cases/disk_analysis --case-id CASE-DISK-01
```

---

## 📁 Cấu trúc Thư mục Kết quả (Output Structure)

Mỗi lần chạy sẽ tạo một thư mục chứa đầy đủ 50 file định dạng JSON, CSV, Excel và HTML:

```txt
output/
└── local_triage_YYYYMMDD_HHMMSS/
    ├── report.html                    # Dashboard HTML tương tác thông minh (Search Ctrl+K, Charts, Inspector)
    ├── forensic_report.xls            # Báo cáo Excel đa sheet tổng hợp hoàn chỉnh
    ├── summary_report.txt             # Báo cáo tóm tắt Executive text
    ├── manifest.json                  # Chứng thực pháp lý & bảng mã băm SHA256/MD5
    ├── checksums.sha256               # File kiểm tra toàn vẹn băm chuẩn Linux
    ├── findings.json / .csv           # Mối đe dọa cảnh báo chuẩn MITRE ATT&CK
    ├── timeline.json / .csv           # Dòng thời gian điều tra tổng hợp (Master Timeline)
    ├── system_info.json               # Cấu hình phần cứng & hệ điều hành
    ├── processes.json / .csv          # Tiến trình đang chạy, cây phân cấp & mã SHA-256
    ├── powershell_history.json / .csv # Lịch sử câu lệnh Terminal / PSReadLine
    ├── execution_history.json / .csv  # Bằng chứng thực thi file UserAssist ROT13 & Prefetch
    ├── network_connections.json / .csv# Socket mạng đang mở & cờ rủi ro
    ├── firewall_rules.json / .csv     # Quy tắc tường lửa & cổng mở nhạy cảm
    ├── system_drivers.json / .csv     # Danh sách Kernel Drivers & ngày biên dịch
    ├── rdp_history.json / .csv        # Lịch sử kết nối Remote Desktop, SSH, FTP
    ├── persistence.json / .csv        # Autoruns, Registry Run, IFEO hijacks
    ├── event_logs.json / .csv         # Windows Security Event Logs
    ├── usb_history.json / .csv        # Lịch sử cắm USB Storage
    ├── browser_history.json / .csv    # Lịch sử duyệt web (Chrome, Edge, Firefox, Brave...)
    ├── browser_downloads.json / .csv  # Lịch sử các file đã tải về
    ├── scheduled_tasks.json / .csv    # Tác vụ định kỳ Scheduled Tasks
    ├── services.json / .csv           # Dịch vụ hệ thống & cảnh báo Unquoted Path
    ├── installed_apps.json / .csv     # Danh mục phần mềm đã cài đặt
    ├── users.json / .csv              # Tài khoản người dùng & quyền Quản trị
    └── recent_files.json / .csv       # Danh sách file và shortcut mở gần đây
```

---

## ⚖️ Disclaimer
Công cụ này được thiết kế và phát triển phục vụ mục đích nghiên cứu, học tập, điều tra số (Digital Forensics) và phản ứng sự cố an toàn thông tin (Incident Response) trên các hệ thống được cấp phép.
