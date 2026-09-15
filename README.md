# SOC Tier 1 Practice Lab

Lab cá nhân mô phỏng môi trường SOC: dựng hệ thống SIEM (Splunk), 
tạo kịch bản tấn công, viết SPL để phát hiện, và ghi report theo 
quy trình phân tích thật.

## Lab Setup
- Splunk Enterprise (Free license) - SIEM
- Windows 10 VM (victim) - Sysmon + Universal Forwarder
- Kali Linux VM (attacker)

## Cases đã thực hiện
- [Brute-force RDP Detection](reports/brute-force-rdp-detection.md)
- [Port Scan Detection](reports/port-scan-detection.md)
