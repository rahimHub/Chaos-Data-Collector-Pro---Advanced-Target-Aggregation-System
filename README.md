# Chaos-Data-Collector-Pro---Advanced-Target-Aggregation-System
این اسکریپت در واقع یک Data Aggregator است که داده‌های عمومی مربوط به دامنه‌ها و ساب‌دامین‌ها را جمع‌آوری می‌کند - ابزاری مفید برای مرحله reconnaissance در تست نفوذ

# 🔍 Chaos Data Collector Pro

**Advanced Target Aggregation System for Security Reconnaissance**

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/security-tools/chaos-collector)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-yellow.svg)](https://www.python.org/)
[![Bash 5.0+](https://img.shields.io/badge/bash-5.0+-brightgreen.svg)](https://www.gnu.org/software/bash/)

## 📖 Overview

Chaos Data Collector Pro is an enterprise-grade tool for aggregating and processing public domain datasets from Project Discovery's Chaos platform. Designed for security professionals, penetration testers, and bug bounty hunters, it automates the collection and preparation of reconnaissance data for security assessments.

## ✨ Features

### 🚀 **Core Capabilities**
- **Automated Dataset Collection**: Downloads and processes all Chaos datasets
- **Parallel Processing**: Multi-threaded downloads for maximum performance
- **Resume Support**: Continue interrupted downloads seamlessly
- **Domain Validation**: Filters invalid domains and false positives
- **Deduplication**: Removes duplicate entries across all datasets

### 📊 **Intelligent Processing**
- **TLD Analysis**: Top-level domain distribution statistics
- **Domain Pattern Extraction**: Wildcard pattern generation for scanning
- **Data Validation**: Format validation and cleanup
- **Statistics Generation**: Detailed collection metrics and reports

### 🛡️ **Enterprise Features**
- **Configurable**: YAML/JSON configuration support
- **Logging**: Comprehensive logging with multiple verbosity levels
- **Backup System**: Automatic backup of previous collections
- **Compression**: Optional output compression for storage efficiency
- **Proxy Support**: HTTP/HTTPS proxy configuration

### 📈 **Output Formats**
- **Aggregated Domains**: Clean, deduplicated domain list
- **TLD Distribution**: Frequency analysis of top-level domains
- **Domain Patterns**: Wildcard patterns for mass scanning
- **JSON Summary**: Machine-readable collection statistics
- **Compressed Archives**: Tar.gz archives for easy sharing

## 🏗️ Architecture

Chaos Collector Pro Architecture
├── Data Collection Layer
│ ├── HTTP Downloader (with retry logic)
│ ├── Parallel Processing Engine
│ └── Resume System
├── Processing Layer
│ ├── Domain Validator
│ ├── Deduplication Engine
│ ├── TLD Analyzer
│ └── Pattern Generator
├── Output Layer
│ ├── Multi-format Exporter
│ ├── Compression Module
│ └── Report Generator
└── Management Layer
├── Configuration Manager
├── Logging System
└── Statistics Tracker

--------------------------------------------------------------------------------
## 📦 Installation

### Prerequisites

#### For Bash Version:
```bash
# Debian/Ubuntu
sudo apt-get install wget unzip jq curl

# RHEL/CentOS
sudo yum install wget unzip jq curl

# macOS
brew install wget unzip jq curl


-------------------------------------------------------------------------------

For Python Version:
bash
pip install -r requirements.txt
Quick Install
bash
# Clone repository
git clone https://github.com/security-tools/chaos-collector-pro.git
cd chaos-collector-pro

# Make executable
chmod +x chaos-collector.sh chaos-collector.py

# Run basic collection
./chaos-collector.sh
Docker Installation
bash
# Build Docker image
docker build -t chaos-collector .

# Run container
docker run -v $(pwd)/data:/data chaos-collector -o /data
🚀 Usage
Basic Collection
bash
# Bash version
./chaos-collector.sh

# Python version
python chaos-collector.py
Advanced Collection
bash
# High-performance collection
./chaos-collector.sh \
  --parallel 10 \
  --retries 5 \
  --timeout 60 \
  --output-dir /data/recon

# Resume interrupted download
./chaos-collector.sh --resume --parallel 8

# Custom configuration
./chaos-collector.sh \
  -c ~/.chaos/config.yaml \
  --no-cleanup \
  --verbose
Integration with Security Tools
bash
# Feed domains to amass
./chaos-collector.sh -o domains
amass enum -df domains/aggregated_targets.txt

# Feed to masscan
./chaos-collector.sh --output-file targets.txt
masscan -iL targets.txt -p1-65535 --rate 1000

# Use with nuclei
nuclei -l domains/aggregated_targets.txt -t ~/nuclei-templates/
⚙️ Configuration
Configuration File (~/.chaos_collector.conf)
bash
# Chaos Collector Configuration
OUTPUT_DIR="chaos_data"
OUTPUT_FILE="aggregated_targets.txt"
INDEX_URL="https://chaos-data.projectdiscovery.io/index.json"
PARALLEL_DOWNLOADS=5
VALIDATE_DOMAINS=true
REMOVE_DUPLICATES=true
ENABLE_COMPRESSION=true
MAX_RETRIES=3
TIMEOUT=30
USER_AGENT="Chaos-Collector-Pro/2.0"
Environment Variables
bash
export CHAOS_OUTPUT_DIR="/opt/recon/data"
export CHAOS_PARALLEL=10
export CHAOS_MAX_RETRIES=5
export CHAOS_PROXY="http://proxy:8080"
📊 Output Structure
******************************************************************************************************************
chaos_data/
├── aggregated_targets.txt          # Main domain list
├── tld_distribution.txt           # TLD frequency analysis
├── domain_distribution.txt        # Domain frequency analysis
├── wildcard_patterns.txt          # Wildcard patterns for scanning
├── collection_summary.json        # JSON statistics
├── chaos_data_20240115.tar.gz     # Compressed archive
└── chaos_collector_20240115.log   # Log file
🔄 Automation
Cron Job for Daily Updates
******************************************************************************************************************
# Daily update at 2 AM
0 2 * * * /opt/chaos-collector/chaos-collector.sh --quiet --output-dir /data/chaos
Systemd Service
ini
# /etc/systemd/system/chaos-collector.service
[Unit]
Description=Chaos Data Collector Pro
After=network.target

[Service]
Type=oneshot
User=security
ExecStart=/opt/chaos-collector/chaos-collector.sh --quiet
WorkingDirectory=/data/chaos

[Install]
WantedBy=multi-user.target
🎯 Use Cases
1. Bug Bounty Programs
*****************************************************************************
# Collect fresh targets daily
./chaos-collector.sh --output-dir ~/bugbounty/targets
./process_targets.sh ~/bugbounty/targets/aggregated_targets.txt
2. Penetration Testing
*****************************************************************************
# Collect targets for engagement
./chaos-collector.sh -o client_engagement
# Use with other recon tools
cat client_engagement/aggregated_targets.txt | httpx -silent | nuclei -t ~/nuclei-templates/
3. Security Monitoring
*******************************************************************************
# Daily monitoring baseline
./chaos-collector.sh --resume --output-dir /var/log/chaos
# Compare with previous day
diff /var/log/chaos/$(date +%Y%m%d)/aggregated_targets.txt \
     /var/log/chaos/$(date -d yesterday +%Y%m%d)/aggregated_targets.txt
4. Research & Analysis
********************************************************************************
# Collect data for research
./chaos-collector.sh --no-cleanup --verbose
# Analyze TLD distribution
cat chaos_data/tld_distribution.txt | head -20
🔧 Advanced Features
Custom Index Sources
********************************************************************************
# Use custom index
./chaos-collector.sh -u "https://internal.chaos.example.com/index.json"

# Multiple sources
for source in $(cat sources.txt); do
    ./chaos-collector.sh -u "$source" -o "data_$(basename $source)"
done
Integration with API
*********************************************************************************
# POST results to API
./chaos-collector.sh --quiet | \
    curl -X POST -H "Content-Type: application/json" \
    -d @- https://api.security-platform.com/domains
Custom Processing Pipeline
**********************************************************************************
# Custom processing script
./chaos-collector.sh --no-deduplication --no-validation | \
    ./custom_filter.py | \
    sort -u > filtered_targets.txt
📈 Performance
Mode	Time (approx)	Memory	CPU	Output Size
Basic	5-10 minutes	< 100MB	Low	50-100MB
Parallel (10)	2-5 minutes	< 200MB	Medium	50-100MB
Full Validation	10-15 minutes	< 300MB	High	30-80MB
Dry Run	< 1 minute	< 50MB	Low	0MB
🔒 Security Considerations
Data Privacy
Chaos datasets contain publicly available information only

No proprietary or sensitive data is collected

Output files should be stored securely

Respect data usage policies and terms of service

Ethical Use
**********************************************************************************
# Always verify you have permission to scan targets
# Use responsibly and in compliance with applicable laws
# Implement rate limiting when testing live systems
Safety Features
Rate limiting built into downloader

Timeout controls for slow connections

Validation to prevent malformed data

Safe file handling and cleanup

🤝 Contributing
We welcome contributions! Please see our Contributing Guidelines.

Development Setup
--------------------------------------------------------------------------------
git clone https://github.com/security-tools/chaos-collector-pro.git
cd chaos-collector-pro

# Setup development environment
python -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt

# Run tests
./run_tests.sh
📚 Documentation
User Guide - Complete usage instructions

API Documentation - Integration guide

Troubleshooting - Common issues and solutions

Case Studies - Real-world usage examples

📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

🙏 Acknowledgments
Project Discovery for the Chaos dataset

Open-source security community

Contributors and testers

📞 Support
Issues: GitHub Issues

Discussions: GitHub Discussions

Security Issues: security@example.com

<div align="center"> <strong>Built for the security community by security professionals</strong><br> Use responsibly and ethically </div> ```
🎯 بهبودهای اصلی انجام شده:
1. ساختار حرفه‌ای
مدیریت خطای پیشرفته

سیستم لاگ‌گیری جامع

پشتیبانی از تنظیمات و پیکربندی

مدیریت نشست و حالت resume

2. عملکرد بهبود یافته
دانلود موازی با کنترل نخ

اعتبارسنجی دامنه‌ها

حذف تکراری‌های هوشمند

تولید گزارش‌های آماری

3. ویژگی‌های امنیتی
اعتبارسنجی SSL

کنترل نرخ درخواست

فیلتر داده‌های نامعتبر

پشتیبانی از پراکسی

4. خروجی‌های متنوع
لیست دامنه‌های خالص

آمار توزیع TLD

الگوهای Wildcard برای اسکن

گزارش‌های JSON و خلاصه اجرایی

5. قابلیت اتوماسیون
پشتیبانی از cron jobs

حالت dry-run برای تست

قابلیت یکپارچه‌سازی با ابزارهای دیگر

سیستم backup خودکار
