# ☁️ Cloud Misconfiguration Scanner

A powerful, production-ready security tool that detects exposed S3 buckets and Azure blobs without requiring authentication. Perfect for security assessments and finding publicly accessible cloud storage misconfigurations.

## 🎯 Features

- **🔍 Automatic Cloud Discovery** - Finds S3 buckets and Azure containers associated with a domain
  - Pattern-based bucket name generation
  - DNS CNAME record analysis  
  - Public search integration
  
- **⚠️ Vulnerability Detection**
  - S3 public access checking (HTTP, list_objects, put_object)
  - Azure blob public access verification
  - Bucket policy analysis
  - Encryption and versioning checks
  - SAS token detection

- **📊 Risk Assessment**
  - Automatic risk scoring (0-100 scale)
  - Severity classification (CRITICAL, HIGH, MEDIUM, LOW)
  - Comprehensive vulnerability counts

- **📄 Professional Reports**
  - Beautiful HTML reports with color-coded risk indicators
  - PDF reports ready for distribution
  - Security recommendations included
  - Exportable findings

## 📋 What It Tests

### Amazon S3
- ✅ Public HTTP access
- ✅ List objects (read permission without auth)
- ✅ Put objects (write permission)
- ✅ Bucket policies for public access
- ✅ Server-side encryption status
- ✅ Versioning configuration
- ✅ Block Public Access settings

### Microsoft Azure
- ✅ Public HTTP access
- ✅ Blob container listing
- ✅ SAS token exposure in URLs
- ✅ Public access level settings

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip (Python package manager)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/cloud_misconfiguration_scanner.git
cd cloud_misconfiguration_scanner
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Verify installation**
```bash
python test_components.py
```

### Basic Usage

**Scan a domain:**
```bash
python main.py example.com
```

**Reports are automatically saved to `output/` folder**

## 📖 Usage Guide

### Command Line Options

```bash
python main.py DOMAIN [OPTIONS]
```

#### Arguments
- `DOMAIN` - Target domain or IP to scan (required)

#### Options
- `--format, -f {html,pdf,both}` - Report format (default: both)
- `--output-dir, -o PATH` - Output directory for reports (default: output)
- `--verbose, -v` - Enable verbose output for detailed discovery info
- `-h, --help` - Show help message

### Examples

**1. Basic scan with HTML and PDF reports**
```bash
python main.py example.com
```

**2. Generate HTML report only**
```bash
python main.py example.com --format html
```

**3. Generate PDF report only**
```bash
python main.py example.com --format pdf
```

**4. Verbose mode to see all discovery steps**
```bash
python main.py example.com --verbose
```

**5. Save reports to custom location**
```bash
python main.py example.com --output-dir ./my_reports
```

**6. Combine multiple options**
```bash
python main.py example.com --format both --verbose --output-dir ./security_reports
```

**7. Scan multiple domains**
```bash
python main.py example.com
python main.py test.io
python main.py myapp.org
```

## 📂 Project Structure

```
cloud_misconfiguration_scanner/
├── main.py                          # CLI entry point
├── test_components.py               # Component test suite
├── requirements.txt                 # Python dependencies
├── .env.example                     # Environment configuration template
├── .gitignore                       # Git ignore rules
├── README.md                        # This file
├── QUICK_START.md                   # Quick start guide
├── HOW_TO_RUN.md                    # Detailed usage guide
│
├── scanners/                        # Scanning modules
│   ├── __init__.py
│   ├── cloud_discoverer.py          # Cloud bucket/blob discovery engine
│   ├── s3_scanner.py                # S3 vulnerability scanner
│   └── azure_scanner.py             # Azure vulnerability scanner
│
├── utils/                           # Utility modules
│   ├── __init__.py
│   └── risk_calculator.py           # Risk scoring and recommendations
│
├── report_templates/                # Report generation
│   ├── html_report.html             # HTML template (Jinja2)
│   └── pdf_report.py                # PDF generator (ReportLab)
│
└── output/                          # Generated reports directory
    ├── report_*.html
    └── report_*.pdf
```

## 🔄 How It Works

### Scanning Process (30-60 seconds per domain)

1. **Phase 1: Discovery** (~10-15 seconds)
   - Generates common S3 bucket name patterns
   - Generates common Azure container name patterns  
   - Queries DNS for CNAME records
   - Searches public indexes

2. **Phase 2: S3 Scanning** (~10-20 seconds)
   - Tests HTTP public access
   - Attempts to list objects
   - Tests write permissions
   - Checks bucket policies

3. **Phase 3: Azure Scanning** (~5-15 seconds)
   - Tests HTTP public access
   - Attempts to list blobs
   - Searches for SAS tokens

4. **Phase 4: Risk Calculation** (<1 second)
   - Scores vulnerabilities
   - Generates recommendations

5. **Phase 5: Report Generation** (<2 seconds)
   - Creates HTML report
   - Creates PDF report
   - Saves to output directory

## 📊 Report Output

### HTML Report Contents
- **Header** - Domain name, timestamp, risk badge
- **Metadata** - Domain, scan time, risk score
- **Statistics** - Vulnerability counts by severity
- **S3 Vulnerabilities** - Detailed table of findings
- **Azure Vulnerabilities** - Container-specific issues
- **Recommendations** - Specific security remediation steps

### PDF Report Contents
- **Title Page** - Overall risk summary
- **Metadata Table** - Domain and scan information
- **Statistics** - Vulnerability breakdown
- **Detailed Findings** - Per-resource vulnerability details
- **Recommendations** - Security fixes needed

## 🛡️ Vulnerability Categories

### S3 Findings
- **CRITICAL** - Bucket is publicly writable (anyone can upload)
- **HIGH** - Bucket allows listing objects + publicly accessible
- **MEDIUM** - Bucket has public read access or public policy
- **LOW** - Missing encryption or other security configurations

### Azure Findings
- **HIGH** - Public access level set or SAS token exposed
- **MEDIUM** - Container allows listing or is publicly accessible
- **LOW** - Other access concerns

## ⚙️ Configuration

### Optional Environment Variables

Create a `.env` file from `.env.example`:

```bash
cp .env.example .env
```

Configurable options:
```env
LOG_LEVEL=INFO
REQUEST_TIMEOUT=10
ENABLE_DNS_DISCOVERY=true
ENABLE_SEARCH_DISCOVERY=true
OUTPUT_DIRECTORY=./output
```

## 🧪 Testing

Run the component test suite:

```bash
python test_components.py
```

This tests:
- ✓ Cloud discovery module
- ✓ Risk calculator
- ✓ HTML report generation
- ✓ PDF report generation
- ✓ Sample report files

## 📊 Example Scan Results

### Scan with No Vulnerabilities
```
======================================================================
CLOUD MISCONFIGURATION SCANNER - SUMMARY REPORT
======================================================================

Target Domain: google.com
Scan Time: 2026-06-05 14:08:00

[DISCOVERY PHASE]
  S3 Buckets: 10 candidates tested
  Azure Accounts: 9 candidates tested

[VULNERABILITY SUMMARY]
  Total Vulnerabilities: 0
  Critical: 0
  High: 0
  Medium: 0
  Low: 0

[RISK ASSESSMENT]
  Overall Risk Level: LOW
  Risk Score: 0/100

✓ Scan complete - No vulnerabilities found
```

### Scan with Vulnerabilities
```
[VULNERABILITY SUMMARY]
  Total Vulnerabilities: 3
  Critical: 1
  High: 2
  Medium: 0
  Low: 0

[S3 VULNERABILITIES]
  • bucket-data [CRITICAL]
    - BUCKET_WRITE_ACCESSIBLE

[AZURE VULNERABILITIES]
  • myaccount/files [HIGH]
    - BLOB_LIST_ACCESSIBLE

[RISK ASSESSMENT]
  Overall Risk Level: CRITICAL
  Risk Score: 95/100
```

## 🔒 Security Considerations

- ✅ **No credentials needed** - Works on public infrastructure only
- ✅ **Read-only** - No modifications to any infrastructure
- ✅ **Safe** - Tests only publicly accessible endpoints
- ⚠️ **Legal** - Use only on domains/IPs you own or have permission to test
- 📋 **Results** - Shows ONLY publicly accessible misconfigurations

**Disclaimer**: Unauthorized access to computer systems is illegal. Use this tool only for authorized security testing.

## 📥 Dependencies

- `boto3` (≥1.34.0) - AWS S3 API client
- `requests` (≥2.31.0) - HTTP client
- `beautifulsoup4` (≥4.12.0) - HTML parsing
- `reportlab` (≥4.0.0) - PDF generation
- `jinja2` (≥3.1.0) - HTML template rendering
- `dnspython` (≥2.4.0) - DNS lookups

Install all with:
```bash
pip install -r requirements.txt
```

## 🐛 Troubleshooting

### No reports generated
- This means no vulnerabilities were found (good news!)
- Use `--verbose` to see all discovery details
- Ensure the domain has actual cloud infrastructure

### Slow scanning
- Normal scan time is 30-60 seconds
- Discovery phase includes DNS and search queries
- Network speed affects results

### Import errors
```bash
# Reinstall all dependencies
pip install -r requirements.txt --upgrade
```

### Reports not saving
- Check that `output/` directory exists (created automatically)
- Verify write permissions to the directory
- Ensure sufficient disk space

## 📝 Command Reference

```bash
# Basic scan
python main.py yourdomain.com

# HTML only
python main.py yourdomain.com --format html

# PDF only
python main.py yourdomain.com --format pdf

# Custom output
python main.py yourdomain.com --output-dir ./reports

# Verbose output
python main.py yourdomain.com --verbose

# All options combined
python main.py yourdomain.com --format both --output-dir ./reports --verbose

# Test components
python test_components.py

# View help
python main.py --help
```

## 🎯 Use Cases

- **Security Audits** - Assess cloud storage configurations
- **Compliance Testing** - Verify security controls
- **Infrastructure Review** - Find exposed cloud resources
- **Threat Assessment** - Identify attack surface
- **Risk Management** - Document security findings

## 📚 Additional Resources

- [QUICK_START.md](QUICK_START.md) - Quick start guide
- [HOW_TO_RUN.md](HOW_TO_RUN.md) - Detailed usage guide
- [AWS S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security.html)
- [Azure Storage Security](https://learn.microsoft.com/en-us/azure/storage/common/storage-security-overview)

## 🤝 Contributing

Contributions welcome! Feel free to submit issues and enhancement requests.

## 📄 License

MIT License - See LICENSE file for details

## 👨‍💻 Author

Created as a security testing tool for cloud infrastructure assessment.

---

**⚠️ Important**: This tool is designed for authorized security testing only. Ensure you have proper authorization before scanning any infrastructure.

**Questions?** Check [HOW_TO_RUN.md](HOW_TO_RUN.md) for detailed documentation.
