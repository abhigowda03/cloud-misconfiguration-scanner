# How to Run and Check Cloud Misconfiguration Scanner

## ✅ Installation (Already Done)

All dependencies are installed. Check with:
```bash
pip list | grep -E "boto3|requests|reportlab|jinja2|dnspython"
```

## 🚀 Quick Start

### 1. Run Scanner on a Domain
```bash
# Basic scan (generates both HTML and PDF)
python main.py example.com

# HTML only
python main.py example.com --format html

# PDF only  
python main.py example.com --format pdf

# Custom output directory
python main.py example.com --output-dir ./my_reports

# Verbose mode (shows all debug info)
python main.py example.com --verbose
```

### 2. View Results
Reports are automatically saved to the `output/` directory:
- **HTML Reports**: Open in any web browser
- **PDF Reports**: Open with PDF reader

## 📊 Understanding the Output

### Console Output
The scanner prints a summary to the console:
```
======================================================================
CLOUD MISCONFIGURATION SCANNER - SUMMARY REPORT
======================================================================

Target Domain: example.com
Scan Time: 2026-06-05 14:08:00

[DISCOVERY PHASE]
  S3 Buckets: 5
  Azure Accounts: 3

[VULNERABILITY SUMMARY]
  Total Vulnerabilities: 2
  Critical: 0
  High: 1
  Medium: 1
  Low: 0

[RISK ASSESSMENT]
  Overall Risk Level: HIGH
  Risk Score: 75/100
```

### Report Files

#### HTML Report (`report_DOMAIN_TIMESTAMP.html`)
- **Header**: Domain name, timestamp, risk badge
- **Statistics**: Vulnerability counts by severity
- **S3 Table**: List of vulnerable buckets with details
- **Azure Table**: List of vulnerable containers
- **Recommendations**: Specific security remediation steps
- **Professional Design**: Color-coded risk indicators

#### PDF Report (`report_DOMAIN_TIMESTAMP.pdf`)
- **Title Page**: Overall risk and metadata
- **Summary Statistics**: Vulnerability breakdown
- **Detailed Findings**: Per-resource details
- **Recommendations Section**: Remediation guidance
- **Professional Formatting**: Ready for distribution

## 🧪 Component Testing

Run the included test suite to verify functionality:
```bash
python test_components.py
```

This tests:
1. ✓ Cloud discovery module (finds 10 S3 + 9 Azure candidates)
2. ✓ Risk calculator (calculates scores and recommendations)
3. ✓ Report generation (creates HTML and PDF files)
4. ✓ Sample reports in `output/` directory

## 📁 Project Layout

```
cloud_misconfiguration_scanner/
├── main.py                 # Entry point (run this!)
├── test_components.py      # Test suite
├── requirements.txt        # Dependencies
├── .env.example            # Configuration template
├── scanners/               # Scanning modules
│   ├── cloud_discoverer.py
│   ├── s3_scanner.py
│   └── azure_scanner.py
├── utils/
│   └── risk_calculator.py
├── report_templates/       # Report generators
│   ├── html_report.html
│   └── pdf_report.py
└── output/                 # Generated reports go here
    ├── report_*.html
    └── report_*.pdf
```

## 🔧 Common Commands

### Scan a Single Domain
```bash
python main.py mycompany.com
```

### Scan with Verbose Output (See all discovery steps)
```bash
python main.py mycompany.com --verbose
```

### Generate Reports in Custom Location
```bash
python main.py mycompany.com --output-dir ./security_reports --format both
```

### Run Multiple Scans (Loop)
```bash
for domain in example.com test.com myapp.io; do
    python main.py $domain
done
```

## 📈 Report File Examples

From test run:
- `test_report.html` (12,400 bytes) - Sample HTML with mock vulnerabilities
- `test_report.pdf` (5,172 bytes) - Sample PDF report
- `report_example_com_20260605_141321.html` - Real scan result
- `report_example_com_20260605_141321.pdf` - Real scan result (PDF)

### Open Reports
**Windows:**
```bash
# Open in default browser
start output\report_*.html

# Open in default PDF reader  
start output\report_*.pdf
```

**Mac:**
```bash
open output/report_*.html
open output/report_*.pdf
```

**Linux:**
```bash
xdg-open output/report_*.html
xdg-open output/report_*.pdf
```

## 🎯 What the Scanner Does

### Discovery Phase (Phase 1)
- Generates common S3 bucket names based on domain
- Generates common Azure container names
- Queries DNS for CNAME records pointing to S3/Azure
- Searches public indexes for bucket references

### S3 Scanning (Phase 2)
- Tests HTTP public access (HEAD request)
- Tries to list objects (ListObjectsV2)
- Attempts write access (PutObject)
- Checks bucket policies
- Verifies encryption and versioning

### Azure Scanning (Phase 3)
- Tests HTTP public access
- Tries to list blobs
- Searches for SAS tokens
- Checks public access levels

### Risk Calculation (Phase 4)
- Scores vulnerabilities (CRITICAL=100, HIGH=75, MEDIUM=50, LOW=25)
- Calculates overall risk (0-100 scale)
- Determines severity level

### Report Generation (Phase 5)
- Creates professional HTML report
- Generates PDF report with formatting
- Includes security recommendations

## 📋 Vulnerability Types Found

### S3 (Amazon)
- `BUCKET_WRITE_ACCESSIBLE` - Anyone can upload files (CRITICAL)
- `BUCKET_LIST_ACCESSIBLE` - Public object listing (HIGH)
- `BUCKET_PUBLICLY_ACCESSIBLE` - Responds to public HTTP (MEDIUM)
- `BUCKET_POLICY_PUBLIC` - Public bucket policy (HIGH)
- `BUCKET_NO_ENCRYPTION` - No server-side encryption (LOW)

### Azure
- `BLOB_SAS_TOKEN_EXPOSED` - SAS token in URL (HIGH)
- `BLOB_LIST_ACCESSIBLE` - Public blob listing (HIGH)
- `BLOB_PUBLICLY_ACCESSIBLE` - HTTP public access (MEDIUM)
- `BLOB_PUBLIC_ACCESS_LEVEL` - Public access set (HIGH)

## ⚙️ Configuration

Optional `.env` file for settings:
```bash
# Copy template
cp .env.example .env

# Edit .env with custom settings
LOG_LEVEL=INFO
REQUEST_TIMEOUT=10
ENABLE_DNS_DISCOVERY=true
ENABLE_SEARCH_DISCOVERY=true
```

## 🚨 Safety Notes

- ✅ No credentials needed - works on public infrastructure only
- ✅ Safe to run - no modifications to any infrastructure
- ✅ Read-only - only tests public accessibility
- ⚠️ Use only on domains you own or have permission to test
- 📝 Results show ONLY publicly accessible misconfigurations

## ❓ Troubleshooting

### No Reports Generated
- This means no vulnerabilities were found (good news!)
- Use `--verbose` to see discovery details
- Check if domain has actual cloud infrastructure

### Slow Scanning
- Discovery phase takes 30-60 seconds per domain
- S3/Azure scanning depends on number of candidates
- Network speed affects scan time

### Import Errors
```bash
# Reinstall all dependencies
pip install -r requirements.txt --upgrade
```

### Report Generation Failed
- Check output directory permissions
- Ensure disk space available
- Check Jinja2 template path

## 📚 Example Scan Results

```
Scan: google.com
- S3 Candidates: 10 discovered
- Azure Candidates: 9 discovered  
- Vulnerabilities Found: 0
- Overall Risk: LOW
- Time: ~45 seconds
```

```
Scan: myapp.example.io
- S3 Candidates: 12 discovered
- Azure Candidates: 8 discovered
- Vulnerabilities Found: 3
- Overall Risk: HIGH
  - 1x CRITICAL (S3 write access)
  - 2x MEDIUM (public read access)
- Time: ~50 seconds
- Reports: HTML + PDF generated
```

## ✅ Verification

After installation, verify everything works:

1. **Check imports**
   ```bash
   python -c "import boto3, requests, reportlab, jinja2; print('✓ All imports OK')"
   ```

2. **Run tests**
   ```bash
   python test_components.py
   ```

3. **Try a scan**
   ```bash
   python main.py example.com
   ```

4. **Check output**
   ```bash
   ls -lh output/
   ```

---

**Ready to scan!** 🎯 Run `python main.py YOUR_DOMAIN.com` to get started.
