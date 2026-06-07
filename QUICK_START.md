# 🎯 QUICK START GUIDE

## ✅ Status: Ready to Use

All dependencies are installed and all components are working.

## 🚀 Running the Scanner

### Option 1: Basic Scan (Easiest)
```bash
cd "c:\Users\abhip\Documents\PROGRAMS\projects\cloud_misconfiguration_scanner"
python main.py example.com
```

**What this does:**
- Discovers S3 buckets and Azure containers for `example.com`
- Scans each for public accessibility vulnerabilities
- Generates HTML and PDF reports
- Prints summary to console

### Option 2: HTML Only
```bash
python main.py example.com --format html
```

### Option 3: PDF Only  
```bash
python main.py example.com --format pdf
```

### Option 4: Verbose (See all discovery steps)
```bash
python main.py example.com --verbose
```

### Option 5: Custom Output Directory
```bash
python main.py example.com --output-dir "C:\my_reports"
```

## 📂 Where to Find Reports

After running a scan, reports are saved in:
```
c:\Users\abhip\Documents\PROGRAMS\projects\cloud_misconfiguration_scanner\output\
```

Filenames look like:
- `report_example_com_20260605_141321.html` (Browser-friendly)
- `report_example_com_20260605_141321.pdf` (PDF-friendly)

### Open Reports

**Windows:**
```bash
# Open HTML in browser
start "output\report_example_com_20260605_141321.html"

# Open PDF
start "output\report_example_com_20260605_141321.pdf"
```

**Or just double-click the files in File Explorer**

## 🧪 Test Everything Works

```bash
python test_components.py
```

This will:
1. ✓ Test cloud discovery (10 S3 + 9 Azure candidates)
2. ✓ Test risk calculator (calculates scores)
3. ✓ Generate sample HTML report
4. ✓ Generate sample PDF report
5. ✓ Save test reports to `output/`

## 📊 Report Contents

### HTML Report
```
├── Header: Domain name + Risk badge (RED/ORANGE/YELLOW/GREEN)
├── Metadata: Domain, timestamp, risk score
├── Statistics: Vulnerability counts by severity
├── S3 Table: Vulnerable buckets with details
├── Azure Table: Vulnerable containers  
├── Recommendations: Security fixes needed
└── Professional design with color coding
```

### PDF Report
```
├── Title page with risk summary
├── Metadata table
├── Statistics
├── S3 vulnerabilities (one page per resource)
├── Azure vulnerabilities
├── Recommendations section
└── Ready for email/sharing
```

## 🎯 Example Workflow

```bash
# Step 1: Navigate to project
cd "c:\Users\abhip\Documents\PROGRAMS\projects\cloud_misconfiguration_scanner"

# Step 2: Scan a domain
python main.py mycompany.com

# Step 3: Wait 30-60 seconds for scan to complete

# Step 4: Check console output for summary

# Step 5: Open the generated reports
#         - HTML: Open in browser
#         - PDF: Open with PDF reader

# Step 6: Review vulnerabilities and recommendations
```

## 📋 Console Output Example

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

[S3 VULNERABILITIES]
  • bucket-data [HIGH]
    - BUCKET_LIST_ACCESSIBLE

[AZURE VULNERABILITIES]  
  • myaccount/data [HIGH]
    - BLOB_LIST_ACCESSIBLE

======================================================================
✓ Reports generated:
  HTML: output/report_example_com_20260605_141321.html
  PDF: output/report_example_com_20260605_141321.pdf
```

## 🔍 Scan Details

Each scan does:

1. **Phase 1: Discovery** (~10-15 seconds)
   - Generates common bucket name patterns
   - Checks DNS records
   - Searches public indexes

2. **Phase 2: S3 Scanning** (~10-20 seconds)
   - Tests public HTTP access
   - Checks list permissions
   - Tests write permissions
   - Reviews bucket policies

3. **Phase 3: Azure Scanning** (~5-15 seconds)
   - Tests public HTTP access
   - Checks list permissions
   - Searches for SAS tokens

4. **Phase 4: Risk Calculation** (<1 second)
   - Scores all vulnerabilities
   - Generates recommendations

5. **Phase 5: Report Generation** (<2 seconds)
   - Creates HTML report
   - Creates PDF report
   - Saves to `output/`

**Total time: 30-60 seconds per domain**

## ⚡ Multiple Domains

Scan multiple domains in sequence:

```bash
python main.py example.com
python main.py test.io
python main.py myapp.org

# Then check output folder for all reports
ls output/
```

Or create a batch scan script:

```bash
# File: scan_domains.bat (Windows)
@echo off
python main.py example.com
python main.py test.io
python main.py myapp.org
echo All scans complete - check output folder
pause
```

## 🛠️ Troubleshooting

### Q: No reports were generated
**A:** This means no vulnerabilities were found (which is good!). 
- Use `--verbose` to see discovery details
- Try a domain you know has cloud infrastructure

### Q: Scan is slow
**A:** Normal - takes 30-60 seconds
- Discovery phase queries DNS and searches
- S3/Azure need time to respond
- Network speed affects results

### Q: Import errors when running
**A:** Reinstall dependencies:
```bash
pip install -r requirements.txt --upgrade
```

### Q: Can't open reports
**A:** Use absolute file path:
```bash
start "c:\Users\abhip\Documents\PROGRAMS\projects\cloud_misconfiguration_scanner\output\report_*.html"
```

## 📚 File Structure

```
cloud_misconfiguration_scanner/
├── main.py                    ← RUN THIS
├── test_components.py         ← Or this (for testing)
├── HOW_TO_RUN.md             ← Detailed guide
├── README.md                 ← Full documentation
├── requirements.txt
├── output/                   ← Reports saved here
│   ├── test_report.html
│   ├── test_report.pdf
│   └── report_*.html/pdf
├── scanners/
├── utils/
└── report_templates/
```

## ✅ Verification Checklist

- [x] Python 3.8+ installed
- [x] All dependencies installed (`pip list` shows them)
- [x] test_components.py runs successfully
- [x] Sample reports generated
- [x] project structure complete
- [x] Ready to scan domains!

## 🎉 You're Ready!

```bash
python main.py yourdomain.com
```

The scanner will:
1. Find cloud buckets/blobs for your domain
2. Test their public accessibility
3. Generate professional reports
4. Show recommendations for security fixes

---

**Need help?** Check `HOW_TO_RUN.md` for detailed documentation.
