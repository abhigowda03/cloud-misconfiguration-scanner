# Cloud Misconfiguration Scanner

[![CI](https://github.com/abhigowda03/cloud-misconfiguration-scanner/actions/workflows/python-app.yml/badge.svg)](https://github.com/abhigowda03/cloud-misconfiguration-scanner/actions/workflows/python-app.yml)

[Live Demo](https://cloud-misconfiguration-scanner.onrender.com)

A comprehensive security tool that detects exposed S3 buckets and Azure blobs without requiring authentication. This tool works on public-facing infrastructure and generates detailed risk reports.

## Features

- **Cloud Discovery**: Automatically discover S3 buckets and Azure blob containers associated with a domain
  - Pattern-based bucket name generation
  - DNS CNAME record analysis
  - Public search integration
  
- **Vulnerability Detection**:
  - S3 public access checking (HTTP, list_objects, put_object)
  - Azure blob public access verification
  - Bucket policy analysis
  - Encryption and versioning checks
  - SAS token detection

- **Risk Assessment**:
  - Automatic risk scoring (0-100)
  - Severity classification (CRITICAL, HIGH, MEDIUM, LOW)
  - Vulnerability counts and statistics

- **Report Generation**:
  - Professional HTML reports with CSS styling
  - PDF reports with detailed findings
  - Color-coded risk indicators
  - Security recommendations

## Installation

1. Clone or download the project
2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. (Optional) Copy and configure environment variables:
```bash
cp .env.example .env
```

## Usage

### Basic Usage

```bash
python main.py example.com
```

### Generate Both HTML and PDF Reports

```bash
python main.py example.com --format both
```

### Specify Output Directory

```bash
python main.py example.com --format both --output-dir ./security_reports
```

### Verbose Output

```bash
python main.py example.com --verbose
```

### Generate Only HTML Reports

```bash
python main.py example.com --format html
```

### Generate Only PDF Reports

```bash
python main.py example.com --format pdf
```

## Web Interface

You can run the scanner as a web app so others can visit a browser page and start scans.

```bash
pip install -r requirements.txt
python app.py
```

Then open `http://127.0.0.1:5000` in your browser.

- The web form accepts a domain and generates report files in `output/`.
- Click the report download links after the scan completes.

## Deploying to a Website

To publish the project online, use a Python-capable hosting service such as Render, Railway, Fly.io, or Azure App Service.

This repository now includes GitHub Actions CI for syntax and build checks on every push to `main`.

### Recommended: Render.com

1. Push the repository to GitHub.
2. Connect the repo in Render and choose the `main` branch.
3. Render will use `pip install -r requirements.txt` and start the app with `gunicorn app:app`.
4. Open the public URL Render gives you.

> Render already supports auto-deploy from GitHub, so pushes to `main` will update the deployed site.

### Alternative: Railway or Azure

- Railway: connect GitHub, set the start command to `gunicorn app:app`, and deploy.
- Azure Web App: choose Python runtime, deploy from GitHub, and use `gunicorn app:app`.

### Important notes

- `app.py` serves the web interface on port `5000` by default and `gunicorn` will bind to the host/port provided by the platform.
- `render.yaml` is included for Render deployments, and `runtime.txt` pins Python 3.11.
- The app saves generated reports in `output/` and serves them at `/reports/<filename>`.

> Note: This repository runs a server-side scanner. Be careful with public exposure, scanning limits, and authorized testing only.

## Publishing on GitHub

1. Initialize Git in the project folder if not already done:

```bash
git init
git add .
git commit -m "Initial commit"
```

2. Create a repository on GitHub and push:

```bash
git remote add origin https://github.com/<your-username>/<repo-name>.git
git push -u origin main
```

3. Add a good `README.md`, license, and a `.gitignore` file.

## Command Line Options

```
positional arguments:
  domain                Target domain to scan (e.g., example.com)

optional arguments:
  -h, --help            Show help message
  -f, --format {html,pdf,both}
                        Report format (default: both)
  -o, --output-dir PATH
                        Output directory for reports (default: output)
  -v, --verbose         Enable verbose output
```

## Project Structure

```
cloud_misconfiguration_scanner/
├── main.py                          # CLI entry point
├── requirements.txt                 # Python dependencies
├── .env.example                     # Environment configuration template
├── scanners/
│   ├── __init__.py
│   ├── cloud_discoverer.py          # Cloud bucket/blob discovery
│   ├── s3_scanner.py                # S3 vulnerability scanner
│   └── azure_scanner.py             # Azure vulnerability scanner
├── utils/
│   ├── __init__.py
│   └── risk_calculator.py           # Risk scoring and recommendations
├── report_templates/
│   ├── html_report.html             # HTML report template (Jinja2)
│   └── pdf_report.py                # PDF generator (ReportLab)
└── output/                          # Generated reports directory
```

## Module Documentation

### cloud_discoverer.py

**CloudDiscoverer** - Discovers cloud storage buckets and blobs associated with a domain.

Methods:
- `discover_from_domain(domain)` - Returns dict with s3_buckets and azure_blobs lists

Discovery Strategies:
- Common naming pattern generation (domain, domain-prod, domain-cdn, etc.)
- DNS CNAME record analysis
- Public search engine queries

### s3_scanner.py

**S3Scanner** - Detects S3 bucket misconfigurations.

Methods:
- `scan_buckets(bucket_names)` - Scans list of S3 buckets
- `_check_bucket(bucket_name)` - Checks individual bucket

Checks Performed:
- Public HTTP access
- List objects (read access)
- Put object (write access)
- Bucket policies
- Encryption settings
- Versioning status
- Block Public Access configuration

Risk Levels:
- **CRITICAL**: Bucket is writable without authentication
- **HIGH**: Bucket allows listing objects and is publicly accessible
- **MEDIUM**: Bucket has public read access or public policy
- **LOW**: No encryption or other security gaps

### azure_scanner.py

**AzureScanner** - Detects Azure Blob Storage misconfigurations.

Methods:
- `scan_blobs(blob_accounts, container_names)` - Scans Azure containers
- `_check_blob(container_name, account_name)` - Checks individual container

Checks Performed:
- Public HTTP access
- Container listing
- SAS token exposure
- Public access level settings

Risk Levels:
- **HIGH**: Public access level set or SAS token exposed
- **MEDIUM**: Container allows listing or is publicly accessible
- **LOW**: Not accessible

### risk_calculator.py

**RiskCalculator** - Calculates overall risk and generates recommendations.

Methods:
- `calculate_overall_risk(vulnerabilities)` - Returns risk score and counts
- `generate_recommendations(vulnerabilities)` - Returns list of remediation steps
- `get_risk_color(risk_level)` - Returns hex color for risk level

Risk Scoring:
- CRITICAL: 100 points
- HIGH: 75 points
- MEDIUM: 50 points
- LOW: 25 points

## Vulnerability Types

### S3 Vulnerabilities

- `BUCKET_WRITE_ACCESSIBLE` - Bucket allows unauthenticated uploads
- `BUCKET_LIST_ACCESSIBLE` - Bucket allows listing objects without auth
- `BUCKET_PUBLICLY_ACCESSIBLE` - Bucket responds to HTTP requests
- `BUCKET_POLICY_PUBLIC` - Bucket policy grants public access
- `BUCKET_NO_ENCRYPTION` - Server-side encryption not enabled

### Azure Vulnerabilities

- `BLOB_PUBLICLY_ACCESSIBLE` - Blob is publicly accessible via HTTP
- `BLOB_LIST_ACCESSIBLE` - Container allows listing without auth
- `BLOB_PUBLIC_ACCESS_LEVEL` - Public access level is set to Container or Blob
- `BLOB_SAS_TOKEN_EXPOSED` - SAS token found in URL

## Report Output

The scanner generates professional reports in two formats:

### HTML Reports
- Color-coded risk indicators
- Interactive tables
- Statistics grid
- Sorted vulnerabilities
- Actionable recommendations
- Responsive design

### PDF Reports
- Title page with risk summary
- Statistics tables
- Vulnerability details
- Security recommendations
- Professional formatting

Both reports include:
- Domain information
- Scan timestamp
- Overall risk level and score
- Vulnerability counts by severity
- Detailed findings for each resource
- Security recommendations

## Security Considerations

⚠️ **IMPORTANT**: This tool scans public infrastructure and does NOT require AWS or Azure credentials. It works by checking what's publicly accessible.

- This tool is designed for authorized security testing
- Use only on domains you own or have permission to test
- Results show only publicly accessible misconfigurations
- Authenticated access to resources is not attempted
- No credentials are stored or transmitted

## Error Handling

The scanner gracefully handles:
- Network timeouts
- Non-existent buckets/containers
- DNS resolution failures
- Invalid domain names
- AWS/Azure service errors
- Authentication failures

Errors are logged to console with details for debugging.

## Performance Notes

- Discovery typically takes 30-60 seconds per domain
- S3 scanning depends on number of candidates (usually fast)
- Azure scanning may take longer due to API call limits
- Reports generation is typically < 5 seconds
- Network timeout is 10 seconds per request (configurable)

## Requirements

- Python 3.8+
- Internet connectivity for discovery and scanning
- No AWS or Azure credentials needed for public scanning

## Dependencies

- `boto3` - AWS S3 API client
- `azure-storage-blob` - Azure Storage SDK
- `requests` - HTTP client for public access checks
- `beautifulsoup4` - HTML parsing for search results
- `reportlab` - PDF generation
- `jinja2` - HTML template rendering
- `dnspython` - DNS record lookup
- `python-dotenv` - Environment configuration

## Troubleshooting

### No vulnerabilities found
- Ensure the domain is correct
- Check if infrastructure actually exists
- Use `--verbose` flag for detailed discovery information

### Discovery slow
- Check internet connection
- DNS lookups can be slow on some networks
- Use specific output directory to avoid scanning existing reports

### Import errors
- Ensure all dependencies from requirements.txt are installed
- Use `pip list` to verify installed packages
- Try `pip install -r requirements.txt --upgrade`

### Report generation failed
- Ensure output directory exists and is writable
- Check disk space for PDF generation
- Verify Jinja2 template path is correct

## Limitations

- Discovery is based on common patterns; not all buckets may be found
- Azure discovery limited by container name patterns
- Search-based discovery limited by search engine indexing
- Some buckets may be hidden or require specific URLs
- Rate limiting on public search APIs

## Future Enhancements

- CloudFront distribution scanning
- GCP Cloud Storage support
- Automated remediation recommendations
- Email report delivery
- Scheduled scanning
- Database result storage
- Web dashboard interface

## License

This tool is provided as-is for security testing purposes.

## Support

For issues, errors, or feature requests, review the output with `--verbose` flag for detailed diagnostic information.

---

**Disclaimer**: This tool is designed for authorized security testing and should only be used on infrastructure you own or have explicit permission to test. Unauthorized access to computer systems is illegal.
>>>>>>> 34e4e43 (Initial commit)
