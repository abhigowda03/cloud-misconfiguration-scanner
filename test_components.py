#!/usr/bin/env python
"""Quick test script to verify Cloud Misconfiguration Scanner works correctly."""

import sys
from pathlib import Path

# Add project to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from scanners.cloud_discoverer import CloudDiscoverer
from scanners.s3_scanner import S3Scanner
from scanners.azure_scanner import AzureScanner
from utils.risk_calculator import RiskCalculator
from main import CloudMisconfigurationScanner

def test_discovery():
    """Test cloud discovery module."""
    print("\n" + "="*70)
    print("TEST 1: Cloud Discovery Module")
    print("="*70)
    
    discoverer = CloudDiscoverer(timeout=3)
    results = discoverer.discover_from_domain("google.com")
    
    print(f"✓ Discovery completed")
    print(f"  - S3 candidates: {len(results['s3_buckets'])} found")
    print(f"  - Azure candidates: {len(results['azure_blobs'])} found")
    print(f"  - Sample S3: {results['s3_buckets'][:3]}")
    print(f"  - Sample Azure: {results['azure_blobs'][:3]}")

def test_risk_calculator():
    """Test risk calculation module."""
    print("\n" + "="*70)
    print("TEST 2: Risk Calculator Module")
    print("="*70)
    
    calculator = RiskCalculator()
    
    # Create mock vulnerabilities
    test_vulns = [
        {
            "service": "S3",
            "bucket_name": "test-bucket",
            "url": "https://test-bucket.s3.amazonaws.com",
            "vulnerabilities": ["BUCKET_WRITE_ACCESSIBLE"],
            "risk_level": "CRITICAL",
            "details": {}
        },
        {
            "service": "S3",
            "bucket_name": "test-bucket-2",
            "url": "https://test-bucket-2.s3.amazonaws.com",
            "vulnerabilities": ["BUCKET_LIST_ACCESSIBLE"],
            "risk_level": "MEDIUM",
            "details": {}
        },
    ]
    
    risk = calculator.calculate_overall_risk(test_vulns)
    print(f"✓ Risk calculation completed")
    print(f"  - Risk Score: {risk['score']}/100")
    print(f"  - Overall Level: {risk['risk_level']}")
    print(f"  - Critical: {risk['critical_count']}, High: {risk['high_count']}, Medium: {risk['medium_count']}")
    
    recs = calculator.generate_recommendations(test_vulns)
    print(f"  - Recommendations: {len(recs)} generated")

def test_report_filename_sanitization():
    """Test report filename sanitization for URL-like inputs."""
    print("\n" + "="*70)
    print("TEST 3: Report Filename Sanitization")
    print("="*70)

    scanner = CloudMisconfigurationScanner(output_dir=project_root / "output")
    safe_target = scanner._sanitize_target("https://www.instagram.com")

    assert safe_target == "www_instagram_com", f"Unexpected sanitized target: {safe_target}"
    print(f"✓ Sanitized filename token: {safe_target}")


def test_html_report():
    """Test HTML report generation."""
    print("\n" + "="*70)
    print("TEST 3: HTML Report Generation")
    print("="*70)
    
    from report_templates.pdf_report import generate_pdf_report
    from jinja2 import Environment, FileSystemLoader
    from datetime import datetime
    
    # Create mock report data
    report_data = {
        "domain": "test.example.com",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "risk_level": "HIGH",
        "risk_score": 75,
        "total_vulns": 2,
        "critical_count": 1,
        "high_count": 1,
        "medium_count": 0,
        "low_count": 0,
        "s3_vulns": [
            {
                "bucket_name": "test-bucket",
                "url": "https://test-bucket.s3.amazonaws.com",
                "risk_level": "CRITICAL",
                "vulnerabilities": ["BUCKET_WRITE_ACCESSIBLE"],
            }
        ],
        "azure_vulns": [
            {
                "account_name": "testaccount",
                "container_name": "data",
                "url": "https://testaccount.blob.core.windows.net/data",
                "risk_level": "HIGH",
                "vulnerabilities": ["BLOB_LIST_ACCESSIBLE"],
            }
        ],
        "recommendations": [
            "Block public write access to S3 bucket immediately",
            "Set Azure blob container to private access"
        ],
        "overall_risk": "HIGH",
    }
    
    # Generate HTML
    try:
        template_dir = project_root / "report_templates"
        env = Environment(loader=FileSystemLoader(str(template_dir)))
        template = env.get_template("html_report.html")
        html_content = template.render(**report_data)
        
        test_html = project_root / "output" / "test_report.html"
        with open(test_html, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        print(f"✓ HTML report generated successfully")
        print(f"  - Output: {test_html}")
        print(f"  - Size: {len(html_content)} bytes")
    except Exception as e:
        print(f"✗ HTML generation failed: {e}")
        raise
    
    # Generate PDF
    try:
        test_pdf = project_root / "output" / "test_report.pdf"
        generate_pdf_report(report_data, str(test_pdf))
        
        print(f"✓ PDF report generated successfully")
        print(f"  - Output: {test_pdf}")
        print(f"  - Size: {test_pdf.stat().st_size} bytes")
    except Exception as e:
        print(f"✗ PDF generation failed: {e}")
        raise

def main():
    """Run all tests."""
    print("\n" + "█"*70)
    print("  CLOUD MISCONFIGURATION SCANNER - COMPONENT TEST")
    print("█"*70)
    
    try:
        test_discovery()
        test_risk_calculator()
        test_html_report()
        
        print("\n" + "="*70)
        print("✓ ALL TESTS PASSED!")
        print("="*70)
        print("\nNext steps:")
        print("  1. Run: python main.py example.com")
        print("  2. Reports will be saved in: ./output/")
        print("  3. Check the generated HTML and PDF files")
        print("\n")
        
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
