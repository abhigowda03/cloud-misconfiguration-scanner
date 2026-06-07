"""
Cloud Misconfiguration Scanner - Main Entry Point

A security tool that detects exposed S3 buckets and Azure blobs without authentication.
Generates comprehensive risk reports in HTML and PDF formats.
"""

import argparse
import sys
import logging
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
from urllib.parse import urlparse

from jinja2 import Environment, FileSystemLoader

from scanners.cloud_discoverer import CloudDiscoverer
from scanners.s3_scanner import S3Scanner
from scanners.azure_scanner import AzureScanner
from utils.risk_calculator import RiskCalculator
from report_templates.pdf_report import generate_pdf_report


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


class CloudMisconfigurationScanner:
    """Main scanner orchestrator class."""

    def __init__(self, output_dir: str = "output"):
        """
        Initialize the scanner.

        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        self.cloud_discoverer = CloudDiscoverer()
        self.s3_scanner = S3Scanner()
        self.azure_scanner = AzureScanner()
        self.risk_calculator = RiskCalculator()

        self.template_dir = Path(__file__).parent / "report_templates"

    def scan(self, domain: str) -> Dict[str, Any]:
        """
        Perform complete scan of domain for cloud misconfigurations.

        Args:
            domain: Target domain

        Returns:
            Dictionary with scan results
        """
        logger.info(f"Starting scan for domain: {domain}")

        # Phase 1: Discover buckets and blobs
        logger.info("Phase 1: Discovering cloud storage...")
        discovery_results = self.cloud_discoverer.discover_from_domain(domain)

        s3_buckets = discovery_results.get("s3_buckets", [])
        azure_accounts = discovery_results.get("azure_blobs", [])

        logger.info(f"Discovered {len(s3_buckets)} S3 buckets and {len(azure_accounts)} Azure accounts")

        all_vulnerabilities = []

        # Phase 2: Scan S3 buckets
        if s3_buckets:
            logger.info("Phase 2: Scanning S3 buckets...")
            s3_vulns = self.s3_scanner.scan_buckets(s3_buckets)
            all_vulnerabilities.extend(s3_vulns)
            logger.info(f"Found {len(s3_vulns)} S3 vulnerabilities")
        else:
            logger.info("No S3 buckets found")
            s3_vulns = []

        # Phase 3: Scan Azure blobs
        if azure_accounts:
            logger.info("Phase 3: Scanning Azure blobs...")
            azure_vulns = self.azure_scanner.scan_blobs(azure_accounts)
            all_vulnerabilities.extend(azure_vulns)
            logger.info(f"Found {len(azure_vulns)} Azure vulnerabilities")
        else:
            logger.info("No Azure accounts found")
            azure_vulns = []

        # Phase 4: Calculate risk
        logger.info("Phase 4: Calculating risk...")
        risk_summary = self.risk_calculator.calculate_overall_risk(all_vulnerabilities)

        # Phase 5: Generate recommendations
        logger.info("Phase 5: Generating recommendations...")
        recommendations = self.risk_calculator.generate_recommendations(all_vulnerabilities)

        # Compile results
        scan_results = {
            "domain": domain,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "discovered": {
                "s3_buckets": s3_buckets,
                "azure_accounts": azure_accounts,
            },
            "vulnerabilities": all_vulnerabilities,
            "s3_vulns": [v for v in all_vulnerabilities if v.get("service") == "S3"],
            "azure_vulns": [v for v in all_vulnerabilities if v.get("service") == "Azure"],
            "risk_summary": risk_summary,
            "recommendations": recommendations,
        }

        # Print summary
        self._print_summary(scan_results)

        return scan_results

    def generate_reports(
        self, scan_results: Dict[str, Any], formats: List[str] = ["html", "pdf"]
    ) -> Dict[str, str]:
        """
        Generate reports from scan results.

        Args:
            scan_results: Dictionary from scan() method
            formats: List of formats to generate ('html', 'pdf', 'both')

        Returns:
            Dictionary with generated report paths
        """
        report_paths = {}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain_safe = self._sanitize_target(scan_results["domain"])

        # Prepare report data
        report_data = {
            "domain": scan_results["domain"],
            "timestamp": scan_results["timestamp"],
            "risk_level": scan_results["risk_summary"]["risk_level"],
            "risk_score": scan_results["risk_summary"]["score"],
            "total_vulns": scan_results["risk_summary"]["total_vulns"],
            "critical_count": scan_results["risk_summary"]["critical_count"],
            "high_count": scan_results["risk_summary"]["high_count"],
            "medium_count": scan_results["risk_summary"]["medium_count"],
            "low_count": scan_results["risk_summary"]["low_count"],
            "s3_vulns": scan_results["s3_vulns"],
            "azure_vulns": scan_results["azure_vulns"],
            "recommendations": scan_results["recommendations"],
            "overall_risk": scan_results["risk_summary"]["risk_level"],
        }

        # Generate HTML report
        if "html" in formats or "both" in formats:
            logger.info("Generating HTML report...")
            html_filename = f"report_{domain_safe}_{timestamp}.html"
            html_path = self.output_dir / html_filename

            try:
                self._generate_html_report(report_data, str(html_path))
                report_paths["html"] = str(html_path)
                logger.info(f"HTML report saved: {html_path}")
            except Exception as e:
                logger.error(f"Failed to generate HTML report: {e}")

        # Generate PDF report
        if "pdf" in formats or "both" in formats:
            logger.info("Generating PDF report...")
            pdf_filename = f"report_{domain_safe}_{timestamp}.pdf"
            pdf_path = self.output_dir / pdf_filename

            try:
                generate_pdf_report(report_data, str(pdf_path))
                report_paths["pdf"] = str(pdf_path)
                logger.info(f"PDF report saved: {pdf_path}")
            except Exception as e:
                logger.error(f"Failed to generate PDF report: {e}")

        return report_paths

    def _generate_html_report(self, report_data: Dict[str, Any], output_file: str) -> None:
        """
        Generate HTML report using Jinja2 template.

        Args:
            report_data: Report data dictionary
            output_file: Output HTML file path
        """
        env = Environment(loader=FileSystemLoader(str(self.template_dir)))
        template = env.get_template("html_report.html")

        html_content = template.render(**report_data)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_content)

    def _print_summary(self, scan_results: Dict[str, Any]) -> None:
        """
        Print scan summary to console.

        Args:
            scan_results: Dictionary from scan() method
        """
        print("\n" + "=" * 70)
        print("CLOUD MISCONFIGURATION SCANNER - SUMMARY REPORT")
        print("=" * 70)
        print(f"\nTarget Domain: {scan_results['domain']}")
        print(f"Scan Time: {scan_results['timestamp']}")

        print(f"\n[DISCOVERY PHASE]")
        print(f"  S3 Buckets: {len(scan_results['discovered']['s3_buckets'])}")
        print(f"  Azure Accounts: {len(scan_results['discovered']['azure_accounts'])}")

        risk = scan_results["risk_summary"]
        print(f"\n[VULNERABILITY SUMMARY]")
        print(f"  Total Vulnerabilities: {risk['total_vulns']}")
        print(f"  Critical: {risk['critical_count']}")
        print(f"  High: {risk['high_count']}")
        print(f"  Medium: {risk['medium_count']}")
        print(f"  Low: {risk['low_count']}")

        print(f"\n[RISK ASSESSMENT]")
        print(f"  Overall Risk Level: {risk['risk_level']}")
        print(f"  Risk Score: {risk['score']}/100")

        if scan_results["s3_vulns"]:
            print(f"\n[S3 VULNERABILITIES]")
            for vuln in scan_results["s3_vulns"]:
                print(f"  • {vuln['bucket_name']} [{vuln['risk_level']}]")
                for v in vuln["vulnerabilities"]:
                    print(f"    - {v}")

        if scan_results["azure_vulns"]:
            print(f"\n[AZURE VULNERABILITIES]")
            for vuln in scan_results["azure_vulns"]:
                print(f"  • {vuln['account_name']}/{vuln['container_name']} [{vuln['risk_level']}]")
                for v in vuln["vulnerabilities"]:
                    print(f"    - {v}")

        if not scan_results["vulnerabilities"]:
            print(f"\n✓ No vulnerabilities found!")

        print("\n" + "=" * 70 + "\n")

    def _sanitize_target(self, target: str) -> str:
        """Create a safe filename token from a domain or URL."""
        parsed = urlparse(target)
        candidate = parsed.netloc or parsed.path or target
        candidate = candidate.strip("/\\")
        safe_target = re.sub(r"[<>:\"/\\|?*\.\s]+", "_", candidate)
        safe_target = re.sub(r"_+", "_", safe_target).strip("_")
        return safe_target or "target"


def main():
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(
        description="Cloud Misconfiguration Scanner - Detect exposed S3 buckets and Azure blobs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py example.com
  python main.py example.com --format both
  python main.py example.com --format pdf --output-dir ./reports
  python main.py example.com --verbose
        """,
    )

    parser.add_argument(
        "domain",
        help="Target domain to scan (e.g., example.com)",
    )

    parser.add_argument(
        "--format",
        "-f",
        choices=["html", "pdf", "both"],
        default="both",
        help="Report format (default: both)",
    )

    parser.add_argument(
        "--output-dir",
        "-o",
        default="output",
        help="Output directory for reports (default: output)",
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose output",
    )

    args = parser.parse_args()

    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        # Create scanner
        scanner = CloudMisconfigurationScanner(output_dir=args.output_dir)

        # Run scan
        logger.info("=" * 70)
        logger.info("CLOUD MISCONFIGURATION SCANNER")
        logger.info("=" * 70)

        scan_results = scanner.scan(args.domain)

        # Generate reports (always, even if no vulnerabilities found)
        formats = args.format.split(",") if "," in args.format else [args.format]
        report_paths = scanner.generate_reports(scan_results, formats)

        print(f"\n✓ Reports generated:")
        for fmt, path in report_paths.items():
            print(f"  {fmt.upper()}: {path}")

        print(f"\n✓ Scan complete!")
        return 0

    except KeyboardInterrupt:
        logger.error("Scan interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=args.verbose)
        return 1


if __name__ == "__main__":
    sys.exit(main())
