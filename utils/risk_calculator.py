"""Risk scoring and recommendation generation module."""

from typing import Dict, List, Any
from enum import Enum


class RiskLevel(Enum):
    """Risk severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RiskCalculator:
    """Calculates overall risk scores and generates security recommendations."""

    # Risk weights for scoring
    RISK_WEIGHTS = {
        "CRITICAL": 100,
        "HIGH": 75,
        "MEDIUM": 50,
        "LOW": 25,
    }

    # Vulnerability to recommendation mapping
    VULNERABILITY_RECOMMENDATIONS = {
        "BUCKET_WRITE_ACCESSIBLE": (
            "CRITICAL",
            "S3 bucket is publicly writable. Anyone can upload files to your bucket. "
            "Immediately block public write access by applying bucket policies and enabling "
            "Block Public Access settings.",
        ),
        "BUCKET_LIST_ACCESSIBLE": (
            "HIGH",
            "S3 bucket allows listing objects without authentication. Sensitive data could be "
            "discovered. Implement bucket policies to restrict ListBucket permissions.",
        ),
        "BUCKET_PUBLICLY_ACCESSIBLE": (
            "MEDIUM",
            "S3 bucket is publicly accessible via HTTP. While objects may be protected by ACLs, "
            "the bucket itself responds to public requests. Review bucket policies and ACLs.",
        ),
        "BUCKET_POLICY_PUBLIC": (
            "HIGH",
            "S3 bucket policy grants public access to principals. Review and restrict the policy "
            "to only required principals. Remove Principal: '*' statements.",
        ),
        "BUCKET_NO_ENCRYPTION": (
            "MEDIUM",
            "S3 bucket does not have server-side encryption enabled. Enable default encryption "
            "using either KMS or AES-256 to protect data at rest.",
        ),
        "BLOB_PUBLICLY_ACCESSIBLE": (
            "MEDIUM",
            "Azure blob container is publicly accessible. Review public access settings and "
            "consider disabling public access if not required.",
        ),
        "BLOB_LIST_ACCESSIBLE": (
            "HIGH",
            "Azure blob container allows listing without authentication. Sensitive file names "
            "could be discovered. Set public access level to Private.",
        ),
        "BLOB_PUBLIC_ACCESS_LEVEL": (
            "HIGH",
            "Azure blob container has public access level set. Change the public access level "
            "to Private or Blob-only, depending on requirements.",
        ),
        "BLOB_SAS_TOKEN_EXPOSED": (
            "HIGH",
            "Azure Blob Storage SAS token may be exposed in URL or logs. Rotate the token immediately "
            "and implement token lifecycle policies. Store tokens securely.",
        ),
    }

    def calculate_overall_risk(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate overall risk score and level from vulnerabilities.

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            Dictionary with risk score, level, and counts
        """
        if not vulnerabilities:
            return {
                "score": 0,
                "risk_level": "LOW",
                "total_vulns": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
            }

        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        total_score = 0

        for vuln in vulnerabilities:
            risk_level = vuln.get("risk_level", "LOW")
            risk_counts[risk_level] += 1
            total_score += self.RISK_WEIGHTS[risk_level]

        # Normalize score to 0-100
        max_possible_score = len(vulnerabilities) * self.RISK_WEIGHTS["CRITICAL"]
        normalized_score = min(100, int((total_score / max_possible_score) * 100)) if max_possible_score > 0 else 0

        # Determine overall risk level
        if risk_counts["CRITICAL"] > 0:
            overall_level = "CRITICAL"
        elif risk_counts["HIGH"] > 0:
            overall_level = "HIGH"
        elif risk_counts["MEDIUM"] > 0:
            overall_level = "MEDIUM"
        else:
            overall_level = "LOW"

        return {
            "score": normalized_score,
            "risk_level": overall_level,
            "total_vulns": len(vulnerabilities),
            "critical_count": risk_counts["CRITICAL"],
            "high_count": risk_counts["HIGH"],
            "medium_count": risk_counts["MEDIUM"],
            "low_count": risk_counts["LOW"],
        }

    def generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """
        Generate security recommendations based on vulnerabilities.

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            List of recommendation strings
        """
        recommendations = []
        seen_vulns = set()

        # Sort by risk level
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda x: list(self.RISK_WEIGHTS.keys()).index(x.get("risk_level", "LOW")),
        )

        for vuln in sorted_vulns:
            for vuln_type in vuln.get("vulnerabilities", []):
                if vuln_type not in seen_vulns:
                    if vuln_type in self.VULNERABILITY_RECOMMENDATIONS:
                        _, recommendation = self.VULNERABILITY_RECOMMENDATIONS[vuln_type]
                        recommendations.append(recommendation)
                        seen_vulns.add(vuln_type)

        # Add general recommendations
        if recommendations:  # Only add general recommendations if there are specific ones
            s3_vulns = [v for v in vulnerabilities if v.get("service") == "S3"]
            azure_vulns = [v for v in vulnerabilities if v.get("service") == "Azure"]

            if s3_vulns:
                recommendations.append(
                    "Enable S3 Block Public Access at both bucket and account levels to prevent accidental exposure. "
                    "Use bucket policies to explicitly deny public access."
                )
                recommendations.append(
                    "Implement versioning and MFA Delete on critical S3 buckets to protect against accidental deletion. "
                    "Enable CloudTrail logging for audit trails."
                )

            if azure_vulns:
                recommendations.append(
                    "Set Azure Blob Storage public access level to Private and use Shared Access Signatures (SAS) "
                    "with minimal permissions and short expiration times for temporary access."
                )
                recommendations.append(
                    "Implement Azure Storage firewall rules to restrict access to known IP ranges or virtual networks. "
                    "Use Azure Private Endpoints for secure connectivity."
                )

            recommendations.append(
                "Regularly audit cloud storage configurations using automated tools. "
                "Implement security group policies to enforce encryption and access controls."
            )

        return recommendations

    def get_risk_color(self, risk_level: str) -> str:
        """
        Get HTML color code for risk level.

        Args:
            risk_level: Risk level string

        Returns:
            Hex color code
        """
        colors = {
            "CRITICAL": "#d32f2f",  # Red
            "HIGH": "#f57c00",  # Orange
            "MEDIUM": "#fbc02d",  # Yellow
            "LOW": "#388e3c",  # Green
        }
        return colors.get(risk_level, "#757575")
