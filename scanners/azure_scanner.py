"""Azure Blob Storage vulnerability scanner module."""

import requests
import re
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


class AzureScanner:
    """Scanner for detecting Azure Blob Storage misconfigurations and vulnerabilities."""

    def __init__(self):
        """Initialize Azure scanner."""
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        )

    def scan_blobs(
        self, blob_accounts: List[str], container_names: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Scan multiple Azure storage accounts for vulnerabilities.

        Args:
            blob_accounts: List of storage account names (without .blob.core.windows.net)
            container_names: Optional list of container names to check

        Returns:
            List of vulnerability dictionaries
        """
        vulnerabilities = []

        for account in blob_accounts:
            logger.info(f"Scanning Azure account: {account}")

            # Default containers to check if not provided
            containers = container_names or [
                "blob",
                "blobs",
                "data",
                "files",
                "uploads",
                "backup",
                "assets",
                "public",
                "$web",
                "container",
                account,
            ]

            for container in containers:
                try:
                    result = self._check_blob(container, account)
                    if result:
                        vulnerabilities.append(result)
                except Exception as e:
                    logger.debug(f"Error scanning {account}/{container}: {e}")

        return vulnerabilities

    def _check_blob(self, container_name: str, account_name: str) -> Optional[Dict[str, Any]]:
        """
        Check a single Azure blob container for vulnerabilities.

        Args:
            container_name: Container name
            account_name: Storage account name

        Returns:
            Dictionary with vulnerability details or None if no issues
        """
        findings = {
            "service": "Azure",
            "account_name": account_name,
            "container_name": container_name,
            "url": f"https://{account_name}.blob.core.windows.net/{container_name}",
            "vulnerabilities": [],
            "risk_level": "LOW",
            "details": {},
        }

        # Check HTTP public access with HEAD request
        try:
            url = f"https://{account_name}.blob.core.windows.net/{container_name}"
            response = self.session.head(url, timeout=5, allow_redirects=False)

            if response.status_code == 200:
                findings["vulnerabilities"].append("BLOB_PUBLICLY_ACCESSIBLE")
                findings["details"]["http_accessible"] = True
            elif response.status_code == 401 or response.status_code == 403:
                findings["details"]["http_accessible"] = False
                return None  # Container not accessible publicly
        except requests.exceptions.ConnectionError:
            logger.debug(f"Connection error for {account_name}/{container_name}")
            return None
        except requests.exceptions.Timeout:
            logger.debug(f"Timeout for {account_name}/{container_name}")
            return None
        except Exception as e:
            logger.debug(f"HTTP access check for {account_name}/{container_name}: {e}")
            return None

        # Try to list blobs with public access
        try:
            url = (
                f"https://{account_name}.blob.core.windows.net/{container_name}?restype=container&comp=list"
            )
            response = self.session.get(url, timeout=5)

            if response.status_code == 200:
                findings["vulnerabilities"].append("BLOB_LIST_ACCESSIBLE")
                findings["details"]["list_blobs"] = True

                # Count blobs in response
                try:
                    blob_count = response.text.count("<Blob>")
                    findings["details"]["blob_count"] = blob_count
                except Exception:
                    pass

                # Check for SAS token in URL
                if "sv=" in response.url or "sig=" in response.url:
                    findings["vulnerabilities"].append("BLOB_SAS_TOKEN_EXPOSED")
                    findings["details"]["sas_token_exposed"] = True
            elif response.status_code == 401 or response.status_code == 403:
                findings["details"]["list_blobs"] = False
        except requests.exceptions.ConnectionError:
            logger.debug(f"Connection error listing {account_name}/{container_name}")
        except requests.exceptions.Timeout:
            logger.debug(f"Timeout listing {account_name}/{container_name}")
        except Exception as e:
            logger.debug(f"List blobs check for {account_name}/{container_name}: {e}")

        # Check for public access level by testing different paths
        try:
            # Try to get properties with public access
            url = f"https://{account_name}.blob.core.windows.net/{container_name}?restype=container"
            response = self.session.get(url, timeout=5)

            if response.status_code == 200:
                # Check response headers for access level
                if "x-ms-blob-public-access" in response.headers:
                    public_access = response.headers["x-ms-blob-public-access"]
                    if public_access in ["container", "blob"]:
                        findings["vulnerabilities"].append("BLOB_PUBLIC_ACCESS_LEVEL")
                        findings["details"]["public_access_level"] = public_access
        except Exception as e:
            logger.debug(f"Public access level check failed: {e}")

        # Search for SAS tokens in URLs
        try:
            sas_patterns = [
                r"sv=\d{4}-\d{2}-\d{2}",  # Service version
                r"sig=[A-Za-z0-9%+/]+",  # Signature
                r"se=\d{4}-\d{2}-\d{2}",  # Signed expiry
            ]

            for pattern in sas_patterns:
                if re.search(pattern, findings["url"]):
                    findings["vulnerabilities"].append("BLOB_SAS_TOKEN_EXPOSED")
                    findings["details"]["sas_token_exposed"] = True
                    break
        except Exception as e:
            logger.debug(f"SAS token search failed: {e}")

        # Determine risk level
        if "BLOB_SAS_TOKEN_EXPOSED" in findings["vulnerabilities"]:
            findings["risk_level"] = "HIGH"
        elif (
            "BLOB_LIST_ACCESSIBLE" in findings["vulnerabilities"]
            and "BLOB_PUBLICLY_ACCESSIBLE" in findings["vulnerabilities"]
        ):
            findings["risk_level"] = "HIGH"
        elif (
            "BLOB_LIST_ACCESSIBLE" in findings["vulnerabilities"]
            or "BLOB_PUBLICLY_ACCESSIBLE" in findings["vulnerabilities"]
            or "BLOB_PUBLIC_ACCESS_LEVEL" in findings["vulnerabilities"]
        ):
            findings["risk_level"] = "MEDIUM"
        else:
            return None  # No vulnerabilities found

        return findings if findings["vulnerabilities"] else None
