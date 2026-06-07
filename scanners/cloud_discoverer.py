"""Cloud storage discovery module for finding buckets and blobs associated with a domain."""

import re
import dns.resolver
import requests
from typing import Dict, List, Set
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)


class CloudDiscoverer:
    """Discovers cloud storage buckets and blobs associated with a target domain."""

    def __init__(self, timeout: int = 5):
        """
        Initialize CloudDiscoverer.

        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        )

        # Common S3 naming patterns
        self.s3_patterns = [
            "{domain}",
            "{domain}-website",
            "{domain}-prod",
            "{domain}-dev",
            "{domain}-staging",
            "{domain}-backup",
            "{domain}-assets",
            "{domain}-files",
            "{domain}-cdn",
            "{domain}-data",
            "www.{domain}",
            "s3.{domain}",
            "bucket.{domain}",
            "cdn.{domain}",
        ]

        # Common Azure naming patterns
        self.azure_patterns = [
            "{domain}",
            "{domain}prod",
            "{domain}dev",
            "{domain}staging",
            "{domain}backup",
            "{domain}assets",
            "{domain}files",
            "www{domain}",
            "blob{domain}",
        ]

    def discover_from_domain(self, domain: str) -> Dict[str, List[str]]:
        """
        Discover cloud buckets and blobs associated with a domain.

        Args:
            domain: Target domain (e.g., example.com)

        Returns:
            Dictionary with 's3_buckets' and 'azure_blobs' lists
        """
        logger.info(f"Starting discovery for domain: {domain}")

        # Remove protocol if present
        domain_clean = domain.replace("http://", "").replace("https://", "").split("/")[0]
        domain_base = domain_clean.replace("www.", "")

        s3_buckets: Set[str] = set()
        azure_blobs: Set[str] = set()

        # Generate candidate bucket names
        s3_candidates = self._generate_s3_candidates(domain_base)
        azure_candidates = self._generate_azure_candidates(domain_base)

        logger.info(f"Generated {len(s3_candidates)} S3 candidates")
        logger.info(f"Generated {len(azure_candidates)} Azure candidates")

        s3_buckets.update(s3_candidates)
        azure_blobs.update(azure_candidates)

        # Try DNS discovery
        logger.info("Attempting DNS CNAME discovery...")
        dns_s3, dns_azure = self._discover_via_dns(domain_clean)
        s3_buckets.update(dns_s3)
        azure_blobs.update(dns_azure)

        # Try public search discovery
        logger.info("Attempting public search discovery...")
        search_s3, search_azure = self._discover_via_search(domain_base)
        s3_buckets.update(search_s3)
        azure_blobs.update(search_azure)

        result = {
            "s3_buckets": sorted(list(s3_buckets)),
            "azure_blobs": sorted(list(azure_blobs)),
        }

        logger.info(f"Discovery complete: {len(result['s3_buckets'])} S3, {len(result['azure_blobs'])} Azure")

        return result

    def _generate_s3_candidates(self, domain_base: str) -> List[str]:
        """Generate candidate S3 bucket names from domain."""
        candidates = []
        domain_base = domain_base.replace(".", "-").replace("_", "-").lower()

        for pattern in self.s3_patterns:
            candidate = pattern.format(domain=domain_base)
            # S3 bucket names must be 3-63 chars, lowercase, alphanumeric and hyphens
            if 3 <= len(candidate) <= 63 and re.match(r"^[a-z0-9-]+$", candidate):
                candidates.append(candidate)

        return candidates

    def _generate_azure_candidates(self, domain_base: str) -> List[str]:
        """Generate candidate Azure blob container names from domain."""
        candidates = []
        domain_base = domain_base.replace(".", "").replace("-", "").lower()

        for pattern in self.azure_patterns:
            candidate = pattern.format(domain=domain_base)
            # Azure container names must be lowercase, alphanumeric, and hyphens
            candidate = candidate.replace(".", "").replace("_", "")
            if 3 <= len(candidate) <= 63 and re.match(r"^[a-z0-9-]+$", candidate):
                candidates.append(candidate)

        return candidates

    def _discover_via_dns(self, domain: str) -> tuple[List[str], List[str]]:
        """Discover buckets via DNS CNAME records."""
        s3_buckets = []
        azure_blobs = []

        try:
            # Try to resolve DNS records
            try:
                cname_records = dns.resolver.resolve(domain, "CNAME")
                for record in cname_records:
                    cname_target = str(record.target).rstrip(".")

                    # Check for S3
                    s3_match = re.search(
                        r"([a-z0-9-]+)\.s3[.-]([a-z0-9-]*\.)?amazonaws\.com",
                        cname_target,
                        re.IGNORECASE,
                    )
                    if s3_match:
                        s3_buckets.append(s3_match.group(1))

                    # Check for Azure
                    azure_match = re.search(
                        r"([a-z0-9]+)\.blob\.core\.windows\.net", cname_target, re.IGNORECASE
                    )
                    if azure_match:
                        azure_blobs.append(azure_match.group(1))
            except dns.resolver.NXDOMAIN:
                pass
            except dns.resolver.NoAnswer:
                pass

            # Try MX records for variations
            try:
                mx_records = dns.resolver.resolve(domain, "MX")
                for record in mx_records:
                    mx_target = str(record.exchange).rstrip(".")
                    if "s3" in mx_target.lower():
                        s3_match = re.search(
                            r"([a-z0-9-]+)\.s3", mx_target, re.IGNORECASE
                        )
                        if s3_match:
                            s3_buckets.append(s3_match.group(1))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass

        except Exception as e:
            logger.debug(f"DNS discovery failed: {e}")

        return s3_buckets, azure_blobs

    def _discover_via_search(self, domain_base: str) -> tuple[List[str], List[str]]:
        """Discover buckets via public search (Google and DuckDuckGo)."""
        s3_buckets = []
        azure_blobs = []

        # S3 URL patterns to search for
        s3_search_queries = [
            f"site:s3.amazonaws.com {domain_base}",
            f"site:s3-website {domain_base}",
            f"{domain_base} s3.amazonaws.com",
        ]

        # Azure URL patterns to search for
        azure_search_queries = [
            f"site:blob.core.windows.net {domain_base}",
            f"{domain_base} blob.core.windows.net",
        ]

        # Try DuckDuckGo search (no auth required, but limited)
        for query in s3_search_queries:
            try:
                results = self._search_duckduckgo(query)
                for result in results:
                    # Extract S3 bucket names from URLs
                    bucket_matches = re.findall(r"([a-z0-9-]+)\.s3", result, re.IGNORECASE)
                    s3_buckets.extend(bucket_matches)
            except Exception as e:
                logger.debug(f"DuckDuckGo S3 search failed: {e}")

        for query in azure_search_queries:
            try:
                results = self._search_duckduckgo(query)
                for result in results:
                    # Extract Azure storage account names
                    account_matches = re.findall(
                        r"([a-z0-9]+)\.blob\.core\.windows\.net", result, re.IGNORECASE
                    )
                    azure_blobs.extend(account_matches)
            except Exception as e:
                logger.debug(f"DuckDuckGo Azure search failed: {e}")

        return list(set(s3_buckets)), list(set(azure_blobs))

    def _search_duckduckgo(self, query: str) -> List[str]:
        """Perform DuckDuckGo search and extract results."""
        results = []
        try:
            # DuckDuckGo lite (no JavaScript required)
            url = "https://duckduckgo.com/lite/"
            params = {"q": query, "kl": "us-en"}

            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()

            # Extract URLs from response
            url_pattern = r'href=["\']?(https?://[^\s"\'<>]+)'
            matches = re.findall(url_pattern, response.text)
            results.extend(matches[:5])  # Limit to first 5 results

        except Exception as e:
            logger.debug(f"DuckDuckGo search error: {e}")

        return results
