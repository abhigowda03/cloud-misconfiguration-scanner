"""S3 bucket vulnerability scanner module."""

import boto3
import requests
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


class S3Scanner:
    """Scanner for detecting S3 bucket misconfigurations and vulnerabilities."""

    def __init__(self):
        """Initialize S3 scanner with anonymous credentials."""
        # Use anonymous credentials to check public access
        self.s3_client = boto3.client(
            "s3",
            aws_access_key_id="",
            aws_secret_access_key="",
            region_name="us-east-1",
            config=Config(
                signature_version="s3v4",
                retries={"max_attempts": 3, "mode": "standard"},
                connect_timeout=5,
                read_timeout=5,
            ),
        )
        self.s3_resource = boto3.resource(
            "s3",
            aws_access_key_id="",
            aws_secret_access_key="",
            region_name="us-east-1",
        )

    def scan_buckets(self, bucket_names: List[str]) -> List[Dict[str, Any]]:
        """
        Scan multiple S3 buckets for vulnerabilities.

        Args:
            bucket_names: List of bucket names to scan

        Returns:
            List of vulnerability dictionaries
        """
        vulnerabilities = []

        for bucket_name in bucket_names:
            logger.info(f"Scanning S3 bucket: {bucket_name}")
            try:
                result = self._check_bucket(bucket_name)
                if result:
                    vulnerabilities.append(result)
            except Exception as e:
                logger.error(f"Error scanning bucket {bucket_name}: {e}")

        return vulnerabilities

    def _check_bucket(self, bucket_name: str) -> Optional[Dict[str, Any]]:
        """
        Check a single S3 bucket for vulnerabilities.

        Args:
            bucket_name: S3 bucket name

        Returns:
            Dictionary with vulnerability details or None if no issues
        """
        findings = {
            "service": "S3",
            "bucket_name": bucket_name,
            "url": f"https://{bucket_name}.s3.amazonaws.com",
            "vulnerabilities": [],
            "risk_level": "LOW",
            "details": {},
        }

        # Check if bucket exists and is accessible
        try:
            # Check public access via HTTP
            response = requests.head(findings["url"], timeout=5, allow_redirects=False)
            if response.status_code == 200:
                findings["vulnerabilities"].append("BUCKET_PUBLICLY_ACCESSIBLE")
                findings["details"]["http_accessible"] = True
        except requests.exceptions.RequestException as e:
            logger.debug(f"HTTP access check for {bucket_name}: {e}")

        # Check list objects (read access)
        try:
            self.s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
            findings["vulnerabilities"].append("BUCKET_LIST_ACCESSIBLE")
            findings["details"]["list_objects"] = True
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "NoSuchBucket":
                return None
            elif error_code in ["AccessDenied", "SignatureDoesNotMatch"]:
                findings["details"]["list_objects"] = False
            else:
                logger.debug(f"S3 list_objects_v2 returned ClientError for {bucket_name}: {e}")
        except EndpointConnectionError as e:
            logger.debug(f"S3 endpoint connection error for {bucket_name}: {e}")
            findings["details"]["list_objects"] = False
        except Exception as e:
            logger.debug(f"List objects check for {bucket_name}: {e}")

        # Check write access
        try:
            test_key = ".access-check-test"
            self.s3_client.put_object(
                Bucket=bucket_name, Key=test_key, Body=b"test"
            )
            findings["vulnerabilities"].append("BUCKET_WRITE_ACCESSIBLE")
            findings["details"]["put_object"] = True

            # Clean up test file
            try:
                self.s3_client.delete_object(Bucket=bucket_name, Key=test_key)
            except Exception:
                pass
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            findings["details"]["put_object"] = error_code not in [
                "AccessDenied",
                "SignatureDoesNotMatch",
            ]
        except Exception as e:
            logger.debug(f"Write access check for {bucket_name}: {e}")

        # Check bucket policy
        try:
            policy = self.s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_text = policy.get("Policy", "")
            if "Principal" in policy_text and ("*" in policy_text or "AWS: *" in policy_text):
                findings["vulnerabilities"].append("BUCKET_POLICY_PUBLIC")
                findings["details"]["public_policy"] = True
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                logger.debug(f"Policy check for {bucket_name}: {e}")
        except Exception as e:
            logger.debug(f"Bucket policy check failed: {e}")

        # Check versioning
        try:
            versioning = self.s3_client.get_bucket_versioning(Bucket=bucket_name)
            if versioning.get("Status") == "Enabled":
                findings["details"]["versioning_enabled"] = True
        except Exception as e:
            logger.debug(f"Versioning check for {bucket_name}: {e}")

        # Check encryption
        try:
            encryption = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
            findings["details"]["encryption_enabled"] = True
        except ClientError as e:
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                findings["details"]["encryption_enabled"] = False
                if findings["vulnerabilities"]:
                    findings["vulnerabilities"].append("BUCKET_NO_ENCRYPTION")
        except Exception as e:
            logger.debug(f"Encryption check for {bucket_name}: {e}")

        # Check block public access
        try:
            block_config = self.s3_client.get_public_access_block(Bucket=bucket_name)
            config = block_config.get("PublicAccessBlockConfiguration", {})
            findings["details"]["block_public_access"] = config.get(
                "BlockPublicAcls", False
            )
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
                logger.debug(f"Block public access check: {e}")
        except Exception as e:
            logger.debug(f"Block public access check failed: {e}")

        # Determine risk level
        if "BUCKET_WRITE_ACCESSIBLE" in findings["vulnerabilities"]:
            findings["risk_level"] = "CRITICAL"
        elif (
            "BUCKET_LIST_ACCESSIBLE" in findings["vulnerabilities"]
            and "BUCKET_PUBLICLY_ACCESSIBLE" in findings["vulnerabilities"]
        ):
            findings["risk_level"] = "HIGH"
        elif (
            "BUCKET_LIST_ACCESSIBLE" in findings["vulnerabilities"]
            or "BUCKET_PUBLICLY_ACCESSIBLE" in findings["vulnerabilities"]
            or "BUCKET_POLICY_PUBLIC" in findings["vulnerabilities"]
        ):
            findings["risk_level"] = "MEDIUM"
        elif not findings["details"].get("encryption_enabled"):
            findings["risk_level"] = "LOW"
        else:
            return None  # No vulnerabilities found

        return findings if findings["vulnerabilities"] else None
