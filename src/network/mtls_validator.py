import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.oid import ExtensionOID

logger = logging.getLogger(__name__)

SPIFFE_URI_PREFIX = "spiffe://"


@dataclass
class ValidationResult:
    valid: bool
    spiffe_id: Optional[str] = None
    error: Optional[str] = None

    def __bool__(self):
        return self.valid


class MTLSValidator:
    def __init__(self, crl_distribution_points: Optional[List[str]] = None):
        self._crl_distribution_points = crl_distribution_points or []
        self._revoked_serials: set = set()
        logger.info("MTLSValidator initialized")

    def _load_cert(self, cert_pem: bytes) -> x509.Certificate:
        if isinstance(cert_pem, str):
            cert_pem = cert_pem.encode()
        return x509.load_pem_x509_certificate(cert_pem, default_backend())

    def extract_spiffe_uri(self, cert_pem: bytes) -> Optional[str]:
        try:
            cert = self._load_cert(cert_pem)
        except Exception as exc:
            logger.error("Failed to parse certificate: %s", exc)
            return None

        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san = san_ext.value
        except ExtensionNotFound:
            logger.debug("Certificate has no SAN extension")
            return None
        except Exception as exc:
            logger.error("Error reading SAN extension: %s", exc)
            return None

        for uri_name in san.get_values_for_type(x509.UniformResourceIdentifier):
            uri_str = str(uri_name)
            if uri_str.startswith(SPIFFE_URI_PREFIX):
                logger.debug("Found SPIFFE URI: %s", uri_str)
                return uri_str

        return None

    def _check_not_expired(self, cert: x509.Certificate) -> Optional[str]:
        now = datetime.now(timezone.utc)
        not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)

        if now < not_before:
            return f"Certificate not yet valid (valid from {not_before.isoformat()})"
        if now > not_after:
            return f"Certificate expired at {not_after.isoformat()}"
        return None

    def _check_crl(self, cert: x509.Certificate) -> Optional[str]:
        serial = cert.serial_number
        if serial in self._revoked_serials:
            return f"Certificate serial {serial} is in CRL (revoked)"
        return None

    def _validate_trust_domain(self, spiffe_id: str, allowed_trust_domain: str) -> Optional[str]:
        if not spiffe_id.startswith(SPIFFE_URI_PREFIX):
            return f"Not a valid SPIFFE URI: {spiffe_id}"

        rest = spiffe_id[len(SPIFFE_URI_PREFIX):]
        parts = rest.split("/", 1)
        trust_domain = parts[0]

        if trust_domain != allowed_trust_domain:
            return (
                f"Trust domain mismatch: expected '{allowed_trust_domain}', "
                f"got '{trust_domain}'"
            )
        return None

    def validate_peer(self, cert_pem: bytes, allowed_trust_domain: str) -> ValidationResult:
        try:
            cert = self._load_cert(cert_pem)
        except Exception as exc:
            return ValidationResult(valid=False, error=f"Failed to parse certificate: {exc}")

        spiffe_id = self.extract_spiffe_uri(cert_pem)
        if not spiffe_id:
            return ValidationResult(
                valid=False,
                error="Certificate does not contain a SPIFFE URI in SAN",
            )

        trust_domain_error = self._validate_trust_domain(spiffe_id, allowed_trust_domain)
        if trust_domain_error:
            return ValidationResult(valid=False, spiffe_id=spiffe_id, error=trust_domain_error)

        expiry_error = self._check_not_expired(cert)
        if expiry_error:
            return ValidationResult(valid=False, spiffe_id=spiffe_id, error=expiry_error)

        crl_error = self._check_crl(cert)
        if crl_error:
            return ValidationResult(valid=False, spiffe_id=spiffe_id, error=crl_error)

        logger.info("mTLS peer validated successfully: spiffe_id=%s", spiffe_id)
        return ValidationResult(valid=True, spiffe_id=spiffe_id)

    def load_crl(self, crl_pem: bytes):
        try:
            crl = x509.load_pem_x509_crl(crl_pem, default_backend())
            for revoked in crl:
                self._revoked_serials.add(revoked.serial_number)
            logger.info("Loaded CRL with %d revoked certificates", len(self._revoked_serials))
        except Exception as exc:
            logger.error("Failed to load CRL: %s", exc)

    def clear_crl(self):
        self._revoked_serials.clear()

# _r 20260629155806-cc32b55d
