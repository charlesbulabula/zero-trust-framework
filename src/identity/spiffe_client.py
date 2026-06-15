import logging
import ssl
import threading
import time
from typing import Optional, Tuple

import grpc
from spiffe.workloadapi import WorkloadApiClient
from spiffe.workloadapi.x509_source import X509Source
from spiffe.bundle.x509_bundle.x509_bundle import X509Bundle
from spiffe.svid.x509_svid import X509Svid

logger = logging.getLogger(__name__)

DEFAULT_WORKLOAD_API_ADDR = "unix:///tmp/spire-agent/public/api.sock"
REFRESH_BEFORE_EXPIRY_SECONDS = 60


class SpiffeClientError(Exception):
    pass


class SpiffeClient:
    def __init__(
        self,
        workload_api_addr: str = DEFAULT_WORKLOAD_API_ADDR,
        trust_domain: str = "cluster.local",
    ):
        self.workload_api_addr = workload_api_addr
        self.trust_domain = trust_domain
        self._current_svid: Optional[X509Svid] = None
        self._current_bundle: Optional[X509Bundle] = None
        self._svid_lock = threading.RLock()
        self._refresh_timer: Optional[threading.Timer] = None
        self._stopped = threading.Event()

        self._source = self._connect()
        self._fetch_and_store()
        logger.info("SpiffeClient initialized with workload API at %s", workload_api_addr)

    def _connect(self) -> X509Source:
        try:
            source = X509Source(workload_api_client=WorkloadApiClient(self.workload_api_addr))
            return source
        except Exception as exc:
            raise SpiffeClientError(f"Failed to connect to workload API at {self.workload_api_addr}: {exc}") from exc

    def _fetch_and_store(self):
        try:
            svid = self._source.svid
            bundle = self._source.get_bundle_for_trust_domain(self.trust_domain)
            with self._svid_lock:
                self._current_svid = svid
                self._current_bundle = bundle
            expiry = svid.expiry_time
            self._schedule_refresh(expiry)
            logger.info(
                "Fetched SVID: spiffe_id=%s expires_at=%s",
                svid.spiffe_id,
                expiry,
            )
        except Exception as exc:
            logger.error("Failed to fetch SVID: %s", exc)
            raise SpiffeClientError(f"SVID fetch failed: {exc}") from exc

    def _schedule_refresh(self, expiry_time):
        if self._refresh_timer:
            self._refresh_timer.cancel()
        now = time.time()
        if hasattr(expiry_time, "timestamp"):
            expiry_ts = expiry_time.timestamp()
        else:
            expiry_ts = float(expiry_time)
        delay = max(0, expiry_ts - now - REFRESH_BEFORE_EXPIRY_SECONDS)
        self._refresh_timer = threading.Timer(delay, self._on_refresh_timer)
        self._refresh_timer.daemon = True
        self._refresh_timer.start()
        logger.debug("SVID refresh scheduled in %.1f seconds", delay)

    def _on_refresh_timer(self):
        if self._stopped.is_set():
            return
        logger.info("SVID refresh timer fired, fetching new SVID")
        try:
            self._fetch_and_store()
        except Exception as exc:
            logger.error("SVID refresh failed: %s, retrying in 30s", exc)
            retry_timer = threading.Timer(30.0, self._on_refresh_timer)
            retry_timer.daemon = True
            retry_timer.start()

    def fetch_svid(self) -> Tuple[bytes, bytes]:
        with self._svid_lock:
            if self._current_svid is None:
                raise SpiffeClientError("No SVID available")
            cert_pem = self._current_svid.cert_chain_pem
            key_pem = self._current_svid.private_key_pem
        return cert_pem, key_pem

    def get_ssl_context(self, verify_peer: bool = True) -> ssl.SSLContext:
        cert_pem, key_pem = self.fetch_svid()

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT if verify_peer else ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.verify_mode = ssl.CERT_REQUIRED if verify_peer else ssl.CERT_OPTIONAL

        import tempfile, os
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cert_f:
            cert_f.write(cert_pem)
            cert_path = cert_f.name
        with tempfile.NamedTemporaryFile(delete=False, suffix=".key") as key_f:
            key_f.write(key_pem)
            key_path = key_f.name

        try:
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            with self._svid_lock:
                if self._current_bundle:
                    bundle_pem = self._current_bundle.x509_authorities_pem
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as ca_f:
                        ca_f.write(bundle_pem)
                        ca_path = ca_f.name
                    ctx.load_verify_locations(ca_path)
                    os.unlink(ca_path)
        finally:
            os.unlink(cert_path)
            os.unlink(key_path)

        return ctx

    def get_spiffe_id(self) -> Optional[str]:
        with self._svid_lock:
            if self._current_svid:
                return str(self._current_svid.spiffe_id)
        return None

    def close(self):
        self._stopped.set()
        if self._refresh_timer:
            self._refresh_timer.cancel()
        if self._source:
            self._source.close()
        logger.info("SpiffeClient closed")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

# _r 20260610104505-f04adb82
