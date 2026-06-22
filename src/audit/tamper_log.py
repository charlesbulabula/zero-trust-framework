import hashlib
import hmac
import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64


class TamperEvidentLog:
    def __init__(self, filepath: str, secret_key: bytes):
        if not secret_key:
            raise ValueError("secret_key must not be empty")
        self.filepath = Path(filepath)
        self._secret_key = secret_key
        self._lock = threading.Lock()
        self._seq = 0
        self._prev_hash = GENESIS_HASH

        if self.filepath.exists():
            self._load_state()
        else:
            self.filepath.parent.mkdir(parents=True, exist_ok=True)
            logger.info("Creating new tamper-evident log at %s", filepath)

    def _load_state(self):
        last_entry = None
        with open(self.filepath, "r") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    last_entry = json.loads(line)
                except json.JSONDecodeError as exc:
                    logger.warning("Malformed log line, skipping: %s", exc)

        if last_entry:
            self._seq = last_entry.get("seq", 0)
            self._prev_hash = last_entry.get("hmac", GENESIS_HASH)
            logger.info("Resumed log at seq=%d", self._seq)

    def _compute_hmac(self, prev_hash: str, data_json: str) -> str:
        message = (prev_hash + data_json).encode("utf-8")
        return hmac.new(self._secret_key, message, hashlib.sha256).hexdigest()

    def append(self, data_dict: dict) -> dict:
        with self._lock:
            self._seq += 1
            seq = self._seq
            ts = datetime.now(timezone.utc).isoformat()
            data_json = json.dumps(data_dict, sort_keys=True, default=str)
            mac = self._compute_hmac(self._prev_hash, data_json)

            entry = {
                "seq": seq,
                "ts": ts,
                "data": data_dict,
                "prev_hash": self._prev_hash,
                "hmac": mac,
            }

            with open(self.filepath, "a") as fh:
                fh.write(json.dumps(entry) + "\n")
                fh.flush()
                os.fsync(fh.fileno())

            self._prev_hash = mac
            logger.debug("Appended log entry seq=%d", seq)
            return entry

    def verify_chain(self, filepath: Optional[str] = None) -> Tuple[bool, Optional[int]]:
        target = Path(filepath) if filepath else self.filepath
        if not target.exists():
            logger.warning("Log file does not exist: %s", target)
            return True, None

        prev_hash = GENESIS_HASH
        expected_seq = 1

        with open(target, "r") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    logger.error("Line %d: malformed JSON", lineno)
                    return False, lineno

                seq = entry.get("seq")
                stored_prev = entry.get("prev_hash")
                stored_hmac = entry.get("hmac")
                data_dict = entry.get("data", {})

                if seq != expected_seq:
                    logger.error(
                        "Sequence gap: expected %d, got %d at line %d",
                        expected_seq,
                        seq,
                        lineno,
                    )
                    return False, seq

                if stored_prev != prev_hash:
                    logger.error(
                        "prev_hash mismatch at seq=%d: expected %s, got %s",
                        seq,
                        prev_hash,
                        stored_prev,
                    )
                    return False, seq

                data_json = json.dumps(data_dict, sort_keys=True, default=str)
                computed_hmac = self._compute_hmac(prev_hash, data_json)

                if not hmac.compare_digest(computed_hmac, stored_hmac):
                    logger.error("HMAC mismatch at seq=%d — log has been tampered with!", seq)
                    return False, seq

                prev_hash = stored_hmac
                expected_seq += 1

        total = expected_seq - 1
        logger.info("Log chain verified: %d entries are intact", total)
        return True, None

    def read_entries(self, filepath: Optional[str] = None):
        target = Path(filepath) if filepath else self.filepath
        if not target.exists():
            return
        with open(target, "r") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue

    @property
    def current_seq(self) -> int:
        return self._seq

# _r 20260622133914-9ea982fa
