"""File-blob storage for the AgentLink relay — Cloudflare R2 in
production, a local directory in dev/test.

SEALED BY DESIGN: agents never see this layer at all. No agent gets
Cloudflare/R2 credentials, a bucket name, or direct object access.
Files move ONLY through the AgentLink line: the relay validates the
caller's identity and group membership server-side, then proxies
CIPHERTEXT (blobs are already end-to-end encrypted by the sending
client) to/from the store. There is deliberately no list/browse
operation on the protocol; deletions happen only through protocol
rules executed by the relay (see relay blob_delete).

Operator configuration for R2 (relay-side environment only):
    R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET
    R2_ENDPOINT (optional override; S3-compatible endpoint URL)
Select with AGENTLINK_BLOB_BACKEND=r2|local or --blob-backend.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


class BlobNotFound(Exception):
    pass


class LocalBlobStore:
    """Dev/test blob store: one file per blob id under a 0700 dir."""

    def __init__(self, root: str | Path):
        self.root = Path(root).expanduser()
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass

    def _path(self, blob_id: str) -> Path:
        if not blob_id.replace("-", "").isalnum():
            raise ValueError("bad blob id")
        return self.root / blob_id

    def put(self, blob_id: str, data: bytes) -> None:
        p = self._path(blob_id)
        tmp = p.with_suffix(".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, p)
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass

    def get(self, blob_id: str) -> bytes:
        p = self._path(blob_id)
        if not p.exists():
            raise BlobNotFound(blob_id)
        return p.read_bytes()

    def delete(self, blob_id: str) -> None:
        p = self._path(blob_id)
        if p.exists():
            p.unlink()

    def list_ids(self) -> list[str]:
        # Operator-side only (backups). Never exposed on the protocol.
        return sorted(f.name for f in self.root.iterdir() if f.is_file())


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class R2BlobStore:
    """Cloudflare R2 via its S3-compatible API, signed with AWS SigV4
    using only the standard library. Relay-operator credentials only."""

    def __init__(self, bucket: str, access_key: str, secret_key: str,
                 account_id: str = "", endpoint: str | None = None,
                 region: str = "auto"):
        if not bucket or not access_key or not secret_key:
            raise ValueError("R2 needs bucket + access key + secret key")
        self.bucket = bucket
        self._ak = access_key
        self._sk = secret_key
        self.region = region
        self.endpoint = (endpoint or
                         f"https://{account_id}.r2.cloudflarestorage.com"
                         ).rstrip("/")

    @classmethod
    def from_env(cls) -> "R2BlobStore":
        return cls(
            bucket=os.environ.get("R2_BUCKET", ""),
            access_key=os.environ.get("R2_ACCESS_KEY_ID", ""),
            secret_key=os.environ.get("R2_SECRET_ACCESS_KEY", ""),
            account_id=os.environ.get("R2_ACCOUNT_ID", ""),
            endpoint=os.environ.get("R2_ENDPOINT"))

    def _signed_request(self, method: str, blob_id: str,
                        data: bytes | None = None) -> bytes:
        parsed = urllib.parse.urlparse(self.endpoint)
        host = parsed.netloc
        uri = (f"{parsed.path}/{self.bucket}/"
               f"{urllib.parse.quote(blob_id, safe='')}")
        body = data or b""
        payload_hash = _sha256_hex(body)
        now = datetime.now(timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")
        headers = {
            "host": host,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amz_date,
        }
        signed = "host;x-amz-content-sha256;x-amz-date"
        canonical_headers = "".join(f"{k}:{headers[k]}\n"
                                    for k in signed.split(";"))
        canonical = "\n".join([method, uri, "", canonical_headers,
                               signed, payload_hash])
        scope = f"{date_stamp}/{self.region}/s3/aws4_request"
        to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope,
                             _sha256_hex(canonical.encode())])

        def _hmac(key: bytes, msg: str) -> bytes:
            return hmac.new(key, msg.encode(), hashlib.sha256).digest()

        k_date = _hmac(("AWS4" + self._sk).encode(), date_stamp)
        k_region = _hmac(k_date, self.region)
        k_service = _hmac(k_region, "s3")
        k_signing = _hmac(k_service, "aws4_request")
        signature = hmac.new(k_signing, to_sign.encode(),
                             hashlib.sha256).hexdigest()
        auth = (f"AWS4-HMAC-SHA256 Credential={self._ak}/{scope}, "
                f"SignedHeaders={signed}, Signature={signature}")
        url = f"{self.endpoint}/{self.bucket}/" + \
            urllib.parse.quote(blob_id, safe="")
        last = None
        for attempt in range(3):
            req = urllib.request.Request(url, data=data, method=method)
            req.add_header("Authorization", auth)
            req.add_header("x-amz-date", amz_date)
            req.add_header("x-amz-content-sha256", payload_hash)
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    return resp.read()
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    raise BlobNotFound(blob_id)
                if exc.code < 500:
                    raise
                last = exc
            except Exception as exc:  # proxy drop / timeout: retry
                last = exc
            if attempt < 2:
                import time as _time
                _time.sleep(0.6 * (attempt + 1))
        raise last

    def put(self, blob_id: str, data: bytes) -> None:
        self._signed_request("PUT", blob_id, data)

    def get(self, blob_id: str) -> bytes:
        return self._signed_request("GET", blob_id)

    def delete(self, blob_id: str) -> None:
        self._signed_request("DELETE", blob_id)

    def list_ids(self) -> list[str]:
        raise NotImplementedError(
            "R2 listing is operator-side only (use the R2 console/API);"
            " backups enumerate blobs from the relay DB manifest")


def create_blob_store(kind: str | None = None, local_root: str | None = None):
    kind = (kind or os.environ.get("AGENTLINK_BLOB_BACKEND")
            or "local").lower()
    if kind == "local":
        return LocalBlobStore(
            local_root or os.path.expanduser("~/.agentlink/blobs"))
    if kind == "r2":
        return R2BlobStore.from_env()
    raise ValueError(f"unknown blob backend {kind!r} (use local|r2)")
