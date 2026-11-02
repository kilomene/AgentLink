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
        status, _headers, body = self._request_raw(
            method, blob_id, data=data, _auth=(auth, amz_date, payload_hash),
            _url=url)
        return body

    def _request_once(self, method: str, blob_id: str, _auth,
                      _url, data: bytes | None = None,
                      extra_headers: dict | None = None):
        """A single signed S3 request attempt. Returns (status,
        headers, body). Raises BlobNotFound on 404; transport errors
        (including http.client.IncompleteRead, whose .partial carries
        the bytes that DID arrive) propagate to the caller.
        extra_headers (e.g. Range) are sent unsigned — they are not
        part of the SigV4 signed-header set."""
        auth, amz_date, payload_hash = _auth
        req = urllib.request.Request(_url, data=data, method=method)
        req.add_header("Authorization", auth)
        req.add_header("x-amz-date", amz_date)
        req.add_header("x-amz-content-sha256", payload_hash)
        for k, v in (extra_headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.status, resp.headers, resp.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise BlobNotFound(blob_id)
            raise

    def _request_raw(self, method: str, blob_id: str,
                     data: bytes | None = None,
                     extra_headers: dict | None = None,
                     attempts: int = 3, _auth=None, _url=None):
        """_request_once with bounded retries on transient transport
        errors (proxy drops, truncated bodies, 5xx)."""
        last = None
        for attempt in range(attempts):
            try:
                return self._request_once(
                    method, blob_id, _auth, _url, data=data,
                    extra_headers=extra_headers)
            except BlobNotFound:
                raise
            except urllib.error.HTTPError as exc:
                if exc.code < 500:
                    raise
                last = exc
            except Exception as exc:  # proxy drop / truncated: retry
                last = exc
            if attempt < attempts - 1:
                import time as _time
                _time.sleep(0.6 * (attempt + 1))
        raise last

    def put(self, blob_id: str, data: bytes) -> None:
        self._signed_request("PUT", blob_id, data)

    def get(self, blob_id: str) -> bytes:
        import http.client as _hc
        try:
            return self._signed_request("GET", blob_id)
        except _hc.IncompleteRead:
            # The egress path intermittently truncates LARGE response
            # bodies mid-read (observed cuts anywhere in the first
            # ~8-26 KB through the proxy, varying per attempt). Fall
            # back to a resumable ranged assembly.
            return self._get_ranged(blob_id)

    _RANGE_SLICE = 32768
    _RANGE_MAX_STALLS = 16

    def _sign_get(self, blob_id: str):
        """SigV4 auth tuple + URL for a bodyless GET of blob_id —
        identical signature to _signed_request('GET', ...)."""
        parsed = urllib.parse.urlparse(self.endpoint)
        host = parsed.netloc
        uri = (f"{parsed.path}/{self.bucket}/"
               f"{urllib.parse.quote(blob_id, safe='')}")
        payload_hash = _sha256_hex(b"")
        now = datetime.now(timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")
        headers = {"host": host,
                   "x-amz-content-sha256": payload_hash,
                   "x-amz-date": amz_date}
        signed = "host;x-amz-content-sha256;x-amz-date"
        canonical_headers = "".join(f"{k}:{headers[k]}\n"
                                    for k in signed.split(";"))
        canonical = "\n".join(["GET", uri, "", canonical_headers,
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
        return (auth, amz_date, payload_hash), url

    def _get_ranged(self, blob_id: str) -> bytes:
        """Resumable ranged assembly: request slices starting at the
        first byte not yet held; a truncated response contributes its
        partial bytes (IncompleteRead.partial) and the next request
        resumes exactly there. Progress is monotone, so a flickering
        transport still converges; only repeated ZERO-progress
        attempts (stalls) fail the read."""
        import http.client as _hc
        import time as _time
        auth, url = self._sign_get(blob_id)
        out = bytearray()
        total: int | None = None
        stalls = 0
        while total is None or len(out) < total:
            if stalls > self._RANGE_MAX_STALLS:
                raise OSError(
                    f"ranged GET for {blob_id} stalled at "
                    f"{len(out)}/{total} after {stalls} empty attempts")
            start = len(out)
            end = (total - 1) if total is not None else \
                start + self._RANGE_SLICE - 1
            if total is not None:
                end = min(end, total - 1)
            try:
                status, headers, body = self._request_once(
                    "GET", blob_id, auth, url,
                    extra_headers={"Range": f"bytes={start}-{end}"})
            except _hc.IncompleteRead as exc:
                partial = exc.partial or b""
                if partial:
                    out += partial
                    stalls = 0
                else:
                    stalls += 1
                    _time.sleep(0.4)
                continue
            except BlobNotFound:
                raise
            except Exception:
                stalls += 1
                _time.sleep(0.4)
                continue
            if status == 200:
                if start == 0:
                    return body
                raise OSError(f"ranged GET for {blob_id}: server "
                              "ignored Range mid-assembly")
            cr = headers.get("Content-Range") or ""
            try:
                total = int(cr.rsplit("/", 1)[1])
            except Exception:
                raise OSError(f"ranged GET without Content-Range "
                              f"for {blob_id}: {cr!r}")
            if body:
                out += body
                stalls = 0
            else:
                stalls += 1
        if total is not None and len(out) != total:
            raise OSError(f"ranged GET size mismatch for {blob_id}: "
                          f"{len(out)} != {total}")
        return bytes(out)

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
