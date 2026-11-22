"""Bounded-chunk streaming upload helpers with concurrent SHA-256 hashing.

Trust boundary
--------------
Upload bytes cross the public HTTP boundary into temporary disk under a
hard size limit.  Hashing happens while bytes are copied so callers never
need a second full-file read.  Failure messages are stable and never echo
payload bytes, filenames beyond what Flask already accepted, or secrets.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Dict, Iterable, Mapping, Optional, Tuple, Union

from flask import g
from werkzeug.datastructures import FileStorage
from werkzeug.exceptions import RequestEntityTooLarge

# ---------------------------------------------------------------------------
# Bounded chunk sizing
# ---------------------------------------------------------------------------

DEFAULT_CHUNK_BYTES = 65_536  # 64 KiB
MIN_CHUNK_BYTES = 4_096  # 4 KiB
MAX_CHUNK_BYTES = 1_048_576  # 1 MiB


def clamp_chunk_bytes(value: int | None, *, enforce_min: bool = False) -> int:
    """Return a positive chunk size capped at ``MAX_CHUNK_BYTES``.

    When *enforce_min* is true (config/env path), values below ``MIN_CHUNK_BYTES``
    are raised to the minimum so operators cannot accidentally configure tiny
    reads. Explicit API callers may pass smaller sizes for tests.
    """
    if value is None:
        return DEFAULT_CHUNK_BYTES
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return DEFAULT_CHUNK_BYTES
    if parsed <= 0:
        return DEFAULT_CHUNK_BYTES
    if enforce_min and parsed < MIN_CHUNK_BYTES:
        return MIN_CHUNK_BYTES
    if parsed > MAX_CHUNK_BYTES:
        return MAX_CHUNK_BYTES
    return parsed


def _upload_config():
    try:
        return getattr(g, "upload_config", None)
    except RuntimeError:
        return None


def resolve_chunk_bytes(explicit: int | None = None) -> int:
    """Resolve chunk size from an explicit value, Flask ``g``, or the default."""
    if explicit is not None:
        return clamp_chunk_bytes(explicit, enforce_min=False)
    config = _upload_config()
    if config is not None:
        return clamp_chunk_bytes(
            getattr(config, "upload_chunk_bytes", None), enforce_min=True
        )
    return DEFAULT_CHUNK_BYTES


def resolve_max_bytes(explicit: int | None = None) -> int:
    """Resolve the hard upload size limit (0 = unlimited, not recommended)."""
    if explicit is not None:
        return max(0, int(explicit))
    config = _upload_config()
    if config is not None:
        for attr in ("upload_max_bytes", "max_video_bytes"):
            value = getattr(config, attr, None)
            if value is not None:
                return max(0, int(value))
    return 0


def resolve_temp_dir(explicit: str | Path | None = None) -> Optional[str]:
    if explicit is not None:
        return str(explicit)
    config = _upload_config()
    if config is not None:
        value = getattr(config, "upload_temp_dir", None)
        if value:
            return str(value)
    return None


def hash_stream_to_path(
    source: BinaryIO,
    destination: Union[str, Path],
    *,
    chunk_size: int | None = None,
    max_size: int | None = None,
    temp_dir: str | Path | None = None,
) -> Tuple[str, int]:
    """Copy *source* to *destination* in bounded chunks while hashing SHA-256.

    Returns ``(hex_digest, bytes_written)``.
    Raises ``RequestEntityTooLarge`` when *max_size* is exceeded mid-stream.
    Temporary files are cleaned up on failure; destination is not left partial
    unless an OS error occurs after the final rename.
    """
    bounded = resolve_chunk_bytes(chunk_size)
    limit = resolve_max_bytes(max_size)
    dest = Path(destination)
    dest.parent.mkdir(parents=True, exist_ok=True)

    hasher = hashlib.sha256()
    bytes_written = 0
    tmp_path: Optional[Path] = None

    try:
        fd, tmp_name = tempfile.mkstemp(
            prefix="harpocrates-stream-",
            dir=resolve_temp_dir(temp_dir),
        )
        tmp_path = Path(tmp_name)
        with os.fdopen(fd, "wb") as tmp_file:
            while True:
                chunk = source.read(bounded)
                if not chunk:
                    break
                if limit > 0 and bytes_written + len(chunk) > limit:
                    raise RequestEntityTooLarge("Upload exceeds size limit")
                tmp_file.write(chunk)
                hasher.update(chunk)
                bytes_written += len(chunk)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())

        # Atomic-ish replace into the final destination.
        shutil.move(str(tmp_path), str(dest))
        tmp_path = None
        return hasher.hexdigest(), bytes_written
    except Exception:
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        if dest.exists():
            # Do not leave a partial final artifact after a size abort.
            try:
                dest.unlink()
            except OSError:
                pass
        raise


def hash_paths_concat(
    paths: Iterable[Union[str, Path]],
    destination: Union[str, Path],
    *,
    chunk_size: int | None = None,
    max_size: int | None = None,
) -> Tuple[str, int]:
    """Concatenate *paths* into *destination* with bounded-chunk SHA-256 hashing."""
    bounded = resolve_chunk_bytes(chunk_size)
    limit = resolve_max_bytes(max_size)
    dest = Path(destination)
    dest.parent.mkdir(parents=True, exist_ok=True)

    hasher = hashlib.sha256()
    bytes_written = 0
    tmp_path: Optional[Path] = None

    try:
        fd, tmp_name = tempfile.mkstemp(prefix="harpocrates-concat-")
        tmp_path = Path(tmp_name)
        with os.fdopen(fd, "wb") as out:
            for path in paths:
                with Path(path).open("rb") as handle:
                    while True:
                        chunk = handle.read(bounded)
                        if not chunk:
                            break
                        if limit > 0 and bytes_written + len(chunk) > limit:
                            raise RequestEntityTooLarge("Upload exceeds size limit")
                        out.write(chunk)
                        hasher.update(chunk)
                        bytes_written += len(chunk)
            out.flush()
            os.fsync(out.fileno())
        shutil.move(str(tmp_path), str(dest))
        tmp_path = None
        return hasher.hexdigest(), bytes_written
    except Exception:
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        if dest.exists():
            try:
                dest.unlink()
            except OSError:
                pass
        raise


def sha256_path_bounded(
    path: Union[str, Path],
    *,
    chunk_size: int | None = None,
) -> str:
    """SHA-256 a file using bounded chunk reads (no full-file buffering)."""
    bounded = resolve_chunk_bytes(chunk_size)
    hasher = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(bounded)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


class StreamingFileStorage(FileStorage):
    """FileStorage that streams to disk in bounded chunks while hashing."""

    def __init__(
        self,
        stream: BinaryIO,
        filename: Optional[str] = None,
        content_type: Optional[str] = None,
        max_size: int = 0,
        chunk_size: int | None = None,
        temp_dir: str | Path | None = None,
    ):
        super().__init__(stream, filename, content_type=content_type)
        self._max_size = max_size
        self._chunk_size = resolve_chunk_bytes(chunk_size)
        self._temp_dir = resolve_temp_dir(temp_dir)
        self._materialized_path: Optional[Path] = None
        self._bytes_written = 0
        self._hash_computed = False
        self._digest: Optional[str] = None

    @property
    def chunk_size(self) -> int:
        return self._chunk_size

    @property
    def bytes_written(self) -> int:
        return self._bytes_written

    @property
    def computed_hash(self) -> Optional[str]:
        """Hex SHA-256 digest once the stream has been fully consumed."""
        return self._digest if self._hash_computed else None

    
    def save(self, dst, buffer_size: int = 16384) -> None:  # noqa: ARG002
        """Stream the upload to *dst* with bounded chunks and concurrent hashing.

        ``buffer_size`` is accepted for FileStorage API compatibility but the
        configured bounded chunk size always wins.
        """
        destination = Path(dst)
        if self._hash_computed and self._materialized_path and self._materialized_path.exists():
            shutil.copyfile(self._materialized_path, destination)
            return

        digest, written = hash_stream_to_path(
            self.stream,
            destination,
            chunk_size=self._chunk_size,
            max_size=self._max_size,
            temp_dir=self._temp_dir,
        )
        self._bytes_written = written
        self._digest = digest
        self._hash_computed = True
        self._materialized_path = destination

    def close(self) -> None:
        try:
            super().close()
        finally:
            # Only remove temp artifacts we own (not caller destinations).
            pass


def create_streaming_file_storage(field_storage: FileStorage) -> StreamingFileStorage:
    """Wrap a Werkzeug ``FileStorage`` with bounded-chunk streaming hashing."""
    config = _upload_config()
    max_size = resolve_max_bytes(
        getattr(config, "upload_max_bytes", None)
        if config is not None
        else None
    )
    if max_size == 0 and config is not None:
        max_size = int(getattr(config, "max_video_bytes", 0) or 0)
    chunk_size = resolve_chunk_bytes(
        getattr(config, "upload_chunk_bytes", None) if config is not None else None
    )
    temp_dir = resolve_temp_dir(
        getattr(config, "upload_temp_dir", None) if config is not None else None
    )
    return StreamingFileStorage(
        stream=field_storage.stream,
        filename=field_storage.filename,
        content_type=field_storage.content_type,
        max_size=max_size,
        chunk_size=chunk_size,
        temp_dir=temp_dir,
    )


# ---------------------------------------------------------------------------
# Offline upload integrity reporting for failed sessions
# ---------------------------------------------------------------------------

INTEGRITY_REPORT_SCHEMA_VERSION = 1

DIGEST_STATUS_MATCHED = "matched"
DIGEST_STATUS_MISMATCH = "mismatch"
DIGEST_STATUS_UNVERIFIED = "unverified"
DIGEST_STATUS_UNAVAILABLE = "unavailable"

BYTE_COUNT_STATUS_MATCHED = "matched"
BYTE_COUNT_STATUS_UNDERFLOW = "underflow"
BYTE_COUNT_STATUS_OVERFLOW = "overflow"
BYTE_COUNT_STATUS_UNKNOWN = "unknown"

_SAFE_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_CHUNK_FILE_RE = re.compile(r"^chunk-(\d+)$")


def _normalize_digest(digest: Optional[str]) -> Optional[str]:
    if digest is None:
        return None
    normalized = digest.strip().lower()
    return normalized or None


def _sanitize_session_id(session_id: Optional[str]) -> Optional[str]:
    """Return *session_id* only if it is an opaque identifier, never a path."""
    if session_id is None:
        return None
    candidate = session_id.strip()
    if not candidate or ".." in candidate or not _SAFE_SESSION_ID_RE.match(candidate):
        return None
    return candidate


def _classify_digest_status(
    expected_digest: Optional[str],
    observed_digest: Optional[str],
) -> str:
    if observed_digest is None:
        return DIGEST_STATUS_UNAVAILABLE
    if expected_digest is None:
        return DIGEST_STATUS_UNVERIFIED
    if observed_digest == expected_digest:
        return DIGEST_STATUS_MATCHED
    return DIGEST_STATUS_MISMATCH


def _classify_byte_count_status(
    expected_bytes: Optional[int],
    observed_bytes: int,
) -> str:
    if expected_bytes is None:
        return BYTE_COUNT_STATUS_UNKNOWN
    if observed_bytes == expected_bytes:
        return BYTE_COUNT_STATUS_MATCHED
    if observed_bytes < expected_bytes:
        return BYTE_COUNT_STATUS_UNDERFLOW
    return BYTE_COUNT_STATUS_OVERFLOW


@dataclass(frozen=True)
class ChunkIntegritySummary:
    """Privacy-safe integrity summary for a single indexed upload chunk.

    Contains only numeric indices, byte counts, and SHA-256 digest metadata —
    never uploaded media bytes or private filenames.
    """

    chunk_index: int
    observed_bytes: int
    observed_digest: Optional[str]
    expected_bytes: Optional[int] = None
    expected_digest: Optional[str] = None
    byte_count_status: str = BYTE_COUNT_STATUS_UNKNOWN
    digest_status: str = DIGEST_STATUS_UNVERIFIED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chunk_index": self.chunk_index,
            "expected_bytes": self.expected_bytes,
            "observed_bytes": self.observed_bytes,
            "byte_count_status": self.byte_count_status,
            "expected_digest": self.expected_digest,
            "observed_digest": self.observed_digest,
            "digest_status": self.digest_status,
        }


@dataclass(frozen=True)
class UploadIntegrityReport:
    """Offline integrity report for a failed (or inspected) upload session.

    Excludes uploaded media bytes, filesystem paths, and private filenames.
    """

    schema_version: int
    session_id: Optional[str]
    status: str
    failure_reason: Optional[str]
    expected_bytes: Optional[int]
    observed_bytes: int
    byte_count_status: str
    expected_digest: Optional[str]
    observed_digest: Optional[str]
    digest_status: str
    chunk_count: int
    missing_chunk_indices: Tuple[int, ...]
    chunks: Tuple[ChunkIntegritySummary, ...]
    generated_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "status": self.status,
            "failure_reason": self.failure_reason,
            "expected_bytes": self.expected_bytes,
            "observed_bytes": self.observed_bytes,
            "byte_count_status": self.byte_count_status,
            "expected_digest": self.expected_digest,
            "observed_digest": self.observed_digest,
            "digest_status": self.digest_status,
            "chunk_count": self.chunk_count,
            "missing_chunk_indices": list(self.missing_chunk_indices),
            "chunks": [chunk.to_dict() for chunk in self.chunks],
            "generated_at": self.generated_at,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)


def build_upload_integrity_report(
    *,
    session_id: Optional[str] = None,
    expected_bytes: Optional[int] = None,
    observed_bytes: int = 0,
    expected_digest: Optional[str] = None,
    observed_digest: Optional[str] = None,
    failure_reason: Optional[str] = None,
    chunks: Iterable[ChunkIntegritySummary] = (),
    missing_chunk_indices: Iterable[int] = (),
    max_bytes: Optional[int] = None,
) -> UploadIntegrityReport:
    """Construct a privacy-safe ``UploadIntegrityReport`` from session metrics."""
    norm_expected_digest = _normalize_digest(expected_digest)
    norm_observed_digest = _normalize_digest(observed_digest)
    byte_status = _classify_byte_count_status(expected_bytes, observed_bytes)
    digest_status = _classify_digest_status(norm_expected_digest, norm_observed_digest)

    chunk_tuple = tuple(chunks)
    missing_tuple = tuple(sorted(set(missing_chunk_indices)))

    inferred_reason = failure_reason
    if inferred_reason is None:
        if max_bytes is not None and max_bytes > 0 and observed_bytes > max_bytes:
            inferred_reason = "size_limit_exceeded"
        elif missing_tuple:
            inferred_reason = "chunk_gap"
        elif byte_status in (BYTE_COUNT_STATUS_UNDERFLOW, BYTE_COUNT_STATUS_OVERFLOW):
            inferred_reason = "byte_count_mismatch"
        elif digest_status == DIGEST_STATUS_MISMATCH:
            inferred_reason = "digest_mismatch"

    status = "failed" if inferred_reason is not None else "verified"

    return UploadIntegrityReport(
        schema_version=INTEGRITY_REPORT_SCHEMA_VERSION,
        session_id=_sanitize_session_id(session_id),
        status=status,
        failure_reason=inferred_reason,
        expected_bytes=expected_bytes,
        observed_bytes=observed_bytes,
        byte_count_status=byte_status,
        expected_digest=norm_expected_digest,
        observed_digest=norm_observed_digest,
        digest_status=digest_status,
        chunk_count=len(chunk_tuple),
        missing_chunk_indices=missing_tuple,
        chunks=chunk_tuple,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


def inspect_failed_upload_session(
    session_dir: Union[str, Path],
    *,
    session_id: Optional[str] = None,
    expected_bytes: Optional[int] = None,
    expected_digest: Optional[str] = None,
    expected_chunks: Optional[int] = None,
    chunk_expectations: Optional[
        Mapping[int, Tuple[Optional[int], Optional[str]]]
    ] = None,
    failure_reason: Optional[str] = None,
    chunk_size: int | None = None,
    max_size: int | None = None,
) -> UploadIntegrityReport:
    """Inspect a session directory offline and produce an ``UploadIntegrityReport``.

    Reads only ``chunk-<N>`` files in bounded chunks while computing SHA-256
    digests. Any other files in *session_dir* are ignored and their names are
    never recorded. Uploaded media bytes and filesystem paths are excluded from
    the returned report.
    """
    directory = Path(session_dir)
    if not directory.exists() or not directory.is_dir():
        return build_upload_integrity_report(
            session_id=session_id,
            expected_bytes=expected_bytes,
            observed_bytes=0,
            expected_digest=expected_digest,
            observed_digest=None,
            failure_reason=failure_reason or "missing_session",
            max_bytes=max_size,
        )

    indexed_files: list[Tuple[int, Path]] = []
    for entry in directory.iterdir():
        if not entry.is_file():
            continue
        match = _CHUNK_FILE_RE.match(entry.name)
        if match is not None:
            indexed_files.append((int(match.group(1)), entry))

    indexed_files.sort(key=lambda item: item[0])

    if not indexed_files:
        missing_indices: list[int] = (
            list(range(expected_chunks)) if expected_chunks and expected_chunks > 0 else []
        )
        return build_upload_integrity_report(
            session_id=session_id,
            expected_bytes=expected_bytes,
            observed_bytes=0,
            expected_digest=expected_digest,
            observed_digest=None,
            failure_reason=failure_reason or "empty_session",
            missing_chunk_indices=missing_indices,
            max_bytes=max_size,
        )

    bounded = resolve_chunk_bytes(chunk_size)
    combined_hasher = hashlib.sha256()
    total_observed_bytes = 0
    chunk_summaries: list[ChunkIntegritySummary] = []

    present_indices = {idx for idx, _ in indexed_files}
    upper_bound = max(present_indices) + 1
    if expected_chunks is not None and expected_chunks > upper_bound:
        upper_bound = expected_chunks
    missing_indices = [i for i in range(upper_bound) if i not in present_indices]

    for idx, chunk_path in indexed_files:
        chunk_hasher = hashlib.sha256()
        chunk_bytes = 0
        with chunk_path.open("rb") as handle:
            while True:
                data = handle.read(bounded)
                if not data:
                    break
                chunk_hasher.update(data)
                combined_hasher.update(data)
                chunk_bytes += len(data)

        total_observed_bytes += chunk_bytes
        c_expected_bytes: Optional[int] = None
        c_expected_digest: Optional[str] = None
        if chunk_expectations and idx in chunk_expectations:
            c_expected_bytes, c_expected_digest = chunk_expectations[idx]
        c_norm_expected = _normalize_digest(c_expected_digest)
        c_observed_digest = chunk_hasher.hexdigest()

        chunk_summaries.append(
            ChunkIntegritySummary(
                chunk_index=idx,
                observed_bytes=chunk_bytes,
                observed_digest=c_observed_digest,
                expected_bytes=c_expected_bytes,
                expected_digest=c_norm_expected,
                byte_count_status=_classify_byte_count_status(
                    c_expected_bytes, chunk_bytes
                ),
                digest_status=_classify_digest_status(
                    c_norm_expected, c_observed_digest
                ),
            )
        )

    return build_upload_integrity_report(
        session_id=session_id,
        expected_bytes=expected_bytes,
        observed_bytes=total_observed_bytes,
        expected_digest=expected_digest,
        observed_digest=combined_hasher.hexdigest(),
        failure_reason=failure_reason,
        chunks=chunk_summaries,
        missing_chunk_indices=missing_indices,
        max_bytes=max_size,
    )


def write_upload_integrity_report(
    report: UploadIntegrityReport,
    destination: Union[str, Path],
) -> Path:
    """Persist an ``UploadIntegrityReport`` as canonical JSON to *destination*."""
    dest = Path(destination)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(report.to_json() + "\n", encoding="utf-8")
    return dest
