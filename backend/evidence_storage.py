import hashlib
import json
import os
import re
import tempfile
import uuid
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Tuple
from cryptography.fernet import Fernet, InvalidToken
import db
import storage

EXPORT_MANIFEST_VERSION = 1
DEFAULT_ENVELOPE_VERSION = "fernet-v1"
_HEX_32_PATTERN = re.compile(r"[0-9a-fA-F]{64}")

DEFAULT_VERIFY_BATCH_SIZE = 50
MAX_VERIFY_BATCH_SIZE = 500
PROGRESS_SCHEMA_VERSION = 1

STATUS_VERIFIED = "verified"
STATUS_FAILED = "failed"
STATUS_UNVERIFIABLE_LEGACY = "unverifiable_legacy"


def generate_dek() -> Tuple[bytes, bytes]:
    """Generates a Data Encryption Key (DEK) and its encrypted form (using a Master Key)."""
    master_key_b64 = os.getenv("MASTER_ENCRYPTION_KEY")
    if not master_key_b64:
        master_key_b64 = Fernet.generate_key().decode()
    f = Fernet(master_key_b64.encode())
    
    dek = Fernet.generate_key()
    encrypted_dek = f.encrypt(dek)
    
    return dek, encrypted_dek

def decrypt_dek(encrypted_dek: bytes) -> bytes:
    master_key_b64 = os.getenv("MASTER_ENCRYPTION_KEY")
    if not master_key_b64:
        raise ValueError("MASTER_ENCRYPTION_KEY is not set")
    f = Fernet(master_key_b64.encode())
    return f.decrypt(encrypted_dek)

def get_encryptor(dek: bytes):
    return Fernet(dek)

def record_blob(content_hash: str, encrypted_dek: bytes, size_bytes: int, storage_path: str):
    with db.get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                insert into blobs (content_hash, encrypted_dek, size_bytes, storage_path)
                values (%s, %s, %s, %s)
                on conflict (content_hash) do nothing
                """,
                (content_hash, encrypted_dek.decode(), size_bytes, storage_path)
            )
        conn.commit()

def record_tenant_ref(tenant_id: str, content_hash: str):
    with db.get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                insert into tenant_blob_refs (tenant_id, content_hash, ref_count)
                values (%s, %s, 1)
                on conflict (tenant_id, content_hash) do update
                set ref_count = tenant_blob_refs.ref_count + 1, updated_at = now()
                """,
                (tenant_id, content_hash)
            )
        conn.commit()

def get_blob_info(content_hash: str) -> dict | None:
    with db.get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("select encrypted_dek, storage_path from blobs where content_hash = %s", (content_hash,))
            row = cursor.fetchone()
            return dict(row) if row else None


def _normalize_authorized_tenants(authorized_tenants: Iterable[str]) -> list[str]:
    if isinstance(authorized_tenants, (str, bytes)):
        raise ValueError("authorized_tenants must be an iterable of tenant identifiers, not a string")
    normalized: set[str] = set()
    for tenant in authorized_tenants:
        if not isinstance(tenant, str) or not tenant.strip():
            raise ValueError("authorized tenant identifier must be a non-empty string")
        normalized.add(tenant.strip())
    if not normalized:
        raise ValueError("authorized_tenants must contain at least one tenant identifier")
    return sorted(normalized)


def _normalize_digest(value: object) -> str:
    if not isinstance(value, str) or _HEX_32_PATTERN.fullmatch(value) is None:
        raise ValueError("blob digest must be a 32-byte hex string")
    return value.lower()


def _normalize_envelope_version(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("envelope_version must be a non-empty string")
    return value.strip()


def _normalize_non_negative_int(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def _normalize_generated_at(generated_at: datetime | None) -> str:
    if generated_at is None:
        dt = datetime.now(timezone.utc)
    else:
        if not isinstance(generated_at, datetime) or generated_at.tzinfo is None:
            raise ValueError("generated_at must be a timezone-aware datetime")
        dt = generated_at.astimezone(timezone.utc)
    return dt.isoformat()


def serialize_evidence_export_manifest(manifest: Mapping[str, Any]) -> str:
    """Serialize an export manifest to canonical JSON."""
    return json.dumps(manifest, separators=(",", ":"), sort_keys=True)


def build_evidence_export_manifest(
    rows: Iterable[Mapping[str, Any]],
    authorized_tenants: Iterable[str],
    *,
    envelope_version: str = DEFAULT_ENVELOPE_VERSION,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Build a read-only encrypted evidence export manifest from storage rows.

    Only allowlisted fields (blob digest, envelope version, size_bytes, and
    authorized tenant references with positive ref_count) are included.
    Unwrapped data keys, wrapped DEKs, local storage paths, and sensitive media
    metadata are strictly excluded.
    """
    tenants = _normalize_authorized_tenants(authorized_tenants)
    allowed_set = set(tenants)
    default_env_version = _normalize_envelope_version(envelope_version)
    timestamp = _normalize_generated_at(generated_at)

    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        tenant_id = row.get("tenant_id")
        if not isinstance(tenant_id, str) or tenant_id.strip() not in allowed_set:
            continue
        tenant_id = tenant_id.strip()

        ref_count = _normalize_non_negative_int(row.get("ref_count", 0), "ref_count")
        if ref_count <= 0:
            continue

        digest = _normalize_digest(row.get("content_hash"))
        size_bytes = _normalize_non_negative_int(row.get("size_bytes"), "size_bytes")
        row_env_version = _normalize_envelope_version(
            row.get("envelope_version") or default_env_version
        )

        entry = grouped.get(digest)
        if entry is None:
            grouped[digest] = {
                "blob_digest": digest,
                "envelope_version": row_env_version,
                "size_bytes": size_bytes,
                "_refs": {tenant_id: ref_count},
            }
        else:
            if entry["size_bytes"] != size_bytes:
                raise ValueError(f"conflicting size_bytes for blob {digest}")
            if entry["envelope_version"] != row_env_version:
                raise ValueError(f"conflicting envelope_version for blob {digest}")
            entry["_refs"][tenant_id] = entry["_refs"].get(tenant_id, 0) + ref_count

    entries: list[dict[str, Any]] = []
    for digest in sorted(grouped.keys()):
        raw_entry = grouped[digest]
        refs = [
            {"tenant_id": tid, "ref_count": raw_entry["_refs"][tid]}
            for tid in sorted(raw_entry["_refs"].keys())
        ]
        entries.append(
            {
                "blob_digest": raw_entry["blob_digest"],
                "envelope_version": raw_entry["envelope_version"],
                "size_bytes": raw_entry["size_bytes"],
                "authorized_references": refs,
            }
        )

    payload: dict[str, Any] = {
        "manifest_version": EXPORT_MANIFEST_VERSION,
        "read_only": True,
        "generated_at": timestamp,
        "authorized_tenants": tenants,
        "entry_count": len(entries),
        "entries": entries,
    }
    canonical = serialize_evidence_export_manifest(payload).encode("utf-8")
    payload["manifest_digest"] = hashlib.sha256(canonical).hexdigest()
    return payload


def export_evidence_manifest(
    authorized_tenants: Iterable[str],
    *,
    envelope_version: str = DEFAULT_ENVELOPE_VERSION,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Query encrypted evidence metadata in read-only mode and build an export manifest.

    Never unwraps DEKs, never selects encrypted_dek or storage_path, and never
    mutates database state.
    """
    tenants = _normalize_authorized_tenants(authorized_tenants)
    default_env_version = _normalize_envelope_version(envelope_version)
    _normalize_generated_at(generated_at)

    with db.get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                select b.content_hash, b.size_bytes, r.tenant_id, r.ref_count
                from blobs b
                inner join tenant_blob_refs r on r.content_hash = b.content_hash
                where r.tenant_id = any(%s) and r.ref_count > 0
                order by b.content_hash asc, r.tenant_id asc
                """,
                (tenants,),
            )
            rows = [dict(row) for row in cursor.fetchall()]

    return build_evidence_export_manifest(
        rows,
        tenants,
        envelope_version=default_env_version,
        generated_at=generated_at,
    )


def clamp_verify_batch_size(batch_size: int | None) -> int:
    if batch_size is None:
        return DEFAULT_VERIFY_BATCH_SIZE
    if isinstance(batch_size, bool) or not isinstance(batch_size, int) or batch_size < 1:
        raise ValueError("batch_size must be a positive integer")
    return min(batch_size, MAX_VERIFY_BATCH_SIZE)


def list_blobs_batch(
    after_content_hash: str | None = None,
    batch_size: int = DEFAULT_VERIFY_BATCH_SIZE,
) -> list[dict[str, Any]]:
    limit = clamp_verify_batch_size(batch_size)
    with db.get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                select content_hash, encrypted_dek, size_bytes, storage_path
                from blobs
                where (%s is null or content_hash > %s)
                order by content_hash asc
                limit %s
                """,
                (after_content_hash, after_content_hash, limit),
            )
            rows = cursor.fetchall()
            return [dict(row) for row in rows]


def verify_blob_integrity(blob: Mapping[str, Any]) -> dict[str, str]:
    """Verify metadata and ciphertext integrity for a single evidence blob.

    Returns a nonsecret status dictionary with keys ``content_hash``,
    ``status``, and ``reason``. Never returns plaintext, ciphertext, DEKs,
    storage paths, or raw exception messages.
    """
    content_hash_raw = blob.get("content_hash")
    content_hash = content_hash_raw if isinstance(content_hash_raw, str) else ""

    if _HEX_32_PATTERN.fullmatch(content_hash) is None:
        return {
            "content_hash": content_hash,
            "status": STATUS_UNVERIFIABLE_LEGACY,
            "reason": "legacy_hash_format",
        }

    size_bytes = blob.get("size_bytes")
    if size_bytes is None:
        return {
            "content_hash": content_hash,
            "status": STATUS_UNVERIFIABLE_LEGACY,
            "reason": "missing_size_metadata",
        }
    if isinstance(size_bytes, bool) or not isinstance(size_bytes, int) or size_bytes < 0:
        return {
            "content_hash": content_hash,
            "status": STATUS_FAILED,
            "reason": "invalid_metadata",
        }

    storage_path_raw = blob.get("storage_path")
    if not isinstance(storage_path_raw, str) or not storage_path_raw.strip():
        return {
            "content_hash": content_hash,
            "status": STATUS_FAILED,
            "reason": "invalid_metadata",
        }

    encrypted_dek_raw = blob.get("encrypted_dek")
    if isinstance(encrypted_dek_raw, bytes):
        encrypted_dek_bytes = encrypted_dek_raw
        is_legacy_prefix = encrypted_dek_bytes.startswith(b"legacy:")
    elif isinstance(encrypted_dek_raw, str):
        if not encrypted_dek_raw.strip():
            return {
                "content_hash": content_hash,
                "status": STATUS_UNVERIFIABLE_LEGACY,
                "reason": "missing_encrypted_dek",
            }
        is_legacy_prefix = encrypted_dek_raw.startswith("legacy:")
        encrypted_dek_bytes = encrypted_dek_raw.encode("utf-8")
    else:
        return {
            "content_hash": content_hash,
            "status": STATUS_UNVERIFIABLE_LEGACY,
            "reason": "missing_encrypted_dek",
        }

    if is_legacy_prefix:
        return {
            "content_hash": content_hash,
            "status": STATUS_UNVERIFIABLE_LEGACY,
            "reason": "legacy_dek_format",
        }

    blob_path = Path(storage_path_raw)
    if not blob_path.exists():
        return {
            "content_hash": content_hash,
            "status": STATUS_FAILED,
            "reason": "missing_blob",
        }
    if not blob_path.is_file():
        return {
            "content_hash": content_hash,
            "status": STATUS_FAILED,
            "reason": "invalid_metadata",
        }

    try:
        dek = decrypt_dek(encrypted_dek_bytes)
    except (ValueError, InvalidToken):
        return {
            "content_hash": content_hash,
            "status": STATUS_UNVERIFIABLE_LEGACY,
            "reason": "unreadable_legacy_dek",
        }

    try:
        ciphertext = blob_path.read_bytes()
    except OSError:
        return {
            "content_hash": content_hash,
            "status": STATUS_FAILED,
            "reason": "missing_blob",
        }

    try:
        plaintext = get_encryptor(dek).decrypt(ciphertext)
    except (InvalidToken, ValueError):
        return {
            "content_hash": content_hash,
            "status": STATUS_FAILED,
            "reason": "corrupt_ciphertext",
        }

    actual_hash = hashlib.sha256(plaintext).hexdigest()
    if actual_hash != content_hash.lower():
        return {
            "content_hash": content_hash,
            "status": STATUS_FAILED,
            "reason": "hash_mismatch",
        }

    if size_bytes not in (len(ciphertext), len(plaintext)):
        return {
            "content_hash": content_hash,
            "status": STATUS_FAILED,
            "reason": "size_mismatch",
        }

    return {
        "content_hash": content_hash,
        "status": STATUS_VERIFIED,
        "reason": "ok",
    }


def _new_integrity_progress(batch_size: int) -> dict[str, Any]:
    return {
        "schema_version": PROGRESS_SCHEMA_VERSION,
        "run_id": str(uuid.uuid4()),
        "status": "in_progress",
        "cursor": None,
        "batch_size": batch_size,
        "batches_completed": 0,
        "totals": {
            "checked": 0,
            "verified": 0,
            "failed": 0,
            "unverifiable_legacy": 0,
        },
        "failure_reasons": {},
        "legacy_reasons": {},
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


def _sanitize_progress_payload(progress: Mapping[str, Any]) -> dict[str, Any]:
    totals_raw = progress.get("totals")
    totals = totals_raw if isinstance(totals_raw, Mapping) else {}
    failure_reasons_raw = progress.get("failure_reasons")
    failure_reasons = (
        {str(k): int(v) for k, v in failure_reasons_raw.items()}
        if isinstance(failure_reasons_raw, Mapping)
        else {}
    )
    legacy_reasons_raw = progress.get("legacy_reasons")
    legacy_reasons = (
        {str(k): int(v) for k, v in legacy_reasons_raw.items()}
        if isinstance(legacy_reasons_raw, Mapping)
        else {}
    )
    cursor = progress.get("cursor")
    return {
        "schema_version": PROGRESS_SCHEMA_VERSION,
        "run_id": str(progress.get("run_id") or uuid.uuid4()),
        "status": "completed" if progress.get("status") == "completed" else "in_progress",
        "cursor": cursor if isinstance(cursor, str) else None,
        "batch_size": clamp_verify_batch_size(int(progress.get("batch_size", DEFAULT_VERIFY_BATCH_SIZE))),
        "batches_completed": max(0, int(progress.get("batches_completed", 0))),
        "totals": {
            "checked": max(0, int(totals.get("checked", 0))),
            "verified": max(0, int(totals.get("verified", 0))),
            "failed": max(0, int(totals.get("failed", 0))),
            "unverifiable_legacy": max(0, int(totals.get("unverifiable_legacy", 0))),
        },
        "failure_reasons": failure_reasons,
        "legacy_reasons": legacy_reasons,
        "updated_at": str(progress.get("updated_at") or datetime.now(timezone.utc).isoformat()),
    }


def load_integrity_progress(progress_path: Path | None = None) -> dict[str, Any] | None:
    path = progress_path if progress_path is not None else storage.get_integrity_progress_path()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("integrity progress file is unreadable or malformed") from exc
    if not isinstance(data, dict) or data.get("schema_version") != PROGRESS_SCHEMA_VERSION:
        raise ValueError("integrity progress file has unsupported schema version")
    return _sanitize_progress_payload(data)


def save_integrity_progress(
    progress: Mapping[str, Any],
    progress_path: Path | None = None,
) -> Path:
    path = progress_path if progress_path is not None else storage.get_integrity_progress_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _sanitize_progress_payload(progress)
    payload["updated_at"] = datetime.now(timezone.utc).isoformat()
    encoded = json.dumps(payload, sort_keys=True, indent=2) + "\n"

    fd, tmp_name = tempfile.mkstemp(prefix=".integrity_progress_", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(encoded)
        os.replace(tmp_name, path)
    except Exception:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
        raise
    return path


def verify_evidence_batch(
    *,
    batch_size: int = DEFAULT_VERIFY_BATCH_SIZE,
    progress_path: Path | None = None,
    reset: bool = False,
    fetch_batch: Callable[[str | None, int], list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Run one bounded batch of resumable evidence integrity verification.

    Persists only nonsecret progress metadata and advances the cursor
    deterministically by ``content_hash``.
    """
    effective_batch_size = clamp_verify_batch_size(batch_size)
    path = progress_path if progress_path is not None else storage.get_integrity_progress_path()

    progress = None if reset else load_integrity_progress(path)
    if progress is None or progress["status"] == "completed":
        progress = _new_integrity_progress(effective_batch_size)
    else:
        progress["batch_size"] = effective_batch_size

    loader = fetch_batch if fetch_batch is not None else list_blobs_batch
    blobs = loader(progress["cursor"], effective_batch_size)

    for blob in blobs:
        result = verify_blob_integrity(blob)
        progress["totals"]["checked"] += 1
        status = result["status"]
        reason = result["reason"]
        if status == STATUS_VERIFIED:
            progress["totals"]["verified"] += 1
        elif status == STATUS_UNVERIFIABLE_LEGACY:
            progress["totals"]["unverifiable_legacy"] += 1
            progress["legacy_reasons"][reason] = progress["legacy_reasons"].get(reason, 0) + 1
        else:
            progress["totals"]["failed"] += 1
            progress["failure_reasons"][reason] = progress["failure_reasons"].get(reason, 0) + 1
        if isinstance(blob.get("content_hash"), str):
            progress["cursor"] = blob["content_hash"]

    progress["batches_completed"] += 1
    progress["status"] = "completed" if len(blobs) < effective_batch_size else "in_progress"
    save_integrity_progress(progress, path)
    return progress


def verify_evidence_resumable(
    *,
    batch_size: int = DEFAULT_VERIFY_BATCH_SIZE,
    max_batches: int | None = None,
    progress_path: Path | None = None,
    reset: bool = False,
    fetch_batch: Callable[[str | None, int], list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Resume and run bounded integrity verification batches until complete or ``max_batches``."""
    if max_batches is not None and (
        isinstance(max_batches, bool) or not isinstance(max_batches, int) or max_batches < 1
    ):
        raise ValueError("max_batches must be a positive integer")

    batches_run = 0
    progress: dict[str, Any] | None = None
    while True:
        progress = verify_evidence_batch(
            batch_size=batch_size,
            progress_path=progress_path,
            reset=(reset and batches_run == 0),
            fetch_batch=fetch_batch,
        )
        batches_run += 1
        if progress["status"] == "completed":
            return progress
        if max_batches is not None and batches_run >= max_batches:
            return progress
