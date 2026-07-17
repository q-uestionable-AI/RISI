"""Atomic evidence-bundle creation and integrity verification."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import Any, cast

from risi.canonical import JsonValue, canonical_json, canonical_sha256


class ArtifactError(ValueError):
    """Raised when an evidence bundle cannot be safely created or verified."""


@dataclass(frozen=True, slots=True)
class InventoryEntry:
    """Describe one verified evidence file.

    Attributes:
        path: POSIX-style path relative to the bundle root.
        sha256: Digest of the exact file bytes.
        byte_count: Number of file bytes covered by the digest.
    """

    path: str
    sha256: str
    byte_count: int

    def to_json(self) -> dict[str, JsonValue]:
        """Return the canonical inventory-entry representation."""
        return {"path": self.path, "sha256": self.sha256, "bytes": self.byte_count}


@dataclass(frozen=True, slots=True)
class BundleVerification:
    """Summarize evidence-bundle integrity verification.

    Attributes:
        run_id: Verified run identifier.
        inventory_sha256: Digest that an operator can retain as an external anchor.
        bundle_hash: Canonical digest of the inventory entries.
        file_count: Number of evidence files covered by the inventory.
        total_bytes: Total bytes covered by the inventory.
        entries: Ordered verified inventory entries.
    """

    run_id: str
    inventory_sha256: str
    bundle_hash: str
    file_count: int
    total_bytes: int
    entries: tuple[InventoryEntry, ...] = ()

    def to_json(self) -> dict[str, JsonValue]:
        """Return the machine-readable verification summary."""
        return {
            "run_id": self.run_id,
            "inventory_sha256": self.inventory_sha256,
            "bundle_hash": self.bundle_hash,
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
        }


@dataclass(frozen=True, slots=True)
class _BundleMaterial:
    entries: tuple[InventoryEntry, ...]
    inventory_content: bytes
    bundle_hash: str
    total_bytes: int


def json_bytes(value: object) -> bytes:
    """Serialize canonical JSON with a final newline.

    Args:
        value: JSON-compatible value.

    Returns:
        Deterministic UTF-8 bytes.
    """
    return f"{canonical_json(value)}\n".encode()


def json_lines_bytes(values: tuple[object, ...]) -> bytes:
    """Serialize canonical newline-delimited JSON.

    Args:
        values: Ordered JSON-compatible records.

    Returns:
        Deterministic UTF-8 JSON Lines bytes.
    """
    return "".join(f"{canonical_json(value)}\n" for value in values).encode()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _validate_artifact_name(name: str) -> None:
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or ".." in path.parts or "\\" in name:
        raise ArtifactError("artifact names must remain beneath the bundle root")
    if name == "inventory.json":
        raise ArtifactError("inventory.json is reserved by the evidence writer")


def _prepare_bundle_material(run_id: str, files: dict[str, bytes]) -> _BundleMaterial:
    if not files:
        raise ArtifactError("evidence bundle must contain files")
    for name in files:
        _validate_artifact_name(name)
    entries = tuple(
        InventoryEntry(name, _sha256_bytes(files[name]), len(files[name])) for name in sorted(files)
    )
    bundle_hash = canonical_sha256([entry.to_json() for entry in entries])
    inventory = {
        "schema_version": 1,
        "run_id": run_id,
        "files": [entry.to_json() for entry in entries],
        "bundle_hash": bundle_hash,
    }
    inventory_content = json_bytes(inventory)
    return _BundleMaterial(
        entries=entries,
        inventory_content=inventory_content,
        bundle_hash=bundle_hash,
        total_bytes=sum(entry.byte_count for entry in entries) + len(inventory_content),
    )


def measure_evidence_bundle(run_id: str, files: dict[str, bytes]) -> int:
    """Return the exact finalized size of an in-memory evidence bundle.

    Args:
        run_id: Run identifier written into the inventory.
        files: Relative evidence filenames and exact content bytes.

    Returns:
        Total bytes including the generated ``inventory.json``.

    Raises:
        ArtifactError: If an evidence path is invalid or no files are supplied.
    """
    return _prepare_bundle_material(run_id, files).total_bytes


def create_evidence_bundle(
    artifact_root: Path,
    run_id: str,
    files: dict[str, bytes],
    *,
    max_bytes: int,
) -> BundleVerification:
    """Create an atomic, content-addressed evidence bundle.

    Args:
        artifact_root: Resolved operator-controlled artifact directory.
        run_id: Filesystem-safe run identifier.
        files: Relative evidence filenames and exact content bytes.
        max_bytes: Approved maximum bundle size.

    Returns:
        Integrity summary for the completed bundle.

    Raises:
        ArtifactError: If paths, sizes, or destination state are unsafe.
    """
    material = _prepare_bundle_material(run_id, files)
    final_path = artifact_root / run_id
    if final_path.exists():
        raise ArtifactError("evidence bundle already exists; run IDs are immutable")
    if material.total_bytes > max_bytes:
        raise ArtifactError("evidence bundle exceeds the approved artifact_bytes limit")
    try:
        with TemporaryDirectory(prefix=".risi-staging-", dir=artifact_root) as temporary:
            staging = Path(temporary)
            for name, content in files.items():
                destination = staging / Path(*PurePosixPath(name).parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content)
            (staging / "inventory.json").write_bytes(material.inventory_content)
            staging.replace(final_path)
    except OSError as exc:
        raise ArtifactError(f"cannot create evidence bundle: {exc}") from exc
    return BundleVerification(
        run_id=run_id,
        inventory_sha256=_sha256_bytes(material.inventory_content),
        bundle_hash=material.bundle_hash,
        file_count=len(material.entries),
        total_bytes=material.total_bytes,
        entries=material.entries,
    )


def _load_inventory(bundle_path: Path) -> tuple[dict[str, Any], bytes]:
    inventory_path = bundle_path / "inventory.json"
    try:
        content = inventory_path.read_bytes()
        value = json.loads(content)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ArtifactError(f"cannot read bundle inventory: {exc}") from exc
    if not isinstance(value, dict):
        raise ArtifactError("bundle inventory must be an object")
    return cast(dict[str, Any], value), content


def _validate_inventory_header(inventory: dict[str, Any]) -> tuple[str, list[Any], str]:
    if set(inventory) != {"schema_version", "run_id", "files", "bundle_hash"}:
        raise ArtifactError("bundle inventory has an invalid field set")
    run_id = inventory["run_id"]
    if inventory["schema_version"] != 1 or not isinstance(run_id, str):
        raise ArtifactError("bundle inventory identity is invalid")
    raw_entries = inventory["files"]
    bundle_hash = inventory["bundle_hash"]
    if not isinstance(raw_entries, list):
        raise ArtifactError("bundle inventory files must be an array")
    if not isinstance(bundle_hash, str):
        raise ArtifactError("bundle inventory hash must be a string")
    return run_id, cast(list[Any], raw_entries), bundle_hash


def _verify_entry(root: Path, raw: Any) -> InventoryEntry:
    if not isinstance(raw, dict) or set(raw) != {"path", "sha256", "bytes"}:
        raise ArtifactError("bundle inventory contains an invalid file entry")
    name = raw["path"]
    digest = raw["sha256"]
    byte_count = raw["bytes"]
    if not isinstance(name, str) or not isinstance(digest, str):
        raise ArtifactError("bundle inventory contains invalid file metadata")
    if isinstance(byte_count, bool) or not isinstance(byte_count, int) or byte_count < 0:
        raise ArtifactError("bundle inventory contains invalid file metadata")
    _validate_artifact_name(name)
    try:
        candidate = (root / Path(*PurePosixPath(name).parts)).resolve(strict=True)
        candidate.relative_to(root)
    except (OSError, ValueError) as exc:
        raise ArtifactError("bundle file escapes or is missing from the bundle root") from exc
    if not candidate.is_file() or candidate.is_symlink():
        raise ArtifactError("bundle entry must name a regular non-symlink file")
    content = candidate.read_bytes()
    if len(content) != byte_count or _sha256_bytes(content) != digest:
        raise ArtifactError(f"bundle file failed integrity verification: {name}")
    return InventoryEntry(name, digest, byte_count)


def _verify_entries(
    root: Path, raw_entries: list[Any]
) -> tuple[tuple[InventoryEntry, ...], set[str], int]:
    entries: list[InventoryEntry] = []
    names: set[str] = set()
    total_bytes = 0
    for raw in raw_entries:
        entry = _verify_entry(root, raw)
        if entry.path in names:
            raise ArtifactError("bundle inventory contains duplicate paths")
        entries.append(entry)
        names.add(entry.path)
        total_bytes += entry.byte_count
    return tuple(entries), names, total_bytes


def verify_evidence_bundle(bundle_path: Path) -> BundleVerification:
    """Verify the inventory, every file digest, and bundle path containment.

    Args:
        bundle_path: Evidence-bundle directory.

    Returns:
        Verified integrity summary.

    Raises:
        ArtifactError: If any contract or digest check fails.
    """
    try:
        root = bundle_path.resolve(strict=True)
    except OSError as exc:
        raise ArtifactError("evidence bundle does not exist") from exc
    if not root.is_dir():
        raise ArtifactError("evidence bundle must be a directory")
    inventory, inventory_content = _load_inventory(root)
    run_id, raw_entries, supplied_bundle_hash = _validate_inventory_header(inventory)
    normalized_entries, expected_names, total_bytes = _verify_entries(root, raw_entries)
    actual_names = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "inventory.json"
    }
    if actual_names != expected_names:
        raise ArtifactError("bundle contains missing or unlisted files")
    expected_bundle_hash = canonical_sha256([entry.to_json() for entry in normalized_entries])
    if supplied_bundle_hash != expected_bundle_hash:
        raise ArtifactError("bundle inventory hash does not match its entries")
    return BundleVerification(
        run_id=run_id,
        inventory_sha256=_sha256_bytes(inventory_content),
        bundle_hash=expected_bundle_hash,
        file_count=len(normalized_entries),
        total_bytes=total_bytes + len(inventory_content),
        entries=normalized_entries,
    )


def load_json_artifact(bundle_path: Path, name: str) -> dict[str, Any]:
    """Load an inventoried JSON object after bundle verification.

    Args:
        bundle_path: Verified evidence-bundle directory.
        name: Relative JSON artifact name.

    Returns:
        Parsed JSON object.

    Raises:
        ArtifactError: If the artifact is missing or malformed.
    """
    _validate_artifact_name(name)
    try:
        value = json.loads(
            (bundle_path / Path(*PurePosixPath(name).parts)).read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ArtifactError(f"cannot read JSON artifact {name}: {exc}") from exc
    if not isinstance(value, dict):
        raise ArtifactError(f"JSON artifact {name} must contain an object")
    return cast(dict[str, Any], value)
