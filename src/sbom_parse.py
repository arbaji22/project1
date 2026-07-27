"""Parse GitHub SPDX JSON SBOMs into flat package features."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.normalize import normalize_package_row, parse_purl_safe


class SbomLoadError(Exception):
    """Raised when a file contains no usable SPDX SBOM."""


@dataclass
class LoadResult:
    sbom: dict[str, Any]
    recovered_concat: bool
    n_json_objects: int
    discarded_objects: int


def _iter_json_objects(text: str) -> list[Any]:
    """Parse one or more concatenated JSON values from a file body."""
    decoder = json.JSONDecoder()
    objects: list[Any] = []
    idx = 0
    n = len(text)
    while idx < n:
        while idx < n and text[idx].isspace():
            idx += 1
        if idx >= n:
            break
        obj, end = decoder.raw_decode(text, idx)
        objects.append(obj)
        idx = end
    return objects


def _as_sbom(obj: Any) -> dict[str, Any] | None:
    """Return an SPDX document dict if this object looks like one."""
    if not isinstance(obj, dict):
        return None
    if "sbom" in obj and isinstance(obj["sbom"], dict):
        candidate = obj["sbom"]
    else:
        candidate = obj
    # Minimal SPDX shape used by this corpus
    if "packages" in candidate or candidate.get("spdxVersion") or candidate.get("SPDXID"):
        return candidate
    return None


def load_sbom(path: Path) -> dict[str, Any]:
    """Load SPDX SBOM; recovers files with concatenated API-error + SBOM JSON."""
    return load_sbom_detailed(path).sbom


def load_sbom_detailed(path: Path) -> LoadResult:
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        raise SbomLoadError("empty file")

    try:
        objects = _iter_json_objects(text)
    except json.JSONDecodeError as exc:
        raise SbomLoadError(f"invalid JSON: {exc}") from exc

    if not objects:
        raise SbomLoadError("no JSON objects found")

    sboms = [s for obj in objects if (s := _as_sbom(obj)) is not None]
    if not sboms:
        # Surface GitHub API error payloads when present
        for obj in objects:
            if isinstance(obj, dict) and obj.get("message"):
                raise SbomLoadError(
                    f"API error only: status={obj.get('status')} message={obj.get('message')}"
                )
        raise SbomLoadError(f"no SPDX SBOM in {len(objects)} JSON object(s)")

    # Prefer the richest SBOM if multiple appear
    chosen = max(sboms, key=lambda s: len(s.get("packages") or []))
    return LoadResult(
        sbom=chosen,
        recovered_concat=len(objects) > 1,
        n_json_objects=len(objects),
        discarded_objects=len(objects) - 1,
    )


def package_purl(pkg: dict[str, Any]) -> str | None:
    for ref in pkg.get("externalRefs") or []:
        if ref.get("referenceType") == "purl":
            return ref.get("referenceLocator")
    return None


def extract_packages(sbom: dict[str, Any], source_file: str) -> list[dict[str, Any]]:
    """Flatten packages with normalized comparison fields."""
    root_name = sbom.get("name")
    rows: list[dict[str, Any]] = []

    for pkg in sbom.get("packages") or []:
        name = pkg.get("name")
        purl = package_purl(pkg)
        parsed = parse_purl_safe(purl)

        is_root = (
            (parsed.get("ecosystem") == "github")
            or (root_name is not None and name == root_name)
        )

        raw_row = {
            "source_file": source_file,
            "sbom_name": root_name,
            "package_name": name,
            "version_raw": pkg.get("versionInfo"),
            "purl": purl,
            "ecosystem": parsed.get("ecosystem"),
            "namespace": parsed.get("namespace"),
            "is_root": is_root,
            "supplier": pkg.get("supplier"),
            "spdx_id": pkg.get("SPDXID"),
        }
        rows.append(normalize_package_row(raw_row))
    return rows


def extract_sbom_summary(
    sbom: dict[str, Any],
    source_file: str,
    *,
    recovered_concat: bool = False,
    n_json_objects: int = 1,
) -> dict[str, Any]:
    packages = extract_packages(sbom, source_file)
    deps = [p for p in packages if not p["is_root"]]
    ecosystems = sorted({p["ecosystem_norm"] for p in deps if p.get("ecosystem_norm")})
    n_exact = sum(1 for p in deps if p.get("version_kind") == "exact")
    n_range = sum(1 for p in deps if p.get("version_kind") == "range")
    return {
        "source_file": source_file,
        "sbom_name": sbom.get("name"),
        "spdx_version": sbom.get("spdxVersion"),
        "n_packages_total": len(packages),
        "n_dependencies": len(deps),
        "n_ecosystems": len(ecosystems),
        "ecosystems": ",".join(ecosystems),
        "n_versions_exact": n_exact,
        "n_versions_range": n_range,
        "has_unresolved_comment": bool(sbom.get("comment")),
        "created": (sbom.get("creationInfo") or {}).get("created"),
        "recovered_concat": recovered_concat,
        "n_json_objects": n_json_objects,
    }
