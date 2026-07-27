"""Normalize SBOM package fields for comparison features.

Rules are documented in docs/PIPELINE.md (Step 2).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote

from packageurl import PackageURL


# Ecosystems observed in the Chaora GitHub SPDX corpus (extend as needed)
ECOSYSTEM_ALIASES = {
    "githubactions": "github_actions",
    "github-actions": "github_actions",
}

# Lightweight display-name → registry-name aliases (expand over time)
PACKAGE_NAME_ALIASES: dict[str, dict[str, str]] = {
    # ecosystem -> {alias_lower: canonical}
    "npm": {
        "jquery": "jquery",  # collapse jQuery / jquery
    },
    "nuget": {
        "sqlite": "sqlite",
    },
}

BRANCH_TOKENS = {"main", "master", "develop", "development", "head", "trunk", "latest"}

RANGE_PREFIX_RE = re.compile(r"^[\^~>=<\s]+")
RANGE_CHARS_RE = re.compile(r"[><=^~*|,\s]")
PEP440_LIKE_RE = re.compile(
    r"^v?(?:\d+!)?\d+(?:\.\d+)*(?:[-._]?(?:a|b|rc|alpha|beta|preview|dev|post)\d*)*(?:\+[a-z0-9.]+)?$",
    re.IGNORECASE,
)


def normalize_ecosystem(ecosystem: str | None) -> str | None:
    if ecosystem is None:
        return None
    eco = ecosystem.strip().lower()
    return ECOSYSTEM_ALIASES.get(eco, eco)


def normalize_package_name(name: str | None, ecosystem: str | None) -> str | None:
    if name is None:
        return None
    n = name.strip()
    if not n:
        return None
    eco = normalize_ecosystem(ecosystem) or ""

    if eco == "pypi":
        # PEP 503: lowercase, replace _, . with -
        n = re.sub(r"[_.]+", "-", n.lower())
    elif eco in {"npm", "cargo", "gem", "nuget", "composer", "pub", "github_actions"}:
        n = n.lower()
    elif eco == "maven":
        # Prefer artifactId if name is group:artifact
        if ":" in n:
            n = n.split(":")[-1]
        n = n.strip()
    elif eco == "golang":
        n = n.strip()  # module paths are case-sensitive; keep as-is after strip
    else:
        n = n.lower()

    aliases = PACKAGE_NAME_ALIASES.get(eco, {})
    return aliases.get(n.lower(), n) if eco != "golang" else aliases.get(n, n)


def normalize_namespace(namespace: str | None, ecosystem: str | None) -> str | None:
    if namespace is None:
        return None
    ns = unquote(str(namespace)).strip()
    if not ns or ns.upper() in {"NOASSERTION", "NONE"}:
        return None
    eco = normalize_ecosystem(ecosystem) or ""
    if eco in {"npm", "nuget", "cargo", "gem", "composer", "pub", "pypi"}:
        return ns.lower()
    return ns


def classify_version(raw: str | None) -> tuple[str | None, str]:
    """Return (version_norm, version_kind).

    version_kind: exact | range | branch | missing | other
    """
    if raw is None:
        return None, "missing"
    v = str(raw).strip()
    if not v or v.upper() in {"NOASSERTION", "NONE"}:
        return None, "missing"

    lower = v.lower()
    if lower in BRANCH_TOKENS:
        return lower, "branch"

    # Range / constraint expressions (keep stripped lower-bound when simple)
    if RANGE_CHARS_RE.search(v) or "||" in v or " - " in v:
        stripped = RANGE_PREFIX_RE.sub("", v).strip()
        # ">= 3.0.0,< 4.0.0" → take first token-ish
        stripped = re.split(r"[,<|]", stripped, maxsplit=1)[0].strip()
        stripped = RANGE_PREFIX_RE.sub("", stripped).strip()
        if stripped and PEP440_LIKE_RE.match(stripped.replace(" ", "")):
            return stripped.lstrip("vV"), "range"
        return None, "range"

    cleaned = v.lstrip("vV").strip()
    if PEP440_LIKE_RE.match(cleaned):
        return cleaned, "exact"

    return cleaned, "other"


def parse_purl_safe(purl: str | None) -> dict[str, str | None]:
    empty = {"ecosystem": None, "namespace": None, "package": None, "version": None, "purl_norm": None}
    if not purl:
        return empty
    try:
        # PackageURL handles percent-encoding (e.g. %40babel → @babel)
        p = PackageURL.from_string(purl.strip())
    except ValueError:
        return empty
    return {
        "ecosystem": p.type,
        "namespace": p.namespace,
        "package": p.name,
        "version": p.version,
        "purl_norm": p.to_string(),
    }


def vendor_proxy(
    *,
    ecosystem: str | None,
    namespace: str | None,
    package_name: str | None,
    supplier: str | None,
) -> str | None:
    """Best-effort 'vendor' stand-in when SPDX supplier is absent."""
    if supplier:
        s = str(supplier).strip()
        # SPDX often uses "Organization: Foo" / "Person: Bar"
        s = re.sub(r"^(Organization|Person|Tool):\s*", "", s, flags=re.I)
        if s and s.upper() not in {"NOASSERTION", "NONE"}:
            return s

    if namespace:
        return namespace
    if ecosystem and package_name:
        return f"{ecosystem}:{package_name}"
    return ecosystem


def package_key(
    ecosystem: str | None,
    namespace: str | None,
    package_name: str | None,
    version: str | None = None,
) -> str | None:
    if not package_name:
        return None
    eco = ecosystem or "?"
    if namespace:
        base = f"{eco}::{namespace}/{package_name}"
    else:
        base = f"{eco}::{package_name}"
    if version:
        return f"{base}@{version}"
    return base


def normalize_package_row(row: dict[str, Any]) -> dict[str, Any]:
    """Add normalized fields onto an extracted package row (non-destructive)."""
    out = dict(row)
    purl_info = parse_purl_safe(row.get("purl"))

    # Prefer PURL-derived identity; fall back to SPDX name fields
    eco_raw = purl_info["ecosystem"] or row.get("ecosystem")
    eco = normalize_ecosystem(eco_raw)

    ns_raw = purl_info["namespace"] if purl_info["namespace"] is not None else row.get("namespace")
    # If SPDX name is scoped npm (@babel/code-frame) and namespace missing, split it
    pkg_raw = purl_info["package"] or row.get("package_name")
    if eco == "npm" and isinstance(pkg_raw, str) and pkg_raw.startswith("@") and "/" in pkg_raw and not ns_raw:
        ns_raw, pkg_raw = pkg_raw.split("/", 1)

    ns = normalize_namespace(ns_raw, eco)
    pkg = normalize_package_name(pkg_raw, eco)

    version_norm, version_kind = classify_version(row.get("version_raw"))
    if version_norm is None and purl_info.get("version"):
        version_norm, version_kind = classify_version(purl_info["version"])

    out["ecosystem_norm"] = eco
    out["namespace_norm"] = ns
    out["package_name_norm"] = pkg
    out["version_norm"] = version_norm
    out["version_kind"] = version_kind
    out["purl_norm"] = purl_info.get("purl_norm") or row.get("purl")
    out["vendor_proxy"] = vendor_proxy(
        ecosystem=eco,
        namespace=ns,
        package_name=pkg,
        supplier=row.get("supplier"),
    )
    out["package_key"] = package_key(eco, ns, pkg)
    out["package_key_versioned"] = package_key(eco, ns, pkg, version_norm)
    return out
