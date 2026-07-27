"""Step 3 — per-SBOM comparison features (software / vendor / version).

Feature definitions are documented in docs/PIPELINE.md.
"""

from __future__ import annotations

import json
import math
from collections import Counter
from typing import Any, Iterable

import pandas as pd


def _entropy(counts: Counter | dict) -> float:
    total = sum(counts.values())
    if total <= 0:
        return 0.0
    ent = 0.0
    for c in counts.values():
        if c <= 0:
            continue
        p = c / total
        ent -= p * math.log2(p)
    return ent


def _share_of_mode(counts: Counter) -> tuple[str | None, float]:
    if not counts:
        return None, 0.0
    mode, n = counts.most_common(1)[0]
    return mode, n / sum(counts.values())


def features_from_dependency_rows(
    source_file: str,
    sbom_name: str | None,
    deps: pd.DataFrame,
    *,
    top_ecosystems: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Build one feature row from non-root dependency packages of a single SBOM."""
    if deps.empty:
        row: dict[str, Any] = {
            "source_file": source_file,
            "sbom_name": sbom_name,
            "n_dependencies": 0,
            "n_unique_packages": 0,
            "n_unique_packages_versioned": 0,
            "n_ecosystems": 0,
            "primary_ecosystem": None,
            "primary_ecosystem_share": 0.0,
            "ecosystem_entropy": 0.0,
            "n_vendors": 0,
            "primary_vendor": None,
            "primary_vendor_share": 0.0,
            "vendor_entropy": 0.0,
            "frac_version_exact": 0.0,
            "frac_version_range": 0.0,
            "frac_version_missing": 0.0,
            "frac_version_branch": 0.0,
            "frac_version_other": 0.0,
            "n_version_exact": 0,
            "n_version_range": 0,
            "n_version_missing": 0,
        }
        if top_ecosystems:
            for eco in top_ecosystems:
                row[f"eco_count__{eco}"] = 0
                row[f"eco_share__{eco}"] = 0.0
        return row

    keys = deps["package_key"].dropna().astype(str)
    keys_v = deps["package_key_versioned"].dropna().astype(str)
    ecos = deps["ecosystem_norm"].fillna("unknown").astype(str)
    vendors = deps["vendor_proxy"].fillna("unknown").astype(str)
    kinds = deps["version_kind"].fillna("missing").astype(str)

    eco_counts = Counter(ecos.tolist())
    vendor_counts = Counter(vendors.tolist())
    kind_counts = Counter(kinds.tolist())
    n = len(deps)

    primary_eco, primary_eco_share = _share_of_mode(eco_counts)
    primary_vendor, primary_vendor_share = _share_of_mode(vendor_counts)

    row = {
        "source_file": source_file,
        "sbom_name": sbom_name,
        # Software / scale
        "n_dependencies": int(n),
        "n_unique_packages": int(keys.nunique()),
        "n_unique_packages_versioned": int(keys_v.nunique()),
        # Ecosystem (software stack family)
        "n_ecosystems": int(len(eco_counts)),
        "primary_ecosystem": primary_eco,
        "primary_ecosystem_share": round(primary_eco_share, 6),
        "ecosystem_entropy": round(_entropy(eco_counts), 6),
        # Vendor proxies
        "n_vendors": int(len(vendor_counts)),
        "primary_vendor": primary_vendor,
        "primary_vendor_share": round(primary_vendor_share, 6),
        "vendor_entropy": round(_entropy(vendor_counts), 6),
        # Version quality / pinning
        "frac_version_exact": round(kind_counts.get("exact", 0) / n, 6),
        "frac_version_range": round(kind_counts.get("range", 0) / n, 6),
        "frac_version_missing": round(kind_counts.get("missing", 0) / n, 6),
        "frac_version_branch": round(kind_counts.get("branch", 0) / n, 6),
        "frac_version_other": round(kind_counts.get("other", 0) / n, 6),
        "n_version_exact": int(kind_counts.get("exact", 0)),
        "n_version_range": int(kind_counts.get("range", 0)),
        "n_version_missing": int(kind_counts.get("missing", 0)),
    }

    if top_ecosystems:
        for eco in top_ecosystems:
            c = int(eco_counts.get(eco, 0))
            row[f"eco_count__{eco}"] = c
            row[f"eco_share__{eco}"] = round(c / n, 6) if n else 0.0

    return row


def package_set_record(source_file: str, deps: pd.DataFrame) -> dict[str, Any]:
    """Serializable package sets for set-based similarity (Step 4)."""
    keys = sorted(set(deps["package_key"].dropna().astype(str)))
    keys_v = sorted(set(deps["package_key_versioned"].dropna().astype(str)))
    vendors = sorted(set(deps["vendor_proxy"].dropna().astype(str)))
    ecosystems = sorted(set(deps["ecosystem_norm"].dropna().astype(str)))
    return {
        "source_file": source_file,
        "package_keys": keys,
        "package_keys_versioned": keys_v,
        "vendors": vendors,
        "ecosystems": ecosystems,
        "n_package_keys": len(keys),
        "n_vendors": len(vendors),
    }


def build_feature_tables(
    packages: pd.DataFrame,
    summary: pd.DataFrame | None = None,
    *,
    top_n_ecosystems: int = 10,
) -> tuple[pd.DataFrame, list[dict[str, Any]]]:
    """Return (system_features_df, package_set_records)."""
    deps = packages.loc[~packages["is_root"]].copy()
    if deps.empty:
        return pd.DataFrame(), []

    # Global top ecosystems for stable sparse columns
    top_ecos = (
        deps["ecosystem_norm"]
        .fillna("unknown")
        .value_counts()
        .head(top_n_ecosystems)
        .index.tolist()
    )

    name_map: dict[str, str | None] = {}
    if summary is not None and "sbom_name" in summary.columns:
        name_map = dict(zip(summary["source_file"], summary["sbom_name"]))

    feature_rows: list[dict[str, Any]] = []
    set_rows: list[dict[str, Any]] = []

    for source_file, group in deps.groupby("source_file", sort=False):
        sbom_name = name_map.get(source_file)
        if sbom_name is None and "sbom_name" in group.columns:
            sbom_name = group["sbom_name"].iloc[0]
        feature_rows.append(
            features_from_dependency_rows(
                source_file,
                sbom_name,
                group,
                top_ecosystems=top_ecos,
            )
        )
        set_rows.append(package_set_record(source_file, group))

    return pd.DataFrame(feature_rows), set_rows


def write_package_sets_jsonl(records: list[dict[str, Any]], path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
