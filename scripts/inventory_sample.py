#!/usr/bin/env python3
"""Inventory a random sample of GitHub SPDX SBOMs → CSV summaries.

Hardened loader recovers concatenated API-error + SBOM JSON.
Writes full and cleaned (min-dependency) outputs.
"""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

import pandas as pd
import yaml
from tqdm import tqdm

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.sbom_parse import (
    SbomLoadError,
    extract_packages,
    extract_sbom_summary,
    load_sbom_detailed,
)


def load_config(path: Path) -> dict:
    with path.open() as f:
        return yaml.safe_load(f)


def list_sbom_files(data_dir: Path) -> list[Path]:
    return sorted(data_dir.glob("*_sbom_data.json"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "config.yaml")
    parser.add_argument("--sample-size", type=int, default=None)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument(
        "--min-dependencies",
        type=int,
        default=None,
        help="Minimum non-root packages for cleaned outputs",
    )
    args = parser.parse_args()

    cfg = load_config(args.config)
    data_dir = Path(cfg["data_dir"])
    sample_size = args.sample_size or cfg.get("sample_size", 2000)
    seed = args.seed if args.seed is not None else cfg.get("random_seed", 42)
    min_deps = (
        args.min_dependencies
        if args.min_dependencies is not None
        else cfg.get("min_dependencies", 1)
    )
    out_dir = ROOT / cfg.get("output_dir", "outputs")
    out_dir.mkdir(parents=True, exist_ok=True)

    files = list_sbom_files(data_dir)
    if not files:
        raise SystemExit(f"No SBOM files found in {data_dir}")

    rng = random.Random(seed)
    if sample_size < len(files):
        files = rng.sample(files, sample_size)

    summaries: list[dict] = []
    packages: list[dict] = []
    errors: list[dict] = []
    n_recovered = 0

    for path in tqdm(files, desc="Parsing SBOMs"):
        try:
            result = load_sbom_detailed(path)
            if result.recovered_concat:
                n_recovered += 1
            summaries.append(
                extract_sbom_summary(
                    result.sbom,
                    path.name,
                    recovered_concat=result.recovered_concat,
                    n_json_objects=result.n_json_objects,
                )
            )
            packages.extend(extract_packages(result.sbom, path.name))
        except (SbomLoadError, OSError, UnicodeDecodeError) as exc:
            errors.append({"source_file": path.name, "error": str(exc)})
        except Exception as exc:  # noqa: BLE001 — inventory should keep going
            errors.append({"source_file": path.name, "error": f"unexpected: {exc}"})

    summary_df = pd.DataFrame(summaries)
    packages_df = pd.DataFrame(packages)

    if len(summary_df):
        clean_mask = summary_df["n_dependencies"] >= min_deps
        clean_summary = summary_df.loc[clean_mask].copy()
        clean_files = set(clean_summary["source_file"])
        if len(packages_df):
            clean_packages = packages_df.loc[packages_df["source_file"].isin(clean_files)].copy()
            deps_df = packages_df.loc[~packages_df["is_root"]].copy()
            clean_deps = clean_packages.loc[~clean_packages["is_root"]].copy()
        else:
            clean_packages = packages_df
            deps_df = packages_df
            clean_deps = packages_df
    else:
        clean_summary = summary_df
        clean_packages = packages_df
        deps_df = packages_df
        clean_deps = packages_df

    summary_path = out_dir / "sbom_summary.csv"
    packages_path = out_dir / "packages.csv"
    clean_summary_path = out_dir / "sbom_summary_clean.csv"
    clean_packages_path = out_dir / "packages_clean.csv"
    errors_path = out_dir / "parse_errors.csv"
    report_path = out_dir / "inventory_report.txt"

    summary_df.to_csv(summary_path, index=False)
    packages_df.to_csv(packages_path, index=False)
    clean_summary.to_csv(clean_summary_path, index=False)
    clean_packages.to_csv(clean_packages_path, index=False)
    pd.DataFrame(errors).to_csv(errors_path, index=False)

    n_loaded = len(summary_df)
    n_empty = int((summary_df["n_dependencies"] < min_deps).sum()) if n_loaded else 0
    n_clean = len(clean_summary)

    lines = [
        f"Files scanned: {len(files)}",
        f"Loaded OK: {n_loaded}",
        f"  recovered from concatenated JSON: {n_recovered}",
        f"Parse / load failures: {len(errors)}",
        f"Dropped (n_dependencies < {min_deps}): {n_empty}",
        f"Clean SBOMs kept: {n_clean}",
        "",
        "— All loaded —",
        f"Mean dependencies: {summary_df['n_dependencies'].mean():.1f}" if n_loaded else "Mean dependencies: n/a",
        f"Median dependencies: {summary_df['n_dependencies'].median():.1f}" if n_loaded else "Median dependencies: n/a",
        f"Max dependencies: {summary_df['n_dependencies'].max()}" if n_loaded else "Max dependencies: n/a",
        "",
        f"— Clean (n_dependencies ≥ {min_deps}) —",
        f"Mean dependencies: {clean_summary['n_dependencies'].mean():.1f}" if n_clean else "Mean dependencies: n/a",
        f"Median dependencies: {clean_summary['n_dependencies'].median():.1f}" if n_clean else "Median dependencies: n/a",
        "",
        "Top ecosystems (clean dependency packages):",
    ]
    if len(clean_deps):
        eco_col = (
            "ecosystem_norm"
            if "ecosystem_norm" in clean_deps.columns
            else "ecosystem"
        )
        eco = clean_deps[eco_col].fillna("unknown").value_counts().head(15)
        for name, count in eco.items():
            lines.append(f"  {name}: {count}")
        lines.append("")
        lines.append("Version kind mix (clean deps):")
        if "version_kind" in clean_deps.columns:
            for name, count in clean_deps["version_kind"].fillna("missing").value_counts().items():
                lines.append(f"  {name}: {count}")
        lines.append("")
        lines.append("Top packages (clean, normalized package_key):")
        if "package_key" in clean_deps.columns:
            top = clean_deps["package_key"].fillna("?").value_counts().head(20)
        else:
            top = (
                clean_deps.assign(
                    key=clean_deps[eco_col].fillna("?")
                    + "::"
                    + clean_deps["package_name"].fillna("?")
                )["key"]
                .value_counts()
                .head(20)
            )
        for name, count in top.items():
            lines.append(f"  {name}: {count}")

        # Normalization quality checks
        lines.append("")
        lines.append("Normalization checks:")
        if "purl" in clean_deps.columns and "namespace_norm" in clean_deps.columns:
            encoded_purls = clean_deps["purl"].astype(str).str.contains("%", na=False).sum()
            encoded_ns = (
                clean_deps["namespace_norm"].astype(str).str.contains("%", na=False).sum()
            )
            lines.append(f"  purls still percent-encoded: {encoded_purls}")
            lines.append(f"  namespace_norm still percent-encoded: {encoded_ns}")
            scoped = clean_deps["package_key"].astype(str).str.contains("::@", na=False).sum()
            lines.append(f"  scoped package_keys (eco::@scope/name): {scoped}")
        if "package_key" in clean_deps.columns:
            lines.append(
                f"  unique package_key values: {clean_deps['package_key'].nunique()}"
            )
            lines.append(
                f"  unique raw package_name values: {clean_deps['package_name'].nunique()}"
            )
    else:
        lines.append("  (none)")

    if len(errors):
        lines.append("")
        lines.append("Top load-error reasons:")
        err_counts = pd.Series([e["error"].split(":")[0] for e in errors]).value_counts().head(10)
        for name, count in err_counts.items():
            lines.append(f"  {name}: {count}")

    report = "\n".join(lines) + "\n"
    report_path.write_text(report)
    print(report)
    print(f"Wrote {summary_path}")
    print(f"Wrote {packages_path}")
    print(f"Wrote {clean_summary_path}")
    print(f"Wrote {clean_packages_path}")
    print(f"Wrote {report_path}")


if __name__ == "__main__":
    main()
