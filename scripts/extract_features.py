#!/usr/bin/env python3
"""Step 3 — extract per-SBOM comparison features from clean inventory outputs."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.features import build_feature_tables, write_package_sets_jsonl


def load_config(path: Path) -> dict:
    with path.open() as f:
        return yaml.safe_load(f)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "config.yaml")
    parser.add_argument(
        "--packages",
        type=Path,
        default=None,
        help="Defaults to outputs/packages_clean.csv",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=None,
        help="Defaults to outputs/sbom_summary_clean.csv",
    )
    parser.add_argument("--top-ecosystems", type=int, default=None)
    args = parser.parse_args()

    cfg = load_config(args.config)
    out_dir = ROOT / cfg.get("output_dir", "outputs")
    packages_path = args.packages or out_dir / "packages_clean.csv"
    summary_path = args.summary or out_dir / "sbom_summary_clean.csv"
    top_n = args.top_ecosystems or cfg.get("top_ecosystems", 10)

    if not packages_path.exists():
        raise SystemExit(
            f"Missing {packages_path} — run scripts/inventory_sample.py first."
        )

    packages = pd.read_csv(packages_path)
    summary = pd.read_csv(summary_path) if summary_path.exists() else None

    features_df, set_records = build_feature_tables(
        packages, summary, top_n_ecosystems=top_n
    )
    if features_df.empty:
        raise SystemExit("No dependency packages found to featurize.")

    out_dir.mkdir(parents=True, exist_ok=True)
    features_path = out_dir / "system_features.csv"
    sets_path = out_dir / "system_package_sets.jsonl"
    report_path = out_dir / "features_report.txt"

    features_df.to_csv(features_path, index=False)
    write_package_sets_jsonl(set_records, sets_path)

    lines = [
        f"Systems featurized: {len(features_df)}",
        f"Feature columns: {len(features_df.columns)}",
        "",
        "Scalar feature summary:",
        features_df[
            [
                "n_dependencies",
                "n_unique_packages",
                "n_ecosystems",
                "n_vendors",
                "primary_ecosystem_share",
                "frac_version_exact",
            ]
        ]
        .describe()
        .to_string(),
        "",
        "Primary ecosystem distribution:",
        features_df["primary_ecosystem"].fillna("unknown").value_counts().head(15).to_string(),
        "",
        "Example row:",
        features_df.iloc[0].to_string(),
    ]
    report = "\n".join(lines) + "\n"
    report_path.write_text(report)

    print(report)
    print(f"Wrote {features_path}")
    print(f"Wrote {sets_path}")
    print(f"Wrote {report_path}")


if __name__ == "__main__":
    main()
