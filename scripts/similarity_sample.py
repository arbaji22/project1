#!/usr/bin/env python3
"""Step 4 similarity with stop-package filtering, IDF weighting, and explanations."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.similarity import (
    document_frequencies,
    explain_pair,
    filter_sets,
    format_explanation_markdown,
    idf_weights,
    pairwise_scores,
    stop_packages,
)


def load_config(path: Path) -> dict:
    with path.open() as f:
        return yaml.safe_load(f)


def load_all_sets(path: Path, field: str) -> dict[str, set[str]]:
    sets: dict[str, set[str]] = {}
    with path.open(encoding="utf-8") as f:
        for line in f:
            rec = json.loads(line)
            items = set(rec.get(field) or [])
            if items:
                sets[rec["source_file"]] = items
    return sets


def load_labels(features_path: Path) -> dict[str, str]:
    if not features_path.exists():
        return {}
    feats = pd.read_csv(features_path)
    if "sbom_name" not in feats.columns:
        return {}
    return {
        row.source_file: str(row.sbom_name)
        for row in feats.itertuples(index=False)
        if getattr(row, "sbom_name", None) and str(row.sbom_name) != "nan"
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "config.yaml")
    parser.add_argument(
        "--sets",
        type=Path,
        default=ROOT / "outputs" / "system_package_sets.jsonl",
    )
    parser.add_argument("--n-systems", type=int, default=100)
    parser.add_argument("--min-dependencies", type=int, default=None)
    parser.add_argument(
        "--feature",
        choices=["package_keys", "package_keys_versioned", "vendors", "ecosystems"],
        default="package_keys",
    )
    parser.add_argument("--max-df", type=float, default=None)
    parser.add_argument("--stop-top-k", type=int, default=None)
    parser.add_argument(
        "--weighted",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="IDF-weighted Jaccard (default from config). --no-weighted for classic.",
    )
    parser.add_argument("--no-stop", action="store_true")
    parser.add_argument("--top-pairs", type=int, default=20)
    parser.add_argument(
        "--explain-top",
        type=int,
        default=None,
        help="How many top pairs to explain (default: top_pairs)",
    )
    parser.add_argument(
        "--explain-packages",
        type=int,
        default=25,
        help="Max distinctive shared packages to list per pair",
    )
    parser.add_argument(
        "--min-shared",
        type=int,
        default=2,
        help="Skip explaining pairs with fewer shared tokens than this",
    )
    args = parser.parse_args()

    cfg = load_config(args.config) if args.config.exists() else {}
    sim_cfg = cfg.get("similarity", {}) if isinstance(cfg, dict) else {}

    max_df = args.max_df if args.max_df is not None else sim_cfg.get("max_df", 0.2)
    stop_top_k = (
        args.stop_top_k if args.stop_top_k is not None else sim_cfg.get("stop_top_k")
    )
    if args.weighted is None:
        weighted = bool(sim_cfg.get("weighted", False))
    else:
        weighted = args.weighted
    min_deps = (
        args.min_dependencies
        if args.min_dependencies is not None
        else cfg.get("min_dependencies", 1)
    )
    explain_top = args.explain_top if args.explain_top is not None else args.top_pairs

    out_dir = ROOT / cfg.get("output_dir", "outputs")
    if not args.sets.exists():
        raise SystemExit(
            f"Missing {args.sets} — run scripts/extract_features.py first."
        )

    all_sets = load_all_sets(args.sets, args.feature)
    if args.feature.startswith("package"):
        all_sets = {k: v for k, v in all_sets.items() if len(v) >= min_deps}

    if len(all_sets) < 2:
        raise SystemExit("Need ≥2 systems with features to compare.")

    n_docs = len(all_sets)
    df = document_frequencies(all_sets)
    weights = idf_weights(df, n_docs)

    stopped: set[str] = set()
    if not args.no_stop and args.feature.startswith("package"):
        stopped = stop_packages(df, n_docs, max_df=max_df, top_k=stop_top_k)

    filtered = filter_sets(all_sets, stopped) if stopped else dict(all_sets)
    filtered = {k: v for k, v in filtered.items() if v}
    if len(filtered) < 2:
        raise SystemExit(
            "Fewer than 2 systems left after stop-filtering — loosen max_df / stop_top_k."
        )

    ordered = [k for k in all_sets if k in filtered][: args.n_systems]
    if len(ordered) < 2:
        ordered = list(filtered.keys())[: args.n_systems]
    compare_sets = {k: filtered[k] for k in ordered}

    use_weights = weights if weighted else None
    matrix, pairs = pairwise_scores(compare_sets, ordered, weights=use_weights)

    out_dir.mkdir(parents=True, exist_ok=True)
    labels = load_labels(out_dir / "system_features.csv")

    idf_rows = [
        {
            "token": token,
            "df": d,
            "df_frac": d / n_docs,
            "idf": weights[token],
            "is_stop": token in stopped,
        }
        for token, d in df.most_common()
    ]
    idf_path = out_dir / "token_idf.csv"
    pd.DataFrame(idf_rows).to_csv(idf_path, index=False)

    stop_path = out_dir / "stop_packages.csv"
    pd.DataFrame(
        [{"token": t, "df": df[t], "df_frac": df[t] / n_docs} for t in sorted(stopped)]
    ).to_csv(stop_path, index=False)

    pair_df = pd.DataFrame(
        [
            {
                "similarity": s,
                "sbom_a": a,
                "sbom_b": b,
                "shared_count": n_shared,
                "shared_weight": w_shared,
            }
            for s, a, b, n_shared, w_shared in pairs
        ]
    )
    pair_path = out_dir / "similarity_pairs.csv"
    pair_df.to_csv(pair_path, index=False)
    mat_path = out_dir / "similarity_matrix.csv"
    pd.DataFrame(matrix, index=ordered, columns=ordered).to_csv(mat_path)

    # --- Explanations for top pairs ---
    explanations: list[dict] = []
    long_rows: list[dict] = []
    for score, a, b, n_shared, _w in pairs:
        if len(explanations) >= explain_top:
            break
        if n_shared < args.min_shared:
            continue
        ex = explain_pair(
            a,
            b,
            compare_sets[a],
            compare_sets[b],
            df=df,
            weights=weights,
            n_docs=n_docs,
            similarity=score,
            label_a=labels.get(a),
            label_b=labels.get(b),
            top_n_packages=args.explain_packages,
        )
        explanations.append(ex)
        for rank, pkg in enumerate(ex["top_shared_packages"], 1):
            long_rows.append(
                {
                    "pair_rank": len(explanations),
                    "similarity": ex["similarity"],
                    "sbom_a": a,
                    "sbom_b": b,
                    "label_a": ex["label_a"],
                    "label_b": ex["label_b"],
                    "shared_rank": rank,
                    "package": pkg["package"],
                    "idf": pkg["idf"],
                    "df": pkg["df"],
                    "df_frac": pkg["df_frac"],
                }
            )

    expl_jsonl = out_dir / "similarity_explanations.jsonl"
    with expl_jsonl.open("w", encoding="utf-8") as f:
        for ex in explanations:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")

    expl_md = out_dir / "similarity_explanations.md"
    expl_md.write_text(format_explanation_markdown(explanations))

    expl_csv = out_dir / "similarity_shared_packages.csv"
    pd.DataFrame(long_rows).to_csv(expl_csv, index=False)

    mode = "IDF-weighted Jaccard" if weighted else "Jaccard"
    stop_desc = "none" if args.no_stop else f"max_df={max_df}, stop_top_k={stop_top_k}"
    report_lines = [
        f"Corpus systems (IDF/DF): {n_docs}",
        f"Compared systems: {len(ordered)}",
        f"Feature: {args.feature}",
        f"Metric: {mode}",
        f"Stop rule: {stop_desc}",
        f"Stop tokens: {len(stopped)}",
        f"Mean tokens/system before stop: {sum(len(v) for v in all_sets.values()) / n_docs:.1f}",
        f"Mean tokens/system after stop (compared): {sum(len(compare_sets[k]) for k in ordered) / len(ordered):.1f}",
        f"Mean pairwise similarity: {pair_df['similarity'].mean():.4f}",
        f"Median pairwise similarity: {pair_df['similarity'].median():.4f}",
        f"Pairs explained: {len(explanations)} (min_shared={args.min_shared})",
        "",
        f"Top {min(15, len(stopped))} stopped tokens:" if stopped else "No stop tokens.",
    ]
    if stopped:
        shown = 0
        for token, d in df.most_common():
            if token not in stopped:
                continue
            report_lines.append(f"  {token}: df={d} ({d / n_docs:.1%})")
            shown += 1
            if shown >= 15:
                break

    report_path = out_dir / "similarity_report.txt"
    report_path.write_text("\n".join(report_lines) + "\n")

    print("\n".join(report_lines))
    print(f"\nTop {args.top_pairs} most similar pairs:")
    print(pair_df.head(args.top_pairs).to_string(index=False))

    if explanations:
        print("\n--- Explanations (distinctive shared packages) ---")
        for i, ex in enumerate(explanations[:5], 1):
            print(
                f"\n[{i}] {ex['label_a']}  ↔  {ex['label_b']}  "
                f"(sim={ex['similarity']:.4f}, shared={ex['n_shared']})"
            )
            for pkg in ex["top_shared_packages"][:8]:
                print(
                    f"    - {pkg['package']}  "
                    f"(idf={pkg['idf']:.2f}, {pkg['df_frac']:.1%} of corpus)"
                )
            if ex["n_shared"] > 8:
                print(f"    … +{ex['n_shared'] - 8} more")

    print(f"\nWrote {pair_path}")
    print(f"Wrote {mat_path}")
    print(f"Wrote {idf_path}")
    print(f"Wrote {stop_path}")
    print(f"Wrote {expl_jsonl}")
    print(f"Wrote {expl_md}")
    print(f"Wrote {expl_csv}")
    print(f"Wrote {report_path}")


if __name__ == "__main__":
    main()
