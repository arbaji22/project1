# Precomputed outputs (reference snapshot)

These files were generated on **2026-07-22** so you can review results without rerunning the pipeline.

## Run settings

| Setting | Value |
|---|---|
| `sample_size` | 2000 |
| `random_seed` | 42 |
| `min_dependencies` | 1 |
| `similarity.max_df` | 0.20 |
| `similarity.weighted` | true |

## Key files to open

| File | What it is |
|---|---|
| `inventory_report.txt` | Parse / clean stats |
| `system_features.csv` | One feature row per SBOM |
| `similarity_explanations.md` | Top pairs + shared packages |
| `similarity_pairs.csv` | All pairwise scores |
| `packages_clean.csv` | Normalized package rows (large) |

## Rerun later

```bash
python scripts/inventory_sample.py --sample-size 2000
python scripts/extract_features.py
python scripts/similarity_sample.py --n-systems 100 --explain-top 10
```

Requires the SBOM dataset under `data/github_spdx_sbom_sample/` (not in git — ~11 GB).
