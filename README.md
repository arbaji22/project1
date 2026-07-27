# ARSS SBOM Similarity Pipeline

Prototype pipeline for SBOM cleaning, normalization, feature extraction, and similarity analysis (proxy corpus: GitHub SPDX SBOMs).

## What gets pushed vs not

| Pushed to GitHub | Not pushed (too large / local) |
|---|---|
| `src/`, `scripts/`, `docs/` | `.venv/` (recreate with pip) |
| `outputs/` — **precomputed results included** | Raw SBOM dataset (~11 GB) |
| `requirements.txt`, `config.yaml`, `README.md` | |

You can **clone and use `outputs/` immediately** without rerunning. The dataset is only needed if you want to regenerate.

## Quick start — results only (no rerun)

```bash
git clone <YOUR_REPO_URL>
cd project2

# Open these — no Python required:
open outputs/similarity_explanations.md
open outputs/inventory_report.txt
```

Or browse `outputs/system_features.csv` and `outputs/similarity_pairs.csv` in Excel / pandas.

## Full pipeline (new machine, optional rerun)

### 1. Clone + Python

```bash
git clone <YOUR_REPO_URL>
cd project2
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Dataset (only if rerunning)

Download from [Zenodo](https://zenodo.org/records/15334733) → `github_spdx_sbom_sample.zip`

```bash
mkdir -p data
unzip github_spdx_sbom_sample.zip -d data/
# Expect: data/github_spdx_sbom_sample/*.json
```

On this Mac you can symlink instead of re-downloading:

```bash
ln -s /path/to/github_spdx_sbom_sample data/github_spdx_sbom_sample
```

### 3. Run (optional — outputs already in repo)

```bash
python scripts/inventory_sample.py --sample-size 2000
python scripts/extract_features.py
python scripts/similarity_sample.py --n-systems 100 --explain-top 10
```

## Take everything on a USB / zip (offline)

If you need the **raw SBOM files** too (not on GitHub):

```bash
cd /Users/arbaji10/internship/project2
zip -r arss-pipeline-with-data.zip . \
  -x ".venv/*" -x ".git/*" -x "__pycache__/*"
```

Or copy the project folder + separately copy `Downloads/github_spdx_sbom_sample/`.

## Scripts

| Script | Purpose |
|---|---|
| `scripts/inventory_sample.py` | Parse SBOMs → `packages_clean.csv` |
| `scripts/extract_features.py` | Features → `system_features.csv` |
| `scripts/similarity_sample.py` | Similarity + shared-package explanations |

## Docs

See `docs/PIPELINE.md` for methodology and changelog.  
See `outputs/README.md` for what the bundled snapshot contains.

## Requirements

- **View results only:** any machine with git
- **Rerun pipeline:** Python 3.10+, ~15 GB disk (dataset + venv)
