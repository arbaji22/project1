# ARSS SBOM Similarity Pipeline

Prototype pipeline for SBOM cleaning, normalization, feature extraction, and similarity analysis (proxy corpus: GitHub SPDX SBOMs).

## What gets pushed vs not

| Pushed to GitHub | Not pushed (local only) |
|---|---|
| `src/`, `scripts/`, `docs/` | `.venv/` |
| `requirements.txt`, `config.example.yaml` | `outputs/` (generated) |
| `README.md`, `.gitignore` | SBOM dataset (~11 GB) |

## Quick start (new machine)

### 1. Clone

```bash
git clone <YOUR_REPO_URL>
cd project2
```

### 2. Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Download the SBOM dataset

From [Zenodo](https://zenodo.org/records/15334733) — file `github_spdx_sbom_sample.zip` (~1.1 GB compressed, ~11 GB extracted).

```bash
mkdir -p data
# unzip into data/github_spdx_sbom_sample/
# You should see files like: 20250208_1001_sbom_data.json
```

### 4. Config

```bash
cp config.example.yaml config.yaml
# Edit data_dir if your dataset lives elsewhere
```

### 5. Run the pipeline

```bash
# Step 1–2: inventory + normalize (sample of 2000 files)
python scripts/inventory_sample.py --sample-size 2000

# Step 3: per-system features
python scripts/extract_features.py

# Step 4: similarity + explanations
python scripts/similarity_sample.py --n-systems 100 --explain-top 10
```

### 6. Check outputs

- `outputs/inventory_report.txt` — parse stats
- `outputs/system_features.csv` — one row per SBOM
- `outputs/similarity_explanations.md` — “they share X” narratives

## Scripts

| Script | Purpose |
|---|---|
| `scripts/inventory_sample.py` | Parse SBOMs → `packages_clean.csv` |
| `scripts/extract_features.py` | Features → `system_features.csv` |
| `scripts/similarity_sample.py` | Similarity + shared-package explanations |

## Docs

See `docs/PIPELINE.md` for full methodology, decisions, and changelog.

## Requirements

- Python 3.10+
- ~15 GB free disk (dataset + venv + outputs)
