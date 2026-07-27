# ARSS SBOM Pipeline Notes

Living notes for the internship prototype: SBOM cleaning → features → similarity / diversity analysis, using a public GitHub SPDX corpus as a **proxy** until reactor-domain SBOMs are available.

## Project context (why this exists)

Modern reactor digital systems often lack vendor HBOM/SBOM transparency. Shared hidden components can create **common-cause failure (CCF)** risk and weaken **D³** (defense-in-depth & diversity) arguments.

**Proposed approach**

1. Data collection (HBOM/SBOM-related info)
2. Data cleaning and normalization
3. Extract comparison features (hardware, software, vendor, version)
4. Similarity and diversity analysis

This repo currently focuses on **software (SBOM) only**, steps 1–3 complete, with a thin step-4 prototype.

## Proxy dataset

| Field | Value |
|---|---|
| Name | SBOM Dataset from 100 000+ Public GitHub Repositories |
| Authors | Chaora, Anesu; Camp, L. Jean |
| Location (local) | `/Users/arbaji10/Downloads/github_spdx_sbom_sample` |
| Size | ~101,476 SPDX JSON files (~11 GB) |
| Format | GitHub Dependency Graph → SPDX 2.3 JSON (`{"sbom": {...}}`) |
| Collected | 2025-02-08 → 2025-05-02 |
| Zenodo | https://zenodo.org/records/15334733 |

**Domain caveat:** These are mostly open-source application repos (npm-heavy), not ICS/OT or nuclear I&C stacks. Use for **pipeline / method development**, not for CCF claims about reactors.

---

## Repo layout

```
project2/
  config.yaml                 # data_dir, sample_size, min_dependencies
  requirements.txt
  docs/
    PIPELINE.md               # this file
  src/
    sbom_parse.py             # load + flatten SPDX JSON
    normalize.py              # Step 2 normalization rules
    features.py               # Step 3 per-SBOM features
    similarity.py             # Step 4 stop-list + IDF Jaccard
  scripts/
    inventory_sample.py       # sample → CSV inventory
    extract_features.py       # Step 3 feature tables
    similarity_sample.py      # Step 4 similarity
  outputs/                    # generated artifacts (gitignored)
```

## How to run

```bash
cd /Users/arbaji10/internship/project2
source .venv/bin/activate
pip install -r requirements.txt

# Step 1–2: parse sample, clean empty SBOMs, normalize package fields
python scripts/inventory_sample.py --sample-size 2000

# Step 3: per-SBOM comparison features
python scripts/extract_features.py

# Step 4 prototype: similarity on Step 3 package-set features
python scripts/similarity_sample.py --n-systems 100
# baselines / variants:
python scripts/similarity_sample.py --n-systems 100 --no-stop --no-weighted   # raw Jaccard
python scripts/similarity_sample.py --n-systems 100 --no-stop --weighted      # IDF only
python scripts/similarity_sample.py --feature vendors --n-systems 100 --no-weighted
```

Key config (`config.yaml`):

- `data_dir` — path to the SPDX sample
- `sample_size` — files to randomly sample (full corpus is large)
- `min_dependencies` — clean outputs keep SBOMs with at least this many non-root packages
- `top_ecosystems` — how many ecosystems become `eco_count__*` / `eco_share__*` columns
- `similarity.max_df` / `weighted` / `stop_top_k` — Step 4 stop-list + IDF settings
- `random_seed` — reproducible sampling

---

## Step 1 — Load / clean (done)

### Problems found in the raw corpus

1. **Concatenated JSON** — some files contain a GitHub API error object (`401 Bad credentials`, `404`, …) *and* a valid `{"sbom": ...}` in the same file. Strict `json.load` fails with `Extra data`.
2. **Empty SBOMs** — many files only describe the root GitHub repo package (no dependency packages). ~70% of a 2k sample had `n_dependencies == 0`.
3. **No SPDX `supplier`** — supplier fields are effectively unused in this corpus; vendor must be proxied.

### What we implemented

- `load_sbom_detailed()` walks **all** JSON values in a file via `JSONDecoder.raw_decode`, keeps the richest SPDX document, flags `recovered_concat`.
- Inventory drops SBOMs below `min_dependencies` into separate clean CSVs.

### Outputs

| File | Meaning |
|---|---|
| `outputs/sbom_summary.csv` | One row per successfully loaded SBOM |
| `outputs/packages.csv` | All packages (raw + normalized columns) |
| `outputs/sbom_summary_clean.csv` | SBOMs with enough dependencies |
| `outputs/packages_clean.csv` | Packages for clean SBOMs only |
| `outputs/parse_errors.csv` | Load failures (should be rare after concat fix) |
| `outputs/inventory_report.txt` | Human-readable stats |

### Snapshot (sample_size=2000, seed=42, min_dependencies=1)

- Loaded OK: **2000** (0 hard failures)
- Recovered from concatenated JSON: **92**
- Dropped empty: **1472**
- Clean SBOMs kept: **528**
- Clean median dependencies: **54.5**

---

## Step 2 — Normalization (current)

Code: `src/normalize.py`. Applied automatically during `extract_packages()`.

### Goals

Make two dependency entries compare as the **same component** when they should (encoding, case, PyPI spelling, scoped npm names), and classify version quality so similarity can ignore junk.

### Rules

| Field | Rule |
|---|---|
| **PURL parse** | Use `packageurl-python` (handles `%40babel` → `@babel`) |
| **ecosystem_norm** | Lowercase; alias `githubactions` → `github_actions` |
| **namespace_norm** | URL-decode; lowercase for npm/pypi/cargo/… |
| **package_name_norm** | Ecosystem-specific: npm/cargo/gem/nuget/… → lowercase; **PyPI** → PEP 503 (`_`/`.` → `-`, lower); **Maven** → artifactId if `group:artifact`; **Go** → keep path case |
| **version_norm / version_kind** | Strip `^` `~` `>=` etc.; kinds: `exact`, `range`, `branch`, `missing`, `other` |
| **vendor_proxy** | SPDX supplier if present; else namespace; else `ecosystem:name` |
| **package_key** | `eco::name` or `eco::namespace/name` (no version) — **default similarity identity** |
| **package_key_versioned** | Same + `@version_norm` when available |

### New / important columns on package rows

- `ecosystem_norm`, `namespace_norm`, `package_name_norm`
- `version_norm`, `version_kind`
- `purl_norm`, `vendor_proxy`
- `package_key`, `package_key_versioned`

Raw columns (`package_name`, `version_raw`, `purl`, …) are retained for audit.

### Why this matters for CCF-style analysis later

Normalization errors create **false diversity** (same library counted as two) or **false homogeneity** (different libs collapsed). Documenting rules here is part of the method’s evidence trail for M3/M4.

---

## Step 3 — Features (done)

Maps to the slide goal: *“Create hardware, software, vendor, and version features for each system.”*  
Hardware is out of scope until HBOMs exist; software/vendor/version are derived from normalized SBOM deps.

Code: `src/features.py` · runner: `scripts/extract_features.py`

### Feature groups (one row per SBOM in `system_features.csv`)

| Group | Fields | Purpose |
|---|---|---|
| **Software / scale** | `n_dependencies`, `n_unique_packages`, `n_unique_packages_versioned` | System size & uniqueness |
| **Ecosystem** | `n_ecosystems`, `primary_ecosystem`, `primary_ecosystem_share`, `ecosystem_entropy`, `eco_count__*`, `eco_share__*` | Stack family mix (diversity signal) |
| **Vendor** | `n_vendors`, `primary_vendor`, `primary_vendor_share`, `vendor_entropy` | Homogeneity of suppliers/namespaces |
| **Version** | `frac_version_*`, `n_version_*` | Pinning quality / uncertainty |

### Set features (`system_package_sets.jsonl`)

One JSON object per SBOM for set-based Step 4 metrics:

- `package_keys` / `package_keys_versioned`
- `vendors`
- `ecosystems`

### Outputs

| File | Meaning |
|---|---|
| `outputs/system_features.csv` | Tabular features for ML / stats |
| `outputs/system_package_sets.jsonl` | Sets for Jaccard / overlap analysis |
| `outputs/features_report.txt` | Quick describe + primary ecosystem mix |

### Design notes

- Scalar features support clustering/classifiers later (M3).
- Set features support interpretable overlap (“shared digital components”).
- `vendor_proxy` is **not** a true vendor — see Step 2; treat as namespace-level stand-in.
- Top ecosystem columns are corpus-relative (from the clean sample being featurized).

---

## Step 4 — Similarity (in progress)

`scripts/similarity_sample.py` loads `system_package_sets.jsonl` and compares systems with:

| Mode | Flag / config | Behavior |
|---|---|---|
| Stop-packages | `similarity.max_df` (default **0.20**) | Drop tokens in ≥20% of systems before comparing |
| Optional top-K stop | `similarity.stop_top_k` | Also drop K most frequent tokens |
| Unweighted Jaccard | `--no-stop` / `weighted: false` | Classic set overlap on filtered sets |
| **IDF-weighted Jaccard** | `similarity.weighted: true` (default) | Rare shared packages count more than ubiquitous ones |

IDF (smoothed): \(\mathrm{idf}(t)=\ln\frac{N+1}{\mathrm{df}(t)+1}+1\)

Weighted Jaccard: \(\frac{\sum_{t \in A \cap B} w_t}{\sum_{t \in A \cup B} w_t}\)

Set feature choices (`--feature`): `package_keys` (default), `package_keys_versioned`, `vendors`, `ecosystems`.

### Outputs

| File | Meaning |
|---|---|
| `similarity_pairs.csv` | Ranked pairwise scores |
| `similarity_matrix.csv` | Dense matrix for compared systems |
| `token_idf.csv` | df / df_frac / idf / is_stop for every token |
| `stop_packages.csv` | Tokens removed by the stop rule |
| `similarity_explanations.md` | **Human narrative:** top pairs + distinctive shared packages |
| `similarity_explanations.jsonl` | Same explanations as structured JSON |
| `similarity_shared_packages.csv` | Long form: one row per (pair, shared package) |
| `similarity_report.txt` | Human-readable settings + top stops |

### Explanations (“they share X”)

For each top pair (after stop-list), we list shared packages **ranked by IDF** (rarer overlap first). That is the evidence trail:

> Systems A and B both depend on `pkg1`, `pkg2`, … — not merely “similarity = 0.93.”

Trivial 1-package overlaps are skipped by default (`--min-shared 2`).

### Why stop / IDF

Ultra-common npm utilities (`debug`, `ms`, `semver`, …) create **false homogeneity**. For CCF-style questions we care more about shared *distinctive* stack components than shared leaf utilities.

### Still limited

- Forks / templates can still look identical after filtering
- Not yet mapped to D³ / CCF categories
- `max_df` is corpus-relative (recompute when the clean sample changes)

---

## Decision log

| Date | Decision | Rationale |
|---|---|---|
| 2026-07-22 | Use Chaora GitHub SPDX corpus as proxy | No reactor SBOMs yet; need real SPDX at scale |
| 2026-07-22 | Recover concatenated JSON instead of dropping files | 92/2000 were recoverable; dropping wastes signal |
| 2026-07-22 | Separate `*_clean.csv` rather than deleting empties from full tables | Keeps audit trail of empty rate |
| 2026-07-22 | Prefer PURL identity over SPDX display name | Stable across tools; `packageurl-python` decodes npm scopes (`%40babel` → `@babel`) |
| 2026-07-22 | Default similarity on name-level `package_key` (not versioned) | Range versions are common; versioned keys under-merge |
| 2026-07-22 | `vendor_proxy` from namespace when supplier missing | This corpus has ~0 usable suppliers |
| 2026-07-22 | Emit both scalar CSV features and JSONL package sets | Scalars for ML; sets for explainable overlap / CCF storytelling |
| 2026-07-22 | Default `max_df=0.20` + IDF-weighted Jaccard | Down-weight ubiquitous packages that inflate similarity |
| 2026-07-22 | Emit per-pair shared-package explanations ranked by IDF | Regulators need “they share X,” not only a score |

---

## Changelog

### 2026-07-22 — Similarity explanations

- Top pairs now emit distinctive shared packages (IDF-ranked)
- New outputs: `similarity_explanations.md`, `.jsonl`, `similarity_shared_packages.csv`

### 2026-07-22 — Stop-packages + IDF similarity

- Added `src/similarity.py`
- Similarity defaults: filter tokens with df≥20% of systems; IDF-weighted Jaccard
- New outputs: `token_idf.csv`, `stop_packages.csv`, `similarity_report.txt`

### 2026-07-22 — Step 3 feature extraction

- Added `src/features.py` and `scripts/extract_features.py`
- Outputs: `system_features.csv`, `system_package_sets.jsonl`, `features_report.txt`
- Similarity script consumes Step 3 sets (`--feature package_keys|vendors|ecosystems|…`)

### 2026-07-22 — Normalization pass

- Added `src/normalize.py` + `packageurl-python` dependency
- Inventory report includes version-kind mix and encoding checks
- Similarity uses `package_key` / `package_key_versioned`

### 2026-07-22 — Hardened loader

- Concat JSON recovery; clean vs full outputs; initial inventory + Jaccard prototype
