"""Step 4 similarity helpers: stop-packages + IDF-weighted Jaccard.

Documented in docs/PIPELINE.md.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Iterable


def document_frequencies(sets: dict[str, set[str]]) -> Counter:
    """Count how many systems contain each token."""
    df: Counter = Counter()
    for items in sets.values():
        df.update(set(items))  # unique within system
    return df


def idf_weights(
    df: Counter,
    n_docs: int,
    *,
    smooth: bool = True,
) -> dict[str, float]:
    """Classic IDF: log((N+1)/(df+1))+1 when smooth, else log(N/df)."""
    weights: dict[str, float] = {}
    for token, d in df.items():
        if smooth:
            weights[token] = math.log((n_docs + 1) / (d + 1)) + 1.0
        else:
            weights[token] = math.log(n_docs / d) if d > 0 else 0.0
    return weights


def stop_packages(
    df: Counter,
    n_docs: int,
    *,
    max_df: float | None = 0.2,
    min_df: int = 1,
    top_k: int | None = None,
) -> set[str]:
    """Tokens too common (and optionally too rare) to keep in unweighted sets.

    A token is stopped if:
    - df/n_docs >= max_df (when max_df is set), OR
    - it is among the top_k most frequent tokens (when top_k is set), OR
    - df < min_df
    """
    stopped: set[str] = set()
    if n_docs <= 0:
        return stopped

    if max_df is not None:
        thresh = max_df * n_docs
        for token, d in df.items():
            if d >= thresh:
                stopped.add(token)

    if top_k is not None and top_k > 0:
        for token, _ in df.most_common(top_k):
            stopped.add(token)

    if min_df > 1:
        for token, d in df.items():
            if d < min_df:
                stopped.add(token)

    return stopped


def filter_sets(
    sets: dict[str, set[str]],
    remove: Iterable[str],
) -> dict[str, set[str]]:
    ban = set(remove)
    return {k: {t for t in v if t not in ban} for k, v in sets.items()}


def jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def weighted_jaccard(
    a: set[str],
    b: set[str],
    weights: dict[str, float],
    *,
    default_weight: float = 1.0,
) -> float:
    """Weighted Jaccard: sum(w∩) / sum(w∪)."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0

    def w(token: str) -> float:
        return weights.get(token, default_weight)

    inter = a & b
    union = a | b
    num = sum(w(t) for t in inter)
    den = sum(w(t) for t in union)
    return num / den if den > 0 else 0.0


def pairwise_scores(
    sets: dict[str, set[str]],
    names: list[str],
    *,
    weights: dict[str, float] | None = None,
) -> tuple[list[list[float]], list[tuple[float, str, str, int, float]]]:
    """Return dense matrix and pair tuples (score, a, b, shared_count, shared_weight)."""
    n = len(names)
    matrix = [[0.0] * n for _ in range(n)]
    pairs: list[tuple[float, str, str, int, float]] = []

    for i in range(n):
        matrix[i][i] = 1.0
        for j in range(i + 1, n):
            a, b = sets[names[i]], sets[names[j]]
            inter = a & b
            shared_n = len(inter)
            if weights is None:
                score = jaccard(a, b)
                shared_w = float(shared_n)
            else:
                score = weighted_jaccard(a, b, weights)
                shared_w = sum(weights.get(t, 1.0) for t in inter)
            matrix[i][j] = matrix[j][i] = score
            pairs.append((score, names[i], names[j], shared_n, shared_w))

    pairs.sort(reverse=True)
    return matrix, pairs


def explain_pair(
    name_a: str,
    name_b: str,
    set_a: set[str],
    set_b: set[str],
    *,
    df: Counter,
    weights: dict[str, float],
    n_docs: int,
    similarity: float,
    label_a: str | None = None,
    label_b: str | None = None,
    top_n_packages: int = 25,
) -> dict:
    """Build an evidence record: score + distinctive shared tokens.

    Shared tokens are ranked by IDF (rarer = more distinctive).
    """
    shared = set_a & set_b
    only_a = set_a - set_b
    only_b = set_b - set_a
    union = set_a | set_b

    shared_ranked = sorted(
        shared,
        key=lambda t: (weights.get(t, 0.0), -df.get(t, 0), t),
        reverse=True,
    )
    shared_details = [
        {
            "package": t,
            "idf": round(weights.get(t, 0.0), 6),
            "df": int(df.get(t, 0)),
            "df_frac": round(df.get(t, 0) / n_docs, 6) if n_docs else 0.0,
        }
        for t in shared_ranked[:top_n_packages]
    ]

    return {
        "sbom_a": name_a,
        "sbom_b": name_b,
        "label_a": label_a or name_a,
        "label_b": label_b or name_b,
        "similarity": round(similarity, 6),
        "n_shared": len(shared),
        "n_only_a": len(only_a),
        "n_only_b": len(only_b),
        "n_union": len(union),
        "shared_weight": round(sum(weights.get(t, 1.0) for t in shared), 6),
        "top_shared_packages": shared_details,
        "top_shared_package_names": [d["package"] for d in shared_details],
    }


def format_explanation_markdown(explanations: list[dict]) -> str:
    """Human-readable narrative for regulators / notes."""
    lines = [
        "# Similarity explanations",
        "",
        "Each pair lists **distinctive shared packages** (after stop-list),",
        "ranked by IDF so rarer shared components appear first.",
        "",
    ]
    for i, ex in enumerate(explanations, 1):
        lines.append(f"## Pair {i}: similarity = {ex['similarity']:.4f}")
        lines.append("")
        lines.append(f"- **A:** `{ex['label_a']}` (`{ex['sbom_a']}`)")
        lines.append(f"- **B:** `{ex['label_b']}` (`{ex['sbom_b']}`)")
        lines.append(
            f"- Overlap: **{ex['n_shared']}** shared / "
            f"{ex['n_union']} union "
            f"(A-only {ex['n_only_a']}, B-only {ex['n_only_b']})"
        )
        lines.append("")
        if not ex["top_shared_packages"]:
            lines.append("_No shared packages after filtering._")
            lines.append("")
            continue
        lines.append("They share (most distinctive first):")
        lines.append("")
        for d in ex["top_shared_packages"]:
            lines.append(
                f"- `{d['package']}` "
                f"(idf={d['idf']:.3f}, in {d['df_frac']:.1%} of corpus)"
            )
        lines.append("")
        # One-sentence story
        top_names = ex["top_shared_package_names"][:5]
        if top_names:
            joined = ", ".join(f"`{n}`" for n in top_names)
            lines.append(
                f"**Story:** These systems both depend on {joined}"
                + ("…" if len(ex["top_shared_package_names"]) > 5 else ".")
            )
            lines.append("")
    return "\n".join(lines)
