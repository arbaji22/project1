#!/usr/bin/env python3
"""Generate poster figures from precomputed outputs/.

Writes transparent-background PNG (300 dpi) to figures/.

  python scripts/make_figures.py
"""

from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import pandas as pd
from matplotlib.gridspec import GridSpec
from matplotlib.patches import FancyBboxPatch

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "outputs"
FIG = ROOT / "figures"

C_INK = "#1a1a1a"
C_MUTED = "#5c5c5c"
C_GRID = "#e6e6e6"
C_ACCENT = "#0b6e4f"
C_ACCENT2 = "#b35c00"
C_NEUTRAL = "#6b7280"
C_SOFT = "#d1d5db"
COHORT_COLORS = [
    "#0b6e4f",
    "#1d4e89",
    "#b35c00",
    "#6b3fa0",
    "#8b2942",
    "#2f6f7a",
]


def style_axes(ax, *, grid_y: bool = True) -> None:
    ax.set_facecolor("none")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color(C_SOFT)
    ax.spines["bottom"].set_color(C_SOFT)
    ax.tick_params(colors=C_MUTED, labelsize=9)
    if grid_y:
        ax.yaxis.grid(True, color=C_GRID, linewidth=0.8)
        ax.set_axisbelow(True)


def save(fig: plt.Figure, name: str) -> None:
    FIG.mkdir(parents=True, exist_ok=True)
    fig.patch.set_alpha(0.0)
    for ax in fig.axes:
        ax.set_facecolor("none")
    path = FIG / f"{name}.png"
    fig.savefig(
        path,
        dpi=300,
        bbox_inches="tight",
        pad_inches=0.25,
        facecolor="none",
        edgecolor="none",
        transparent=True,
    )
    print(f"Wrote {path}")
    plt.close(fig)


def _rounded(ax, xy, w, h, *, fc="#f3f4f6", ec=C_SOFT, lw=1.2, radius=0.03, z=1):
    box = FancyBboxPatch(
        xy,
        w,
        h,
        boxstyle=f"round,pad=0.012,rounding_size={radius}",
        linewidth=lw,
        facecolor=fc,
        edgecolor=ec,
        zorder=z,
    )
    ax.add_patch(box)
    return box


def fig0_sbom_anatomy() -> None:
    """Simple poster graphic: what one SBOM contains."""
    fig, ax = plt.subplots(figsize=(11.5, 6.2))
    ax.set_xlim(0, 11.5)
    ax.set_ylim(0, 6.2)
    ax.axis("off")
    ax.set_facecolor("none")

    # Outer SBOM document frame (stroke only — transparent fill)
    _rounded(
        ax, (0.35, 0.45), 10.8, 5.3,
        fc=(1, 1, 1, 0.0), ec=C_ACCENT, lw=2.0, radius=0.08, z=0,
    )
    ax.text(
        0.6,
        5.45,
        "One SBOM document  (Software Bill of Materials)",
        fontsize=14,
        fontweight="semibold",
        color=C_INK,
        zorder=2,
    )
    ax.text(
        0.6,
        5.1,
        "SPDX 2.3 JSON  ·  lists a system and every software component it depends on",
        fontsize=9.5,
        color=C_MUTED,
        zorder=2,
    )

    # Header card
    _rounded(ax, (0.6, 3.85), 3.3, 1.0, fc=(0.91, 0.96, 0.94, 0.92), ec=C_ACCENT, lw=1.4, radius=0.05)
    ax.text(0.8, 4.55, "Document header", fontsize=10, fontweight="semibold", color=C_ACCENT)
    ax.text(0.8, 4.25, "name   ·   SPDX version", fontsize=9, color=C_INK)
    ax.text(0.8, 3.98, "creation info   ·   document ID", fontsize=9, color=C_MUTED)

    # Root system card
    _rounded(ax, (4.2, 3.85), 3.3, 1.0, fc=(1.0, 0.96, 0.91, 0.92), ec=C_ACCENT2, lw=1.4, radius=0.05)
    ax.text(4.4, 4.55, "Root system", fontsize=10, fontweight="semibold", color=C_ACCENT2)
    ax.text(4.4, 4.25, "the repo / product being described", fontsize=9, color=C_INK)
    ax.text(4.4, 3.98, "example: owner/my-app", fontsize=9, color=C_MUTED, fontstyle="italic")

    # Identity key card
    _rounded(ax, (7.8, 3.85), 3.0, 1.0, fc=(0.95, 0.95, 0.96, 0.92), ec=C_NEUTRAL, lw=1.4, radius=0.05)
    ax.text(8.0, 4.55, "How we compare", fontsize=10, fontweight="semibold", color=C_NEUTRAL)
    ax.text(8.0, 4.25, "package_key = eco::name", fontsize=9, color=C_INK, fontfamily="monospace")
    ax.text(8.0, 3.98, "version dropped for overlap", fontsize=9, color=C_MUTED)

    ax.text(
        0.6,
        3.45,
        "Dependency packages  (the components inside the SBOM)",
        fontsize=11,
        fontweight="semibold",
        color=C_INK,
    )

    pkgs = [
        ("npm package", "react", "version  18.2.0", "purl  pkg:npm/react@18.2.0", "ecosystem  npm"),
        ("Maven artifact", "org.slf4j:slf4j-api", "version  1.7.36", "purl  pkg:maven/…", "vendor proxy  org.slf4j"),
        ("PyPI package", "numpy", "version  1.26.4", "purl  pkg:pypi/numpy@…", "ecosystem  pypi"),
    ]
    x0 = 0.6
    for title, name, ver, purl, extra in pkgs:
        _rounded(ax, (x0, 1.15), 3.3, 2.05, fc=(1, 1, 1, 0.88), ec=C_SOFT, lw=1.3, radius=0.05)
        _rounded(ax, (x0 + 0.15, 2.8), 1.35, 0.28, fc=(0.91, 0.96, 0.94, 0.95), ec=C_ACCENT, lw=0.8, radius=0.04)
        ax.text(x0 + 0.82, 2.93, title, fontsize=8, color=C_ACCENT, ha="center", va="center", fontweight="semibold")
        ax.text(x0 + 0.2, 2.45, name, fontsize=12, fontweight="semibold", color=C_INK, fontfamily="monospace")
        ax.text(x0 + 0.2, 2.05, ver, fontsize=9, color=C_INK)
        ax.text(x0 + 0.2, 1.7, purl, fontsize=8.5, color=C_MUTED, fontfamily="monospace")
        ax.text(x0 + 0.2, 1.35, extra, fontsize=8.5, color=C_MUTED)
        x0 += 3.5

    ax.annotate(
        "",
        xy=(5.75, 3.25),
        xytext=(5.75, 3.85),
        arrowprops=dict(arrowstyle="-|>", color=C_ACCENT2, lw=1.4),
    )
    ax.text(6.0, 3.5, "depends on", fontsize=8, color=C_ACCENT2, fontstyle="italic")

    ax.text(
        5.75,
        0.55,
        "Each SBOM ≈ one system + a set of packages with name, version, ecosystem, and identity (PURL).",
        fontsize=9.5,
        color=C_MUTED,
        ha="center",
    )
    save(fig, "fig0_sbom_anatomy")


def fig1_inventory(feat: pd.DataFrame) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(11.2, 4.8))
    fig.subplots_adjust(wspace=0.45)
    fig.patch.set_alpha(0.0)

    ax = axes[0]
    sizes = [1472, 528]
    colors = [C_SOFT, C_ACCENT]
    wedges, _ = ax.pie(
        sizes,
        colors=colors,
        startangle=90,
        wedgeprops=dict(width=0.58, edgecolor="white", linewidth=2),
        labels=None,
    )
    ax.legend(
        wedges,
        ["Empty (dropped)  73.6%  ·  1,472", "Clean (≥1 dep)  26.4%  ·  528"],
        loc="upper center",
        bbox_to_anchor=(0.5, -0.02),
        frameon=False,
        fontsize=9,
    )
    ax.text(
        0,
        0,
        "528\nclean",
        ha="center",
        va="center",
        fontsize=12,
        color=C_INK,
        fontweight="semibold",
    )
    ax.set_title("Sample composition (n = 2,000)", color=C_INK, fontsize=12, pad=10)

    ax = axes[1]
    deps = feat["n_dependencies"]
    bins = [1, 10, 50, 100, 500, 1000, float(deps.max()) + 1]
    labels_x = ["1–9", "10–49", "50–99", "100–499", "500–999", "1000+"]
    counts = [
        int(((deps >= bins[i]) & (deps < bins[i + 1])).sum()) for i in range(len(bins) - 1)
    ]
    bars = ax.bar(labels_x, counts, color=C_ACCENT, width=0.72, edgecolor="white")
    style_axes(ax)
    ax.set_xlabel("Dependencies per SBOM", color=C_MUTED, fontsize=10)
    ax.set_ylabel("Number of systems", color=C_MUTED, fontsize=10)
    ax.set_title("Clean corpus size distribution (n = 528)", color=C_INK, fontsize=12, pad=10)
    ax.set_ylim(0, max(counts) * 1.22)
    for b, c in zip(bars, counts):
        ax.text(
            b.get_x() + b.get_width() / 2,
            b.get_height() + max(counts) * 0.02,
            str(c),
            ha="center",
            va="bottom",
            fontsize=8,
            color=C_MUTED,
        )

    fig.suptitle(
        "Figure 1. SBOM inventory and cleaning",
        fontsize=13,
        fontweight="semibold",
        color=C_INK,
        y=1.02,
    )
    fig.text(
        0.72,
        -0.06,
        f"median = {deps.median():.0f} deps   ·   mean = {deps.mean():.0f} deps",
        ha="center",
        fontsize=9,
        color=C_MUTED,
    )
    save(fig, "fig1_inventory")


def fig2_ecosystems(feat: pd.DataFrame) -> None:
    counts = feat["primary_ecosystem"].value_counts()
    rename = {"github_actions": "GitHub Actions"}
    labels = [rename.get(i, i) for i in counts.index]
    values = counts.values

    fig, ax = plt.subplots(figsize=(9, 4.8))
    y = np.arange(len(labels))[::-1]
    vals = values[::-1]
    labs = labels[::-1]
    colors = [C_ACCENT if lab == "npm" else C_NEUTRAL for lab in labs]
    ax.barh(y, vals, color=colors, height=0.68, edgecolor="white")
    style_axes(ax, grid_y=False)
    ax.xaxis.grid(True, color=C_GRID, linewidth=0.8)
    ax.set_yticks(y)
    ax.set_yticklabels(labs, fontsize=10, color=C_INK)
    ax.set_xlabel("Number of clean systems", color=C_MUTED, fontsize=10)
    ax.set_title(
        "Figure 2. Primary ecosystem among clean SBOMs (n = 528)",
        color=C_INK,
        fontsize=12,
        pad=12,
    )
    ax.set_xlim(0, max(vals) * 1.18)
    for yi, v in zip(y, vals):
        ax.text(v + max(vals) * 0.015, yi, str(v), va="center", fontsize=9, color=C_MUTED)

    fig.text(
        0.5,
        -0.01,
        "npm accounts for ≈96% of clean dependency rows (mono-stack systems dominate).",
        ha="center",
        fontsize=9,
        color=C_MUTED,
    )
    save(fig, "fig2_ecosystems")


def fig3_similarity(pairs: pd.DataFrame) -> None:
    s = pairs["similarity"]
    fig, axes = plt.subplots(
        1, 2, figsize=(11.2, 4.8), gridspec_kw={"width_ratios": [1, 1.55]}
    )
    fig.subplots_adjust(wspace=0.4)

    ax = axes[0]
    zero = int((s == 0).sum())
    nonzero = int((s > 0).sum())
    bars = ax.bar(
        ["sim = 0", "sim > 0"],
        [zero, nonzero],
        color=[C_SOFT, C_ACCENT],
        width=0.55,
        edgecolor="white",
    )
    style_axes(ax)
    ax.set_ylabel("Number of pairs", color=C_MUTED, fontsize=10)
    ax.set_title("Zero vs nonzero (4,950 pairs)", color=C_INK, fontsize=11, pad=8)
    ax.set_ylim(0, max(zero, nonzero) * 1.2)
    for b, v in zip(bars, [zero, nonzero]):
        pct = 100 * v / len(s)
        ax.text(
            b.get_x() + b.get_width() / 2,
            b.get_height() + max(zero, nonzero) * 0.03,
            f"{v:,}\n({pct:.1f}%)",
            ha="center",
            va="bottom",
            fontsize=9,
            color=C_MUTED,
        )

    ax = axes[1]
    pos = s[s > 0]
    bins = [0, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0001]
    labels = ["≤0.01", "0.01–0.05", "0.05–0.1", "0.1–0.25", "0.25–0.5", "0.5–1"]
    hist, _ = np.histogram(pos, bins=bins)
    colors = [C_NEUTRAL] * 3 + [C_ACCENT2] * 2 + [C_ACCENT]
    ax.bar(labels, hist, color=colors, width=0.78, edgecolor="white")
    style_axes(ax)
    ax.set_xlabel("Similarity bin", color=C_MUTED, fontsize=10)
    ax.set_ylabel("Number of pairs", color=C_MUTED, fontsize=10)
    ax.set_title(
        f"Nonzero tail (n = {len(pos):,}; mean = {pos.mean():.3f})",
        color=C_INK,
        fontsize=11,
        pad=8,
    )
    ax.set_ylim(0, max(hist) * 1.18)
    ax.tick_params(axis="x", rotation=15)
    for i, v in enumerate(hist):
        ax.text(i, v + max(hist) * 0.02, str(v), ha="center", va="bottom", fontsize=8, color=C_MUTED)

    fig.suptitle(
        "Figure 3. Pairwise SBOM similarity distribution",
        fontsize=13,
        fontweight="semibold",
        color=C_INK,
        y=1.05,
    )
    fig.text(
        0.5,
        -0.04,
        "IDF-weighted Jaccard on package_keys  ·  max_df = 0.20 stop-list  ·  100 systems",
        ha="center",
        fontsize=9,
        color=C_MUTED,
    )
    save(fig, "fig3_similarity")


def _display_name(name: str) -> str:
    name = str(name).replace("com.github.", "")
    if "/" in name:
        owner, repo = name.split("/", 1)
        if len(repo) > 18:
            repo = repo[:16] + "…"
        return f"{owner}/{repo}" if len(owner) <= 12 else f"{owner[:10]}…/{repo}"
    return name[:22]


def fig4_similarity_graph(pairs: pd.DataFrame, feat: pd.DataFrame) -> None:
    """Graph with letter IDs on nodes + roster panel (no label/edge collisions)."""
    edges = pairs[pairs["similarity"] >= 0.5].copy()
    name_map = dict(zip(feat.source_file, feat.sbom_name))
    eco_map = dict(zip(feat.source_file, feat.primary_ecosystem))

    G = nx.Graph()
    for a, b, sim in edges[["sbom_a", "sbom_b", "similarity"]].itertuples(index=False):
        G.add_edge(a, b, weight=float(sim))

    components = sorted(
        [list(c) for c in nx.connected_components(G) if len(c) >= 2],
        key=len,
        reverse=True,
    )
    # Stable order within each component by display name
    for comp in components:
        comp.sort(key=lambda n: _display_name(name_map.get(n, n)))

    cohort_titles = [
        "C1  CRA / React  (mean 0.81)",
        "C2  Large npm SPA  (0.54)",
        "C3  Slideshow forks  (0.95)",
        "C4  Tiny identical  (1.00)",
        "C5  singing-city pair  (0.64)",
        "C6  RN / app pair  (0.52)",
    ]

    # Assign IDs like C1a, C1b, …
    node_id: dict[str, str] = {}
    node_cohort: dict[str, int] = {}
    roster_lines: list[tuple[str, str, str]] = []  # id, name, cohort title
    for i, comp in enumerate(components):
        for j, n in enumerate(comp):
            nid = f"C{i + 1}{chr(ord('a') + j)}"
            node_id[n] = nid
            node_cohort[n] = i
            roster_lines.append(
                (nid, _display_name(name_map.get(n, n)), cohort_titles[i])
            )

    # Pack cohorts on a 3×2 grid with large gaps so halos never collide
    # Top: C1 C2 C5    Bottom: C3 C4 C6
    anchors = [
        (0.0, 2.4),  # C1
        (2.2, 2.4),  # C2
        (0.0, 0.0),  # C3
        (2.2, 0.0),  # C4
        (4.4, 2.4),  # C5
        (4.4, 0.0),  # C6
    ]
    pos: dict[str, tuple[float, float]] = {}
    for i, comp in enumerate(components):
        sub = G.subgraph(comp)
        if len(comp) <= 5:
            sp = nx.circular_layout(sub, scale=1.0)
        else:
            sp = nx.spring_layout(sub, weight="weight", seed=42 + i, iterations=100)
        xs = np.array([sp[n][0] for n in comp])
        ys = np.array([sp[n][1] for n in comp])
        xs = (xs - xs.mean()) / (xs.std() + 1e-6)
        ys = (ys - ys.mean()) / (ys.std() + 1e-6)
        scale = 0.42 if len(comp) >= 4 else 0.28
        ax0, ay0 = anchors[i]
        for n, x, y in zip(comp, xs, ys):
            pos[n] = (ax0 + float(x) * scale, ay0 + float(y) * scale)

    fig = plt.figure(figsize=(14.0, 7.6))
    gs = GridSpec(1, 2, width_ratios=[2.5, 1.0], wspace=0.06, figure=fig)
    ax = fig.add_subplot(gs[0, 0])
    ax_leg = fig.add_subplot(gs[0, 1])
    ax.set_aspect("equal")
    ax.axis("off")
    ax_leg.axis("off")

    # Soft cohort halos (tight to nodes — no neighbor bleed)
    for i, comp in enumerate(components):
        xs = np.array([pos[n][0] for n in comp])
        ys = np.array([pos[n][1] for n in comp])
        cx, cy = float(xs.mean()), float(ys.mean())
        rad = float(np.hypot(xs - cx, ys - cy).max()) + 0.28
        circ = plt.Circle(
            (cx, cy),
            rad,
            facecolor=COHORT_COLORS[i],
            edgecolor=COHORT_COLORS[i],
            linewidth=1.0,
            alpha=0.10,
            zorder=0,
        )
        ax.add_patch(circ)
        ax.text(
            cx,
            cy + rad + 0.08,
            f"C{i + 1}",
            ha="center",
            va="bottom",
            fontsize=10,
            fontweight="semibold",
            color=COHORT_COLORS[i],
            zorder=5,
        )

    # Draw edges as clean rings (n≥3) or single links (pairs) — no crossing clutter
    for i, comp in enumerate(components):
        sub = G.subgraph(comp)
        n = len(comp)
        if n >= 3:
            ordered = sorted(
                comp,
                key=lambda node: np.arctan2(
                    pos[node][1] - np.mean([pos[m][1] for m in comp]),
                    pos[node][0] - np.mean([pos[m][0] for m in comp]),
                ),
            )
            edge_list = list(zip(ordered, ordered[1:] + ordered[:1]))
        else:
            edge_list = list(sub.edges())

        for u, v in edge_list:
            x1, y1 = pos[u]
            x2, y2 = pos[v]
            # Shorten so edges meet node borders, not centers (keeps IDs readable)
            dx, dy = x2 - x1, y2 - y1
            length = max(np.hypot(dx, dy), 1e-6)
            shrink = 0.11
            sx1, sy1 = x1 + dx / length * shrink, y1 + dy / length * shrink
            sx2, sy2 = x2 - dx / length * shrink, y2 - dy / length * shrink
            w = G[u][v]["weight"] if G.has_edge(u, v) else 0.5
            lw = 1.4 + 2.0 * max(w - 0.5, 0) / 0.5
            ax.plot(
                [sx1, sx2],
                [sy1, sy2],
                color=C_MUTED,
                linewidth=lw,
                alpha=0.75,
                solid_capstyle="round",
                zorder=1,
            )

    for n, (x, y) in pos.items():
        cid = node_cohort[n]
        color = COHORT_COLORS[cid]
        eco = eco_map.get(n, "")
        marker = "o" if eco == "npm" else ("s" if eco == "gem" else "D")
        ax.scatter(
            [x],
            [y],
            s=520,
            c=color,
            marker=marker,
            edgecolors="white",
            linewidths=1.6,
            zorder=3,
        )
        ax.text(
            x,
            y,
            node_id[n],
            ha="center",
            va="center",
            fontsize=7.5,
            fontweight="bold",
            color="white",
            zorder=4,
        )

    # Pad view so titles aren't clipped
    xs = [p[0] for p in pos.values()]
    ys = [p[1] for p in pos.values()]
    ax.set_xlim(min(xs) - 0.9, max(xs) + 0.9)
    ax.set_ylim(min(ys) - 0.9, max(ys) + 1.0)

    # Roster panel
    y = 0.98
    ax_leg.text(
        0.0,
        y,
        "Node roster",
        fontsize=11,
        fontweight="semibold",
        color=C_INK,
        transform=ax_leg.transAxes,
        va="top",
    )
    y -= 0.05
    ax_leg.text(
        0.0,
        y,
        "circle = npm    square = gem",
        fontsize=8,
        color=C_MUTED,
        transform=ax_leg.transAxes,
        va="top",
    )
    y -= 0.06
    current_cohort = None
    for nid, dname, ctitle in roster_lines:
        cohort_key = ctitle.split("  ")[0]
        if cohort_key != current_cohort:
            current_cohort = cohort_key
            y -= 0.018
            ax_leg.text(
                0.0,
                y,
                ctitle,
                fontsize=8,
                fontweight="semibold",
                color=COHORT_COLORS[int(cohort_key[1]) - 1],
                transform=ax_leg.transAxes,
                va="top",
            )
            y -= 0.038
        ax_leg.text(
            0.02,
            y,
            f"{nid}  {dname}",
            fontsize=7.5,
            color=C_INK,
            family="monospace",
            transform=ax_leg.transAxes,
            va="top",
        )
        y -= 0.034

    fig.suptitle(
        "Figure 4. SBOM similarity graph (edge if IDF Jaccard ≥ 0.5)",
        fontsize=13,
        fontweight="semibold",
        color=C_INK,
        y=0.98,
    )
    fig.text(
        0.38,
        0.02,
        "21 of 100 systems in 6 cohorts  ·  29 edges  ·  clustering 0.94  ·  "
        "79 isolates not shown  ·  rings = connected cohorts (sim ≥ 0.5)",
        ha="center",
        fontsize=8,
        color=C_MUTED,
    )
    save(fig, "fig4_similarity_graph")


def fig5_shared_packages(shared: pd.DataFrame, feat: pd.DataFrame) -> None:
    a = "20250306_550_sbom_data.json"
    b = "20250315_1221_sbom_data.json"
    mask = ((shared.sbom_a == a) & (shared.sbom_b == b)) | (
        (shared.sbom_a == b) & (shared.sbom_b == a)
    )
    sub = shared[mask].sort_values("idf", ascending=False).head(12)
    if sub.empty:
        raise RuntimeError("CRA-like pair not found in similarity_shared_packages.csv")

    labels = []
    idfs = []
    for _, r in sub.iterrows():
        pkg = str(r["package"]).replace("npm::", "")
        # Prefer readable shortening over ellipsis mid-word
        if pkg.startswith("@") and "/" in pkg:
            scope, name = pkg.split("/", 1)
            if len(pkg) > 40:
                pkg = f"{scope}/\n{name}" if len(name) <= 28 else f"{scope}/{name[:26]}…"
        elif len(pkg) > 40:
            pkg = pkg[:38] + "…"
        labels.append(pkg)
        idfs.append(float(r["idf"]))

    labels = labels[::-1]
    idfs = idfs[::-1]

    fig, ax = plt.subplots(figsize=(10.5, 5.8))
    y = np.arange(len(labels))
    ax.barh(y, idfs, color=C_ACCENT, height=0.65, edgecolor="white")
    style_axes(ax, grid_y=False)
    ax.xaxis.grid(True, color=C_GRID, linewidth=0.8)
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=8.5, color=C_INK, fontfamily="monospace", linespacing=1.15)
    xmin = min(idfs) - 0.2
    xmax = max(idfs) + 0.4
    ax.set_xlim(xmin, xmax)
    for yi, v in zip(y, idfs):
        ax.text(v + 0.025, yi, f"{v:.2f}", va="center", fontsize=8, color=C_MUTED)
    ax.set_xlabel("IDF weight (higher = rarer shared package)", color=C_MUTED, fontsize=10)
    ax.set_title(
        "Figure 5. Distinctive shared packages — CRA-like pair\n"
        "TextUtils-React vs atg-world  ·  similarity = 0.926  ·  631 shared packages",
        color=C_INK,
        fontsize=12,
        pad=12,
    )
    fig.text(
        0.5,
        -0.02,
        "Stop-list removed ubiquitous packages (debug, semver, …); "
        "ranked overlap highlights stack-specific components.",
        ha="center",
        fontsize=9,
        color=C_MUTED,
    )
    fig.subplots_adjust(left=0.36)
    save(fig, "fig5_shared_packages")


def fig6_graph_thresholds() -> None:
    thresholds = [0.05, 0.10, 0.25, 0.50]
    edges = [500, 291, 84, 29]
    clusters = [7, 9, 10, 6]
    giant = [52, 40, 16, 5]
    clustering = [0.754, 0.688, 0.817, 0.938]
    labels = [f"≥ {t}" for t in thresholds]
    x = np.arange(len(thresholds))

    fig, (ax1, ax2) = plt.subplots(
        2, 1, figsize=(8.8, 6.0), sharex=True, gridspec_kw={"height_ratios": [1.4, 1]}
    )
    fig.subplots_adjust(hspace=0.22)

    w = 0.36
    ax1.bar(x - w / 2, edges, width=w, color=C_NEUTRAL, label="Edges", edgecolor="white")
    ax1.bar(
        x + w / 2,
        giant,
        width=w,
        color=C_ACCENT2,
        label="Giant component size",
        edgecolor="white",
    )
    style_axes(ax1)
    ax1.set_ylabel("Count", color=C_MUTED, fontsize=10)
    ax1.set_title(
        "Figure 6. Similarity-graph structure vs edge threshold",
        color=C_INK,
        fontsize=12,
        pad=10,
    )
    ax1.legend(frameon=False, fontsize=9, loc="upper right")
    ax1.set_ylim(0, max(edges) * 1.18)
    for i, (e, g) in enumerate(zip(edges, giant)):
        ax1.text(i - w / 2, e + 12, str(e), ha="center", fontsize=8, color=C_MUTED)
        ax1.text(i + w / 2, g + 12, str(g), ha="center", fontsize=8, color=C_MUTED)

    # Bottom: clustering line only (no dual-axis bar overlap)
    ax2.plot(
        x,
        clustering,
        color=C_INK,
        marker="o",
        linewidth=2.2,
        markersize=8,
        label="Local clustering",
    )
    style_axes(ax2)
    ax2.set_ylabel("Local clustering", color=C_MUTED, fontsize=10)
    ax2.set_xlabel("Similarity edge threshold", color=C_MUTED, fontsize=10)
    ax2.set_ylim(0.60, 1.06)
    for i, v in enumerate(clustering):
        ax2.text(i, v + 0.028, f"{v:.2f}", ha="center", fontsize=9, color=C_INK)
    ax2.set_xticks(x)
    ax2.set_xticklabels(
        [f"{lab}\n{c} clusters" for lab, c in zip(labels, clusters)],
        fontsize=9,
    )

    fig.text(
        0.5,
        -0.01,
        "At ≥0.5, remaining cohorts are small, dense cliques (clustering 0.94) — "
        "candidate common-stack / low-diversity groups.",
        ha="center",
        fontsize=9,
        color=C_MUTED,
    )
    save(fig, "fig6_graph_thresholds")


def main() -> None:
    feat = pd.read_csv(OUT / "system_features.csv")
    pairs = pd.read_csv(OUT / "similarity_pairs.csv")
    shared = pd.read_csv(OUT / "similarity_shared_packages.csv")

    plt.rcParams.update(
        {
            "font.family": "sans-serif",
            "font.sans-serif": ["Helvetica Neue", "Arial", "DejaVu Sans"],
            "axes.titleweight": "semibold",
            "figure.dpi": 150,
            "savefig.transparent": True,
            "figure.facecolor": "none",
            "axes.facecolor": "none",
        }
    )

    # Remove old PDFs if present
    for pdf in FIG.glob("*.pdf"):
        pdf.unlink()
        print(f"Deleted {pdf}")

    fig0_sbom_anatomy()
    fig1_inventory(feat)
    fig2_ecosystems(feat)
    fig3_similarity(pairs)
    fig4_similarity_graph(pairs, feat)
    fig5_shared_packages(shared, feat)
    fig6_graph_thresholds()

    (FIG / "README.md").write_text(
        """# Poster figures

Generated by `python scripts/make_figures.py` from `outputs/`.

Transparent-background PNG @ 300 dpi (no PDF).

| File | Description |
|---|---|
| `fig0_sbom_anatomy` | What one SBOM contains (header, root, packages) |
| `fig1_inventory` | Empty vs clean composition + dependency-size histogram |
| `fig2_ecosystems` | Primary ecosystem counts (clean corpus) |
| `fig3_similarity` | Pairwise IDF-weighted Jaccard distribution |
| `fig4_similarity_graph` | Similarity graph with ID roster (edge if sim ≥ 0.5) |
| `fig5_shared_packages` | IDF-ranked shared packages for CRA-like pair |
| `fig6_graph_thresholds` | Graph metrics vs similarity threshold |
"""
    )
    print(f"Wrote {FIG / 'README.md'}")


if __name__ == "__main__":
    main()
