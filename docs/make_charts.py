#!/usr/bin/env python3
"""Generate the README benchmark chart with only the Python standard library.

Run from the worktree root: python docs/make_charts.py
The output is deterministic; this script does not train or run the scanner.
"""

from __future__ import annotations

from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "assets" / "benchmark.svg"

# Source: README.md, "Audited benchmark (181 adversarial examples)", full-row table.
# These exact four-decimal published values were verified against
# evals/results/2026-11-17-{before,after}.json at public threshold 0.5.
# Full results include fitting rows: descriptive, NOT independent generalization.
SERIES = ("v0.1.0", "v0.2.0")
METRICS = (
    ("Injection recall", "Higher is better", ("0.2963", "0.6173")),
    ("F1", "Higher is better", ("0.5537", "0.7282")),
    (
        "False-positive rate",
        "Lower is better · more benign flags after tuning",
        ("0.1167", "0.1667"),
    ),
)

WIDTH = 960
HEIGHT = 588
PLOT_X = 248
PLOT_WIDTH = 640
BAR_HEIGHT = 20

# Selected light AND dark categorical slots from the dataviz reference palette.
# Both pairs passed validate_palette.js on their respective chart surfaces.
STYLE = """
.viz-root {
  color-scheme: light;
  --surface: #fcfcfb;
  --primary: #0b0b0b;
  --secondary: #52514e;
  --grid: #e1e0d9;
  --baseline: #c3c2b7;
  --series-1: #2a78d6;
  --series-2: #eb6834;
  --texture-1: #104281;
  --texture-2: #d95926;
}
@media (prefers-color-scheme: dark) {
  .viz-root {
    color-scheme: dark;
    --surface: #1a1a19;
    --primary: #f0efec;
    --secondary: #c3c2b7;
    --grid: #2c2c2a;
    --baseline: #383835;
    --series-1: #3987e5;
    --series-2: #d95926;
    --texture-1: #9ec5f4;
    --texture-2: #eb6834;
  }
}
text {
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  font-size: 15px;
  fill: var(--primary);
}
.heading { font-size: 29px; font-weight: 650; }
.metric { font-size: 18px; font-weight: 650; }
.secondary, .version, .tick { fill: var(--secondary); }
.hint, .version, .tick { font-size: 14px; }
.value { font-size: 16px; font-weight: 650; }
.tick, .value { font-variant-numeric: tabular-nums; }
.frame, .tooltip-bg { fill: var(--surface); }
.grid { stroke: var(--grid); stroke-width: 1; }
.baseline { stroke: var(--baseline); stroke-width: 1; }
.series-1 { fill: var(--series-1); }
.series-2 { fill: var(--series-2); }
.hit { fill: transparent; }
.bar { outline: none; }
.bar:hover .mark, .bar:focus .mark { opacity: 0.8; }
.bar:focus .hit { stroke: var(--primary); stroke-width: 1; }
.tooltip { visibility: hidden; pointer-events: none; }
.tooltip-bg { stroke: var(--baseline); stroke-width: 1; }
.bar:hover .tooltip, .bar:focus .tooltip { visibility: visible; }
.texture { display: none; pointer-events: none; }
@media print {
  .viz-root {
    color-scheme: light;
    --surface: #fcfcfb;
    --primary: #0b0b0b;
    --secondary: #52514e;
    --grid: #e1e0d9;
    --baseline: #c3c2b7;
    --series-1: #2a78d6;
    --series-2: #eb6834;
    --texture-1: #104281;
    --texture-2: #d95926;
  }
  .texture { display: inline; }
}
@media (forced-colors: active) {
  .viz-root { forced-color-adjust: none; }
  .texture { display: inline; }
}
"""


def text(x: float, y: float, label: str, css: str = "secondary", anchor: str = "start") -> str:
    """Escape labels and keep all chart text on semantic ink tokens."""
    return f'<text x="{x:g}" y="{y:g}" class="{css}" text-anchor="{anchor}">{escape(label)}</text>'


def bar_path(y: float, value: str) -> str:
    """Use a zero baseline, square anchored end and 4px rounded data-end."""
    width = float(value) * PLOT_WIDTH
    return (
        f"M {PLOT_X} {y:g} h {width - 4:.3f} "
        f"a 4 4 0 0 1 4 4 v {BAR_HEIGHT - 8} "
        f"a 4 4 0 0 1 -4 4 H {PLOT_X} Z"
    )


def bar(metric: str, series_index: int, value: str, center: float, hint: str) -> str:
    """Add direct series labels, enlarged hit areas and hover/focus readouts."""
    series = SERIES[series_index]
    slot = series_index + 1
    y = center - BAR_HEIGHT / 2
    width = float(value) * PLOT_WIDTH
    label = f"{series} · {metric}: {value}. {hint}."
    pieces = [
        f'<g class="bar" tabindex="0" role="img" aria-label="{escape(label, quote=True)}">',
        f"<title>{escape(label)}</title>",
        f'<path class="mark series-{slot}" d="{bar_path(y, value)}"/>',
        f'<path class="texture" fill="url(#texture-{slot})" d="{bar_path(y, value)}"/>',
        # Each hit area is 28px tall: larger than the 20px mark, with a surface gap.
        f'<rect class="hit" x="{PLOT_X - 2}" y="{center - 14:g}" '
        f'width="{width + 4:.3f}" height="28"/>',
        text(PLOT_X - 16, center + 5, series, "version", "end"),
    ]
    # Label the after endpoints only; exact before values are in the README table,
    # accessible description and per-mark readouts, never gated behind hover.
    if series_index == 1:
        pieces.append(text(PLOT_X + width + 10, center + 5, value, "value"))
    pieces.extend(
        [
            f'<g class="tooltip" aria-hidden="true" transform="translate(608 {center - 72:g})">',
            '<rect class="tooltip-bg" width="280" height="60" rx="8"/>',
            text(14, 24, value, "value"),
            text(14, 46, f"{series} · {metric}", "secondary hint"),
            "</g></g>",
        ]
    )
    return "\n".join(pieces)


def make_svg() -> str:
    values = "; ".join(
        f"{metric}: {SERIES[0]} {pair[0]}, {SERIES[1]} {pair[1]}" for metric, _, pair in METRICS
    )
    description = (
        "Grouped horizontal bars on one common 0–1 axis. "
        f"{values}. False-positive rate is worse when higher: benign flags rise from 7 to 10. "
        "Full 181 rows include fitting data; descriptive, not an independent generalization "
        "estimate. The holdout was inspected during development, not a blind external test. "
        "Source: README.md audited benchmark; recorded reports dated 2026-11-17, threshold 0.5. "
        "The README provides the full data table and counts."
    )
    pieces = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" '
        f'viewBox="0 0 {WIDTH} {HEIGHT}" class="viz-root" role="img" '
        'aria-labelledby="chart-title chart-desc">',
        '<title id="chart-title">PromptWarden: more recall, with a false-positive cost</title>',
        f'<desc id="chart-desc">{escape(description)}</desc>',
        f"<style>{STYLE}</style>",
        "<defs>",
        '<pattern id="texture-1" width="8" height="8" patternUnits="userSpaceOnUse" '
        'patternTransform="rotate(45)">',
        '<path d="M 0 0 V 8" stroke="var(--texture-1)" stroke-width="2"/>',
        "</pattern>",
        '<pattern id="texture-2" width="8" height="8" patternUnits="userSpaceOnUse" '
        'patternTransform="rotate(135)">',
        '<path d="M 0 0 V 8" stroke="var(--texture-2)" stroke-width="2"/>',
        "</pattern></defs>",
        f'<rect class="frame" width="{WIDTH}" height="{HEIGHT}" rx="20"/>',
        text(32, 46, "More recall, with a false-positive cost", "heading"),
        text(32, 76, "Audited benchmark · full 181 rows · public threshold 0.5 · 2026-11-17"),
    ]
    for index, series in enumerate(SERIES):
        x = 32 + index * 242
        pieces.extend(
            [
                f'<rect class="series-{index + 1}" x="{x}" y="99" width="18" height="12" rx="2"/>',
                text(x + 28, 111, series),
            ]
        )
    pieces.append(text(888, 111, "Score / rate · 0–1", "secondary hint", "end"))
    for value in (0.0, 0.25, 0.5, 0.75, 1.0):
        x = PLOT_X + value * PLOT_WIDTH
        css = "baseline" if value == 0.0 else "grid"
        pieces.append(f'<line class="{css}" x1="{x:g}" x2="{x:g}" y1="178" y2="458"/>')
        pieces.append(text(x, 482, f"{value:.2f}", "tick", "middle"))
    for index, (metric, hint, pair) in enumerate(METRICS):
        top = 156 + index * 108
        pieces.append(text(32, top, metric, "metric"))
        # Keep the tradeoff sentence out of the plot: the left column is narrow.
        short_hint = "Lower is better" if index == 2 else hint
        pieces.append(text(32, top + 23, short_hint, "secondary hint"))
        for series_index, value in enumerate(pair):
            pieces.append(bar(metric, series_index, value, top + 42 + series_index * 28, hint))
    pieces.extend(
        [
            '<line class="grid" x1="32" x2="928" y1="505" y2="505"/>',
            text(32, 531, "FPR tradeoff: benign flags rise from 7 to 10. Lower FPR is better."),
            text(
                32,
                554,
                "Includes fitting rows: descriptive, not an independent generalization estimate.",
            ),
            text(
                32,
                577,
                "The holdout was inspected during development; it is not a blind external test.",
            ),
            "</svg>",
        ]
    )
    return "\n".join(pieces) + "\n"


def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(make_svg(), encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
