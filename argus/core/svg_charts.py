"""Dependency-free SVG charts (Phase B1).

Pure, UI-free string builders that emit inline ``<svg>`` markup — no
``d3`` / ``plotly`` / chart library, matching the browser viewer's vanilla
CSS+JS style and keeping the dependency surface at zero. Lives in ``core``
(not ``viewers/browser``) so both the browser dashboard *and* the formal PDF
report (Phase B4) render identical charts from one place.

Charts: a donut (severity breakdown), a trend line (findings over runs), and
horizontal bars (by scanner / package). Each returns a self-contained
``<svg>`` element string; the data comes from ``argus.core.trends``.

Security note: every caller-supplied label is XML-escaped, so a finding's
scanner / package name can't inject markup into the page or the PDF.
"""

from __future__ import annotations

import math
from xml.sax.saxutils import escape as _xml_escape

# Brand severity colours (mirrors the browser argus.css palette).
SEVERITY_COLORS: dict[str, str] = {
    "critical": "#e74c3c",
    "high": "#e67e22",
    "medium": "#f1c40f",
    "low": "#3498db",
    "info": "#9fb09f",
    "unknown": "#7f8c8d",
}
_DEFAULT_COLOR = "#84b852"  # argus primary green


def _esc(text: object) -> str:
    return _xml_escape(str(text))


def donut(
    segments: list[tuple[str, int, str]],
    *,
    size: int = 160,
    thickness: int = 26,
    title: str = "",
    center: int | None = None,
) -> str:
    """Render a donut chart from ``(label, value, color)`` segments.

    Uses the stroke-dasharray ring technique (one arc per segment) so it's
    pure arithmetic — no path math. Zero-total input renders an empty ring.
    ``center`` overrides the number shown in the hole (e.g. an authoritative
    total from elsewhere); the arc proportions always come from the segments.
    """
    total = sum(max(0, v) for _, v, _ in segments)
    center_value = total if center is None else center
    radius = (size - thickness) / 2
    cx = cy = size / 2
    circumference = 2 * math.pi * radius
    parts: list[str] = [
        f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" '
        f'role="img" aria-label="{_esc(title or "severity breakdown")}">',
        f'<circle cx="{cx}" cy="{cy}" r="{radius:.2f}" fill="none" '
        f'stroke="#16211c" stroke-width="{thickness}"/>',
    ]
    offset = 0.0
    if total > 0:
        for label, value, color in segments:
            if value <= 0:
                continue
            seg_len = circumference * value / total
            parts.append(
                f'<circle cx="{cx}" cy="{cy}" r="{radius:.2f}" fill="none" '
                f'stroke="{_esc(color)}" stroke-width="{thickness}" '
                f'stroke-dasharray="{seg_len:.2f} {circumference - seg_len:.2f}" '
                f'stroke-dashoffset="{-offset:.2f}" '
                f'transform="rotate(-90 {cx} {cy})">'
                f'<title>{_esc(label)}: {value}</title></circle>'
            )
            offset += seg_len
    parts.append(
        f'<text x="{cx}" y="{cy}" text-anchor="middle" dominant-baseline="central" '
        f'font-size="{size // 6}" fill="#eaf2ea">{center_value}</text>'
    )
    parts.append("</svg>")
    return "".join(parts)


def trend_line(
    values: list[float],
    *,
    width: int = 280,
    height: int = 80,
    color: str = _DEFAULT_COLOR,
    title: str = "",
) -> str:
    """Render a sparkline-style trend polyline for ``values`` (left→right)."""
    label = _esc(title or "findings over time")
    if not values:
        return (
            f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
            f'role="img" aria-label="{label}"></svg>'
        )
    pad = 4
    lo, hi = min(values), max(values)
    span = (hi - lo) or 1
    n = len(values)
    step = (width - 2 * pad) / max(1, n - 1)
    points = []
    for i, v in enumerate(values):
        x = pad + i * step
        y = height - pad - (v - lo) / span * (height - 2 * pad)
        points.append(f"{x:.1f},{y:.1f}")
    pts = " ".join(points)
    last_x, last_y = points[-1].split(",")
    return (
        f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
        f'role="img" aria-label="{label}">'
        f'<polyline points="{pts}" pathLength="1" fill="none" stroke="{_esc(color)}" '
        f'stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>'
        f'<circle cx="{last_x}" cy="{last_y}" r="3" fill="{_esc(color)}"/>'
        f"</svg>"
    )


def bar_chart(
    items: list[tuple[str, int]],
    *,
    width: int = 320,
    bar_height: int = 18,
    gap: int = 6,
    color: str = _DEFAULT_COLOR,
    colors: dict[str, str] | None = None,
    title: str = "",
) -> str:
    """Render a horizontal bar chart from ``(label, value)`` items.

    ``colors`` optionally maps a label → bar colour (e.g. severity hues);
    otherwise every bar uses ``color``. Bars scale to the largest value.
    """
    label = _esc(title or "breakdown")
    if not items:
        return (
            f'<svg viewBox="0 0 {width} 20" width="{width}" height="20" '
            f'role="img" aria-label="{label}"></svg>'
        )
    largest = max((v for _, v in items), default=0) or 1
    label_w = 120
    track_w = width - label_w - 40
    height = len(items) * (bar_height + gap) + gap
    parts = [
        f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
        f'role="img" aria-label="{label}">'
    ]
    y = gap
    for name, value in items:
        fill = (colors or {}).get(name, color)
        bar_w = max(1, track_w * value / largest) if value else 0
        text_y = y + bar_height * 0.72
        parts.append(
            f'<text x="0" y="{text_y:.1f}" font-size="12" fill="#9fb09f">{_esc(name)}</text>'
            f'<rect x="{label_w}" y="{y}" width="{bar_w:.1f}" height="{bar_height}" '
            f'rx="2" fill="{_esc(fill)}"><title>{_esc(name)}: {value}</title></rect>'
            f'<text x="{label_w + bar_w + 6:.1f}" y="{text_y:.1f}" font-size="12" '
            f'fill="#eaf2ea">{value}</text>'
        )
        y += bar_height + gap
    parts.append("</svg>")
    return "".join(parts)


def severity_donut(breakdown: list[tuple[object, int]], **kwargs: object) -> str:
    """Convenience: a donut from ``trends.severity_breakdown`` output.

    Accepts ``(Severity, count)`` pairs; maps each to its brand colour.
    """
    segments: list[tuple[str, int, str]] = []
    for severity, count in breakdown:
        name = getattr(severity, "value", str(severity))
        segments.append((name.capitalize(), count, SEVERITY_COLORS.get(name, _DEFAULT_COLOR)))
    return donut(segments, **kwargs)  # type: ignore[arg-type]
