"""Unit tests for argus.core.svg_charts (Phase B1 — dependency-free SVG)."""

from __future__ import annotations

from argus.core.models import Severity
from argus.core.svg_charts import (
    SEVERITY_COLORS,
    bar_chart,
    donut,
    severity_donut,
    trend_line,
)


class TestDonut:
    def test_one_arc_per_nonzero_segment(self):
        svg = donut([("Crit", 3, "#e74c3c"), ("High", 1, "#e67e22"), ("Low", 0, "#3498db")])
        assert svg.startswith("<svg") and svg.endswith("</svg>")
        # background ring + 2 non-zero segments = 3 <circle>
        assert svg.count("<circle") == 3

    def test_total_in_center(self):
        assert ">7<" in donut([("a", 4, "#111"), ("b", 3, "#222")])

    def test_zero_total_renders_empty_ring(self):
        svg = donut([("a", 0, "#111")])
        assert svg.count("<circle") == 1  # just the background ring
        assert ">0<" in svg

    def test_label_escaped(self):
        svg = donut([("<script>", 1, "#111")])
        assert "<script>" not in svg and "&lt;script&gt;" in svg

    def test_center_overrides_displayed_total(self):
        # Arc proportions come from segments; the hole shows the override.
        svg = donut([("a", 4, "#111"), ("b", 3, "#222")], center=99)
        assert ">99<" in svg and ">7<" not in svg


class TestTrendLine:
    def test_polyline_has_point_per_value(self):
        svg = trend_line([1, 5, 2, 8])
        assert "<polyline" in svg
        pts = svg.split('points="', 1)[1].split('"', 1)[0]
        assert len(pts.split()) == 4

    def test_empty_is_valid_svg(self):
        svg = trend_line([])
        assert svg.startswith("<svg") and "polyline" not in svg

    def test_aria_label(self):
        assert 'role="img"' in trend_line([1, 2], title="trend")
        assert 'aria-label="trend"' in trend_line([1, 2], title="trend")


class TestBarChart:
    def test_bar_per_item_and_values_shown(self):
        svg = bar_chart([("bandit", 5), ("osv", 2)])
        assert svg.count("<rect") == 2
        assert ">5<" in svg and ">2<" in svg

    def test_largest_is_widest(self):
        svg = bar_chart([("a", 10), ("b", 5)], width=400)
        widths = [float(s.split('width="', 1)[1].split('"', 1)[0]) for s in svg.split("<rect ")[1:]]
        assert widths[0] > widths[1]

    def test_per_label_colors(self):
        svg = bar_chart([("critical", 3)], colors={"critical": "#e74c3c"})
        assert "#e74c3c" in svg

    def test_empty(self):
        assert "<rect" not in bar_chart([])

    def test_label_escaped(self):
        assert "&amp;" in bar_chart([("a&b", 1)])


class TestThemeAware:
    # Light-mode guard: structural colors must reference theme tokens (which
    # flip light/dark) rather than hardcoded dark hexes, so inline SVG renders
    # correctly under [data-theme="light"]. Severity hues stay fixed.
    def test_donut_uses_theme_tokens(self):
        svg = donut([("a", 3, "#e74c3c")])
        assert "var(--fg" in svg            # centre total text
        assert "var(--surface-alt" in svg   # track ring
        assert "#e74c3c" in svg             # severity hue stays fixed

    def test_bar_chart_uses_theme_tokens(self):
        svg = bar_chart([("bandit", 5)])
        assert "var(--fg-muted" in svg      # label
        assert "var(--fg," in svg           # value


class TestSeverityDonut:
    def test_maps_severity_to_brand_colors(self):
        svg = severity_donut([(Severity.CRITICAL, 2), (Severity.LOW, 1)])
        assert SEVERITY_COLORS["critical"] in svg
        assert SEVERITY_COLORS["low"] in svg
        assert ">3<" in svg  # total

    def test_handles_plain_strings(self):
        # tolerant of (str, count) too
        svg = severity_donut([("high", 1)])
        assert SEVERITY_COLORS["high"] in svg
