#!/usr/bin/env python3
"""Generate GitHub-renderable assurance documentation from a release profile."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import math
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any


PROFILE_POLICY = "dcrypt-v4-assurance-profile-v1"
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


class DocumentationError(RuntimeError):
    """Raised when source evidence cannot support the generated documentation."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def require_mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DocumentationError(f"{label} must be an object")
    return value


def require_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise DocumentationError(f"{label} must be a non-negative integer")
    return value


def require_number(value: object, label: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise DocumentationError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise DocumentationError(f"{label} must be finite and non-negative")
    return result


def validate_profile(profile: object) -> dict[str, Any]:
    root = require_mapping(profile, "profile")
    if root.get("content_policy") != PROFILE_POLICY:
        raise DocumentationError("unsupported Assurance Profile content policy")

    release = require_mapping(root.get("release"), "release")
    version = release.get("version")
    if not isinstance(version, str) or SEMVER.fullmatch(version) is None:
        raise DocumentationError("release.version must be a stable semantic version")
    subject = require_mapping(release.get("subject"), "release.subject")
    commit = subject.get("commit")
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise DocumentationError("release.subject.commit must be a full Git object id")
    if subject.get("working_tree_clean") is not True:
        raise DocumentationError("release subject must record a clean working tree")

    status = require_mapping(root.get("status"), "status")
    passed = require_int(status.get("commands_passed"), "status.commands_passed")
    total = require_int(status.get("commands_total"), "status.commands_total")
    if status.get("result") != "pass" or passed != total or total == 0:
        raise DocumentationError("profile status is not a complete pass")

    evidence = require_mapping(root.get("evidence"), "evidence")
    signature = require_mapping(evidence.get("manifest_signature"), "evidence.manifest_signature")
    if signature.get("verified") is not True:
        raise DocumentationError("profile manifest signature is not verified")

    metrics = require_mapping(root.get("metrics"), "metrics")
    required_metrics = {
        "artifact_faults",
        "historical_replay",
        "leakage_calibration",
        "packages",
        "platforms",
        "sboms",
        "standards",
        "timing",
    }
    if set(metrics) != required_metrics:
        raise DocumentationError(
            "metric set differs from the reviewed v4 profile: "
            f"missing={sorted(required_metrics - set(metrics))}, "
            f"extra={sorted(set(metrics) - required_metrics)}"
        )

    faults = require_mapping(metrics["artifact_faults"], "metrics.artifact_faults")
    if require_int(faults.get("detected"), "artifact_faults.detected") != require_int(
        faults.get("injected"), "artifact_faults.injected"
    ):
        raise DocumentationError("artifact fault campaign is not a complete detection pass")

    replay = require_mapping(metrics["historical_replay"], "metrics.historical_replay")
    if require_int(replay.get("passed"), "historical_replay.passed") != require_int(
        replay.get("total"), "historical_replay.total"
    ):
        raise DocumentationError("historical replay is not a complete pass")

    packages = require_mapping(metrics["packages"], "metrics.packages")
    if require_int(packages.get("byte_equal"), "packages.byte_equal") != require_int(
        packages.get("total"), "packages.total"
    ):
        raise DocumentationError("package rebuild comparison is not a complete pass")

    timing = require_mapping(metrics["timing"], "metrics.timing")
    if require_int(timing.get("release_blocks"), "timing.release_blocks") != 0:
        raise DocumentationError("timing profile contains a release-blocking family decision")
    blocking_cases = require_int(timing.get("blocking_cases"), "timing.blocking_cases")
    complete_passes = require_int(timing.get("complete_passes"), "timing.complete_passes")
    runs = timing.get("runs")
    if not isinstance(runs, list) or len(runs) != complete_passes:
        raise DocumentationError("timing run count differs from complete_passes")
    reference_names: list[str] | None = None
    for run_index, run_value in enumerate(runs):
        run = require_mapping(run_value, f"timing.runs[{run_index}]")
        cases = run.get("cases")
        if not isinstance(cases, list) or len(cases) != blocking_cases:
            raise DocumentationError("timing run does not contain the complete case family")
        names: list[str] = []
        for case_index, case_value in enumerate(cases):
            case = require_mapping(case_value, f"timing.runs[{run_index}].cases[{case_index}]")
            name = case.get("name")
            if not isinstance(name, str) or not name:
                raise DocumentationError("timing case name must be nonempty")
            if case.get("holm_reject") is not False or case.get("blocks_release") is not False:
                raise DocumentationError("timing profile contains a rejecting case decision")
            names.append(name)
        if reference_names is None:
            reference_names = names
        elif names != reference_names:
            raise DocumentationError("timing case order differs between complete passes")

    calibration = require_mapping(metrics["leakage_calibration"], "metrics.leakage_calibration")
    positive = require_number(
        calibration.get("positive_control_abs_t"), "leakage_calibration.positive_control_abs_t"
    )
    negative = require_number(
        calibration.get("negative_control_abs_t"), "leakage_calibration.negative_control_abs_t"
    )
    threshold = require_number(calibration.get("threshold"), "leakage_calibration.threshold")
    if not positive > threshold or not negative < threshold:
        raise DocumentationError("leakage controls do not bracket the declared threshold")

    standards = require_mapping(metrics["standards"], "metrics.standards")
    total_cases = require_int(standards.get("total_cases"), "standards.total_cases")
    component_cases = require_int(standards.get("ml_dsa_cases"), "standards.ml_dsa_cases") + require_int(
        standards.get("ml_kem_cases"), "standards.ml_kem_cases"
    )
    if component_cases != total_cases:
        raise DocumentationError("standards case totals do not reconcile")

    require_int(require_mapping(metrics["sboms"], "metrics.sboms").get("deterministic"), "sboms.deterministic")
    require_int(
        require_mapping(metrics["platforms"], "metrics.platforms").get("configured_targets"),
        "platforms.configured_targets",
    )
    return root


def evidence_class(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise DocumentationError("metric classification must be a nonempty string")
    return value.replace("-", " ")


def metric_rows(profile: dict[str, Any]) -> list[tuple[str, str, str, str, str]]:
    metrics = profile["metrics"]
    faults = metrics["artifact_faults"]
    calibration = metrics["leakage_calibration"]
    timing = metrics["timing"]
    replay = metrics["historical_replay"]
    standards = metrics["standards"]
    packages = metrics["packages"]
    sboms = metrics["sboms"]
    platforms = metrics["platforms"]
    return [
        (
            "Injected artifact faults",
            f"**{faults['detected']} / {faults['injected']} detected**",
            evidence_class(faults["classification"]),
            "`metrics.artifact_faults`",
            "[fault model](OPEN-SECURITY-LAB.md#fault-simulation)",
        ),
        (
            "Leakage-detector calibration",
            f"**{calibration['samples_per_class']:,} samples/class**; "
            f"positive absolute t {calibration['positive_control_abs_t']:.2f}; "
            f"negative absolute t {calibration['negative_control_abs_t']:.2f}",
            evidence_class(calibration["classification"]),
            "`metrics.leakage_calibration`",
            "[calibration model](OPEN-SECURITY-LAB.md#leakage-calibration)",
        ),
        (
            "Timing-sensitive paths",
            f"**{timing['blocking_cases']} cases × {timing['complete_passes']} complete passes**; "
            f"{timing['release_blocks']} suite-wide Holm rejects",
            evidence_class(timing["classification"]),
            "`metrics.timing`",
            "[statistical policy](METRICS.md#timing-visualization)",
        ),
        (
            "Historical vulnerability classes",
            f"**{replay['passed']} / {replay['total']} replayed**",
            evidence_class(replay["classification"]),
            "`metrics.historical_replay`",
            "[advisory index](../security/README.md)",
        ),
        (
            "Post-quantum vector cases",
            f"**{standards['total_cases']:,} exact cases** "
            f"({standards['ml_dsa_cases']} ML-DSA + {standards['ml_kem_cases']} ML-KEM)",
            evidence_class(standards["classification"]),
            "`metrics.standards`",
            "[terminology](METRICS.md#standards-vector-terminology)",
        ),
        (
            "Publishable packages",
            f"**{packages['byte_equal']} / {packages['total']} byte-equal rebuilds**",
            evidence_class(packages["classification"]),
            "`metrics.packages`",
            "[release-lab evidence](../../assurance/release-lab/README.md)",
        ),
        (
            "Software inventories",
            f"**{sboms['deterministic']} deterministic SBOMs**",
            evidence_class(sboms["classification"]),
            "`metrics.sboms`",
            "[release-lab evidence](../../assurance/release-lab/README.md)",
        ),
        (
            "Configured targets",
            f"**{platforms['configured_targets']} target profiles**",
            evidence_class(platforms["classification"]),
            "`metrics.platforms`",
            "[boundary policy](../../implementation-boundary.toml)",
        ),
    ]


def render_summary(
    profile: dict[str, Any],
    *,
    profile_sha256: str,
    repository_url: str,
    source_ref: str,
) -> str:
    version = profile["release"]["version"]
    commit = profile["release"]["subject"]["commit"]
    release_url = f"{repository_url}/releases/tag/v{version}"
    download_url = f"{repository_url}/releases/download/v{version}"
    rows = metric_rows(profile)
    table = "\n".join(
        f"| {signal} | {result} | {classification} | {field} · {source} |"
        for signal, result, classification, field, source in rows
    )
    return f"""<!-- Generated by tools/generate-assurance-docs.py. Do not edit by hand. -->

# dcrypt {version} Assurance Profile at a glance

> Security claims with an address: one exact release, one inspectable result,
> and a public path from headline metric to evidence.

[Download the visual report]({download_url}/assurance-report.html) ·
[Download the public profile]({download_url}/assurance-profile.json) ·
[View the GitHub release]({release_url}) ·
[Reproduce the laboratory](REPRODUCE.md)

<a href="{download_url}/assurance-report.html">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/v4-assurance-overview-dark.svg">
    <img src="assets/v4-assurance-overview-light.svg" alt="dcrypt {version} Assurance Profile overview — four separate evidence panels">
  </picture>
</a>

| Security signal | Released result | Evidence class | Inspect |
| :--- | :--- | :--- | :--- |
{table}

## Timing-family coverage

<a href="{download_url}/assurance-report.html">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/v4-timing-family-dark.svg">
    <img src="assets/v4-timing-family-light.svg" alt="Per-case primary p-values for both complete timing passes on a log scale">
  </picture>
</a>

Each row is one released timing-sensitive case. The paired dots mark the
primary p-value observed in each complete family pass on a logarithmic scale
against the family-wise Holm policy; neither pass produced a case-level Holm
reject or a release block. The downloadable report preserves case-level means,
thresholds, confidence intervals, and primary p-values.

## Evidence identity

| Field | Value |
| :--- | :--- |
| Release | [`v{version}`]({release_url}) |
| Subject commit | [`{commit}`]({repository_url}/commit/{commit}) |
| Public profile SHA-256 | `{profile_sha256}` |
| Tracked profile snapshot | [`releases/v{version}/assurance-profile.json`](releases/v{version}/assurance-profile.json) |
| Source view | [`{source_ref}`]({repository_url}/tree/{source_ref}) |

The bars and counts above are separate signals, not a composite score. The
profile demonstrates the recorded software executions and calibrated simulation
models. It does not convert software simulation into a physical-device result,
an independent audit, FIPS validation, or formal verification.
"""


THEMES: dict[str, dict[str, str]] = {
    # Light values sit on the GitHub light canvas; dark values on the GitHub
    # dark canvas. Series colors are the validated categorical slots 1 and 2
    # stepped per surface (CVD-checked against both canvases).
    "light": {
        "canvas": "#ffffff",
        "card": "#fcfcfb",
        "border": "#e4e3de",
        "ink": "#0b0b0b",
        "ink2": "#52514e",
        "muted": "#898781",
        "grid": "#e1e0d9",
        "baseline": "#c3c2b7",
        "wash": "#f4f4f1",
        "series1": "#2a78d6",
        "series2": "#eb6834",
        "good": "#006300",
    },
    "dark": {
        "canvas": "#0d1117",
        "card": "#151b23",
        "border": "#2a313c",
        "ink": "#e6edf3",
        "ink2": "#9aa4af",
        "muted": "#7d8590",
        "grid": "#262d37",
        "baseline": "#3d444d",
        "wash": "#151a22",
        "series1": "#3987e5",
        "series2": "#d95926",
        "good": "#0ca30c",
    },
}


def svg_open(
    title: str, description: str, *, width: int, height: int, theme: dict[str, str]
) -> str:
    ink = theme["ink"]
    ink2 = theme["ink2"]
    muted = theme["muted"]
    card = theme["card"]
    border = theme["border"]
    grid = theme["grid"]
    canvas = theme["canvas"]
    return f"""<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-labelledby="title desc" viewBox="0 0 {width} {height}" width="{width}" height="{height}">
  <title id="title">{html.escape(title)}</title>
  <desc id="desc">{html.escape(description)}</desc>
  <style>
    text {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans", Helvetica, Arial, sans-serif; fill: {ink}; }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; }}
    .h1 {{ font-size: 24px; font-weight: 700; }}
    .sub {{ font-size: 13px; fill: {ink2}; }}
    .clabel {{ font-size: 13px; font-weight: 600; fill: {ink2}; }}
    .value {{ font-size: 40px; font-weight: 700; }}
    .vlabel {{ font-size: 13px; fill: {ink2}; }}
    .stat {{ font-size: 13px; fill: {ink2}; }}
    .name {{ font-size: 13px; }}
    .head {{ font-size: 15px; font-weight: 700; }}
    .small {{ font-size: 11px; fill: {muted}; }}
    .note {{ font-size: 12px; fill: {muted}; }}
    .tick {{ font-size: 12px; fill: {muted}; }}
    .thr {{ font-size: 11px; fill: {ink2}; }}
    .card {{ fill: {card}; stroke: {border}; stroke-width: 1; }}
    .grid {{ stroke: {grid}; stroke-width: 1; }}
  </style>
  <rect width="{width}" height="{height}" fill="{canvas}"/>
"""


def log_x(value: float, *, x0: float, x1: float, lo: float, hi: float) -> float:
    clamped = min(max(value, lo), hi)
    frac = (math.log10(clamped) - math.log10(lo)) / (math.log10(hi) - math.log10(lo))
    return round(x0 + frac * (x1 - x0), 2)


def check_mark(x: float, y: float, color: str) -> str:
    return (
        f'  <path d="M{x:.2f} {y:.2f} l4.2 4.2 l7.6 -8.8" fill="none" '
        f'stroke="{color}" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>'
    )


def render_overview_svg(
    profile: dict[str, Any], profile_sha256: str, theme_name: str
) -> str:
    theme = THEMES[theme_name]
    s1 = theme["series1"]
    s2 = theme["series2"]
    ink2 = theme["ink2"]
    good = theme["good"]
    canvas = theme["canvas"]
    baseline = theme["baseline"]
    metrics = profile["metrics"]
    release = profile["release"]
    faults = metrics["artifact_faults"]
    calibration = metrics["leakage_calibration"]
    timing = metrics["timing"]
    replay = metrics["historical_replay"]
    standards = metrics["standards"]
    packages = metrics["packages"]
    sboms = metrics["sboms"]
    platforms = metrics["platforms"]
    version = html.escape(release["version"])
    short_commit = release["subject"]["commit"][:12]
    result = [
        svg_open(
            f"dcrypt {release['version']} Assurance Profile overview",
            "Four separate evidence panels: calibrated simulation with the leakage-detector "
            "calibration on a logarithmic t-statistic scale, measured product evidence, "
            "repository-corpus correctness with the ML-DSA and ML-KEM case split, and "
            "supply-chain and build evidence. No composite score is shown.",
            width=1200,
            height=620,
            theme=theme,
        ),
        f'  <text x="48" y="52" class="h1">Assurance Profile · {version}</text>',
        '  <text x="48" y="78" class="sub">Released evidence for one exact subject — separate signals, no composite score.</text>',
        f'  <text x="1152" y="40" text-anchor="end" class="mono small">commit {short_commit}</text>',
        f'  <text x="1152" y="58" text-anchor="end" class="mono small">profile sha256 {profile_sha256[:12]}</text>',
    ]

    # Card A — calibrated simulation, with the calibration controls on a real
    # log-scale strip (negative control, decision threshold, positive control).
    ax, ay = 48, 104
    strip_x0, strip_x1 = ax + 24.0, ax + 516.0
    t_lo, t_hi = 0.1, 1000.0
    neg_x = log_x(float(calibration["negative_control_abs_t"]), x0=strip_x0, x1=strip_x1, lo=t_lo, hi=t_hi)
    thr_x = log_x(float(calibration["threshold"]), x0=strip_x0, x1=strip_x1, lo=t_lo, hi=t_hi)
    pos_x = log_x(float(calibration["positive_control_abs_t"]), x0=strip_x0, x1=strip_x1, lo=t_lo, hi=t_hi)
    axis_y = ay + 166
    result.extend(
        [
            f'  <rect x="{ax}" y="{ay}" width="540" height="200" rx="6" class="card"/>',
            f'  <text x="{ax + 24}" y="{ay + 34}" class="clabel">Calibrated simulation</text>',
            f'  <text x="{ax + 24}" y="{ay + 88}" class="value">{faults["detected"]} / {faults["injected"]}</text>',
            f'  <text x="{ax + 24}" y="{ay + 112}" class="vlabel">injected single-bit artifact faults detected</text>',
            f'  <text x="{ax + 24}" y="{ay + 136}" class="small">leakage-detector calibration · absolute t, log scale · {calibration["samples_per_class"]:,} samples/class</text>',
            f'  <line x1="{strip_x0}" y1="{axis_y}" x2="{strip_x1}" y2="{axis_y}" stroke="{baseline}" stroke-width="1"/>',
        ]
    )
    for tick in (0.1, 1.0, 10.0, 100.0, 1000.0):
        tick_x = log_x(tick, x0=strip_x0, x1=strip_x1, lo=t_lo, hi=t_hi)
        tick_label = f"{tick:g}"
        result.extend(
            [
                f'  <line x1="{tick_x}" y1="{axis_y}" x2="{tick_x}" y2="{axis_y + 4}" stroke="{baseline}" stroke-width="1"/>',
                f'  <text x="{tick_x}" y="{axis_y + 18}" text-anchor="middle" class="small">{tick_label}</text>',
            ]
        )
    result.extend(
        [
            f'  <line x1="{thr_x}" y1="{axis_y - 10}" x2="{thr_x}" y2="{axis_y + 6}" stroke="{ink2}" stroke-width="1.5"/>',
            f'  <text x="{thr_x}" y="{axis_y - 14}" text-anchor="middle" class="thr">threshold {calibration["threshold"]:g}</text>',
            f'  <circle cx="{neg_x}" cy="{axis_y}" r="5" fill="{s1}" stroke="{canvas}" stroke-width="2"/>',
            f'  <text x="{neg_x}" y="{axis_y - 14}" text-anchor="middle" class="small">negative {calibration["negative_control_abs_t"]:.2f}</text>',
            f'  <circle cx="{pos_x}" cy="{axis_y}" r="5" fill="{s1}" stroke="{canvas}" stroke-width="2"/>',
            f'  <text x="{pos_x}" y="{axis_y - 14}" text-anchor="middle" class="small">positive {calibration["positive_control_abs_t"]:.2f}</text>',
        ]
    )

    # Card B — measured product evidence.
    bx, by = 612, 104
    result.extend(
        [
            f'  <rect x="{bx}" y="{by}" width="540" height="200" rx="6" class="card"/>',
            f'  <text x="{bx + 24}" y="{by + 34}" class="clabel">Measured product evidence</text>',
            f'  <text x="{bx + 24}" y="{by + 88}" class="value">{timing["blocking_cases"]} × {timing["complete_passes"]}</text>',
            f'  <text x="{bx + 24}" y="{by + 112}" class="vlabel">timing-sensitive cases × complete passes</text>',
            check_mark(bx + 24, by + 145, good),
            f'  <text x="{bx + 46}" y="{by + 150}" class="stat">{timing["release_blocks"]} suite-wide Holm rejects across both passes</text>',
            check_mark(bx + 24, by + 173, good),
            f'  <text x="{bx + 46}" y="{by + 178}" class="stat">{replay["passed"]} / {replay["total"]} historical vulnerability classes replayed</text>',
        ]
    )

    # Card C — repository-corpus correctness with the corpus split as a
    # two-segment stacked bar (2px surface gap, rounded data ends).
    cx, cy = 48, 328
    bar_y = cy + 148
    inner = 492.0 - 2.0
    dsa_w = round(inner * standards["ml_dsa_cases"] / standards["total_cases"], 2)
    kem_w = round(inner - dsa_w, 2)
    result.extend(
        [
            f'  <rect x="{cx}" y="{cy}" width="540" height="200" rx="6" class="card"/>',
            f'  <text x="{cx + 24}" y="{cy + 34}" class="clabel">Repository-corpus correctness</text>',
            f'  <text x="{cx + 24}" y="{cy + 88}" class="value">{standards["total_cases"]:,}</text>',
            f'  <text x="{cx + 24}" y="{cy + 112}" class="vlabel">exact post-quantum vector cases</text>',
            f'  <text x="{cx + 24}" y="{cy + 136}" class="small">byte-bound ACVP-format corpus · repository correctness, not NIST validation</text>',
            f'  <clipPath id="corpus-{theme_name}"><rect x="{cx + 24}" y="{bar_y}" width="492" height="12" rx="5"/></clipPath>',
            f'  <g clip-path="url(#corpus-{theme_name})">',
            f'    <rect x="{cx + 24}" y="{bar_y}" width="{dsa_w}" height="12" fill="{s1}"/>',
            f'    <rect x="{cx + 24 + dsa_w + 2}" y="{bar_y}" width="{kem_w}" height="12" fill="{s2}"/>',
            "  </g>",
            f'  <rect x="{cx + 24}" y="{cy + 174}" width="9" height="9" rx="2" fill="{s1}"/>',
            f'  <text x="{cx + 39}" y="{cy + 183}" class="stat">ML-DSA · {standards["ml_dsa_cases"]} cases</text>',
            f'  <rect x="{cx + 224}" y="{cy + 174}" width="9" height="9" rx="2" fill="{s2}"/>',
            f'  <text x="{cx + 239}" y="{cy + 183}" class="stat">ML-KEM · {standards["ml_kem_cases"]} cases</text>',
        ]
    )

    # Card D — supply chain and build surface.
    dx, dy = 612, 328
    result.extend(
        [
            f'  <rect x="{dx}" y="{dy}" width="540" height="200" rx="6" class="card"/>',
            f'  <text x="{dx + 24}" y="{dy + 34}" class="clabel">Supply chain and build surface</text>',
            f'  <text x="{dx + 24}" y="{dy + 88}" class="value">{packages["byte_equal"]} / {packages["total"]}</text>',
            f'  <text x="{dx + 24}" y="{dy + 112}" class="vlabel">byte-equal package rebuilds</text>',
            check_mark(dx + 24, dy + 145, good),
            f'  <text x="{dx + 46}" y="{dy + 150}" class="stat">{sboms["deterministic"]} deterministic software inventories (SBOMs)</text>',
            check_mark(dx + 24, dy + 173, good),
            f'  <text x="{dx + 46}" y="{dy + 178}" class="stat">{platforms["configured_targets"]} configured target profiles</text>',
        ]
    )

    result.extend(
        [
            '  <line x1="48" y1="560" x2="1152" y2="560" class="grid"/>',
            '  <text x="48" y="586" class="note">Separate signals — no composite score · Calibrated simulation is not physical-device evidence · Corpus passes are not NIST validation</text>',
            "</svg>",
            "",
        ]
    )
    return "\n".join(result)


def render_flow_svg(
    profile: dict[str, Any], profile_sha256: str, theme_name: str
) -> str:
    theme = THEMES[theme_name]
    s1 = theme["series1"]
    muted = theme["muted"]
    good = theme["good"]
    release = profile["release"]
    status = profile["status"]
    evidence = profile["evidence"]
    version = html.escape(release["version"])
    short_commit = release["subject"]["commit"][:12]
    signature = evidence["manifest_signature"]
    steps = [
        (
            "01",
            f"dcrypt {version}",
            f'<tspan class="mono">commit {short_commit}</tspan>',
            "clean tree · exact closure",
        ),
        (
            "02",
            f'{status["commands_passed"]} / {status["commands_total"]} lab commands',
            "replay · timing · rebuild",
            "SBOM · targets · simulation",
        ),
        (
            "03",
            f'{html.escape(signature["algorithm"])} verified',
            "canonical manifest",
            "hash-bound evidence set",
        ),
        (
            "04",
            "Profile + report",
            "public release artifacts",
            f'<tspan class="mono">sha256 {profile_sha256[:12]}</tspan>',
        ),
    ]
    result = [
        svg_open(
            f"dcrypt {release['version']} evidence path",
            "The exact release subject enters the open laboratory, produces a verified "
            "manifest, and is projected into public profile and report artifacts. "
            "Physical-device resistance, independent audit, FIPS validation, and formal "
            "proof remain outside the demonstrated path.",
            width=1200,
            height=392,
            theme=theme,
        ),
        '  <text x="48" y="52" class="h1">From release subject to public evidence</text>',
        '  <text x="48" y="78" class="sub">One reproducible path binds the security claim to the artifact set a user installs.</text>',
    ]
    card_w, card_h, gap, top = 243, 150, 44, 104
    for index, (num, head, line1, line2) in enumerate(steps):
        x = 48 + index * (card_w + gap)
        result.extend(
            [
                f'  <rect x="{x}" y="{top}" width="{card_w}" height="{card_h}" rx="6" class="card"/>',
                f'  <text x="{x + 20}" y="{top + 32}" class="mono" font-size="12" font-weight="700" fill="{s1}">{num}</text>',
                f'  <text x="{x + 20}" y="{top + 62}" class="head">{head}</text>',
                f'  <text x="{x + 20}" y="{top + 92}" class="note">{line1}</text>',
                f'  <text x="{x + 20}" y="{top + 114}" class="note">{line2}</text>',
            ]
        )
        if index < len(steps) - 1:
            ar_x0 = x + card_w + 7
            ar_x1 = x + card_w + gap - 7
            ar_y = top + card_h / 2
            result.extend(
                [
                    f'  <line x1="{ar_x0}" y1="{ar_y}" x2="{ar_x1 - 2}" y2="{ar_y}" stroke="{muted}" stroke-width="1.5"/>',
                    f'  <path d="M{ar_x1 - 7} {ar_y - 5} L{ar_x1} {ar_y} L{ar_x1 - 7} {ar_y + 5}" fill="none" stroke="{muted}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
                ]
            )
    result.extend(
        [
            '  <line x1="48" y1="292" x2="1152" y2="292" class="grid"/>',
            check_mark(48, 322, good),
            '  <text x="72" y="327" font-size="12" font-weight="700">Demonstrated</text>',
            '  <text x="184" y="327" class="note">portable software execution · calibrated models · exact artifact identity</text>',
            f'  <line x1="49" y1="351" x2="60" y2="351" stroke="{muted}" stroke-width="2.4" stroke-linecap="round"/>',
            '  <text x="72" y="355" font-size="12" font-weight="700">Not inferred</text>',
            '  <text x="184" y="355" class="note">physical-device resistance · administrative independence · FIPS validation · formal proof</text>',
            "</svg>",
            "",
        ]
    )
    return "\n".join(result)


def render_timing_svg(profile: dict[str, Any], theme_name: str) -> str:
    theme = THEMES[theme_name]
    s1 = theme["series1"]
    s2 = theme["series2"]
    ink2 = theme["ink2"]
    canvas = theme["canvas"]
    baseline = theme["baseline"]
    wash = theme["wash"]
    release = profile["release"]
    timing = profile["metrics"]["timing"]
    runs = timing["runs"]
    run_a, run_b = runs[0], runs[1]
    label_a = html.escape(run_a["label"])
    label_b = html.escape(run_b["label"])
    alpha = run_a["alpha"]
    x0, x1 = 380.0, 1152.0
    p_lo, p_hi = 0.001, 1.0
    plot_top, row_h = 118, 26
    plot_bottom = plot_top + row_h * len(run_a["cases"])
    alpha_x = log_x(float(alpha), x0=x0, x1=x1, lo=p_lo, hi=p_hi)
    result = [
        svg_open(
            f"dcrypt {release['version']} timing-family evidence",
            f"Per-case primary p-values from the {run_a['label']} and {run_b['label']} "
            "timing families on a logarithmic scale. Every case in both complete passes "
            "recorded no Holm reject and no release block under the family-wise policy.",
            width=1200,
            height=1000,
            theme=theme,
        ),
        f'  <text x="48" y="46" class="h1">Timing-family evidence · {timing["blocking_cases"]} cases × {timing["complete_passes"]} complete passes</text>',
        f'  <text x="48" y="72" class="sub">Primary p-value per released case · family-wise Holm step-down at α = {alpha:g} · {timing["release_blocks"]} suite-wide rejects</text>',
        f'  <circle cx="54" cy="93" r="5" fill="{s1}" stroke="{canvas}" stroke-width="2"/>',
        f'  <text x="66" y="97" class="stat">{label_a}</text>',
        f'  <circle cx="160" cy="93" r="5" fill="{s2}" stroke="{canvas}" stroke-width="2"/>',
        f'  <text x="172" y="97" class="stat">{label_b}</text>',
        '  <text x="1152" y="97" text-anchor="end" class="small">smaller p → stronger evidence of a timing difference</text>',
    ]
    for index in range(len(run_a["cases"])):
        if index % 2 == 1:
            result.append(
                f'  <rect x="40" y="{plot_top + index * row_h}" width="1120" height="{row_h}" fill="{wash}"/>'
            )
    for decade in (0.001, 0.1, 1.0):
        grid_x = log_x(decade, x0=x0, x1=x1, lo=p_lo, hi=p_hi)
        result.append(
            f'  <line x1="{grid_x}" y1="{plot_top - 2}" x2="{grid_x}" y2="{plot_bottom + 6}" class="grid"/>'
        )
    result.extend(
        [
            f'  <line x1="{alpha_x}" y1="{plot_top - 2}" x2="{alpha_x}" y2="{plot_bottom + 6}" stroke="{ink2}" stroke-width="1.25"/>',
            f'  <text x="{alpha_x}" y="{plot_top - 10}" text-anchor="middle" class="thr">family α = {alpha:g} (Holm step-down)</text>',
        ]
    )
    for index, (case_a, case_b) in enumerate(zip(run_a["cases"], run_b["cases"])):
        row_mid = plot_top + index * row_h + row_h / 2
        xa = log_x(float(case_a["primary_p_value"]), x0=x0, x1=x1, lo=p_lo, hi=p_hi)
        xb = log_x(float(case_b["primary_p_value"]), x0=x0, x1=x1, lo=p_lo, hi=p_hi)
        result.extend(
            [
                f'  <text x="48" y="{row_mid + 4.5}" class="name">{html.escape(case_a["name"])}</text>',
                f'  <line x1="{xa}" y1="{row_mid}" x2="{xb}" y2="{row_mid}" stroke="{baseline}" stroke-width="2"/>',
                f'  <circle cx="{xa}" cy="{row_mid}" r="5" fill="{s1}" stroke="{canvas}" stroke-width="2"/>',
                f'  <circle cx="{xb}" cy="{row_mid}" r="5" fill="{s2}" stroke="{canvas}" stroke-width="2"/>',
            ]
        )
    for decade, decade_label in ((0.001, "0.001"), (0.01, "0.01"), (0.1, "0.1"), (1.0, "1")):
        tick_x = log_x(decade, x0=x0, x1=x1, lo=p_lo, hi=p_hi)
        result.append(
            f'  <text x="{tick_x}" y="{plot_bottom + 26}" text-anchor="middle" class="tick">{decade_label}</text>'
        )
    result.extend(
        [
            f'  <text x="{(x0 + x1) / 2}" y="{plot_bottom + 48}" text-anchor="middle" class="small">primary p-value (log scale)</text>',
            f'  <line x1="48" y1="{plot_bottom + 68}" x2="1152" y2="{plot_bottom + 68}" class="grid"/>',
            f'  <text x="48" y="{plot_bottom + 92}" class="note">No case-level Holm rejects and no release blocks in either pass · passing is scoped statistical evidence, not a universal constant-time proof</text>',
            f'  <text x="48" y="{plot_bottom + 112}" class="note">case-level means, confidence intervals, practical thresholds, and p-values ship in the public profile and downloadable report</text>',
            "</svg>",
            "",
        ]
    )
    return "\n".join(result)


def compare_or_write(path: Path, content: bytes, *, check: bool) -> None:
    if check:
        try:
            actual = path.read_bytes()
        except OSError as error:
            raise DocumentationError(f"generated documentation is missing: {path}") from error
        if actual != content:
            raise DocumentationError(f"generated documentation is stale: {path}")
        return

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--assets-dir", type=Path, required=True)
    parser.add_argument("--snapshot-output", type=Path)
    parser.add_argument(
        "--repository-url",
        default="https://github.com/ioi-foundation/dcrypt",
    )
    parser.add_argument("--source-ref")
    parser.add_argument("--check", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        profile_bytes = args.profile.read_bytes()
        profile = validate_profile(json.loads(profile_bytes))
        version = profile["release"]["version"]
        source_ref = args.source_ref or f"v{version}"
        profile_sha256 = sha256_bytes(profile_bytes)
        summary = render_summary(
            profile,
            profile_sha256=profile_sha256,
            repository_url=args.repository_url.rstrip("/"),
            source_ref=source_ref,
        ).encode("utf-8")
        compare_or_write(args.summary, summary, check=args.check)
        for theme_name in sorted(THEMES):
            assets = {
                f"v4-assurance-overview-{theme_name}.svg": render_overview_svg(
                    profile, profile_sha256, theme_name
                ),
                f"v4-evidence-flow-{theme_name}.svg": render_flow_svg(
                    profile, profile_sha256, theme_name
                ),
                f"v4-timing-family-{theme_name}.svg": render_timing_svg(
                    profile, theme_name
                ),
            }
            for asset_name, content in assets.items():
                compare_or_write(
                    args.assets_dir / asset_name,
                    content.encode("utf-8"),
                    check=args.check,
                )
        if args.snapshot_output is not None:
            compare_or_write(args.snapshot_output, profile_bytes, check=args.check)
    except (OSError, UnicodeError, json.JSONDecodeError, DocumentationError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    action = "verified" if args.check else "generated"
    print(
        f"{action} Assurance Profile documentation for v{version} "
        f"(profile sha256 {profile_sha256})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
