"""Shared matplotlib style for paper figures."""

import matplotlib

RCPARAMS = {
    "font.size": 9,
    "font.family": "serif",
    "figure.figsize": (3.33, 2.2),  # single-column width
    "axes.linewidth": 0.8,
    "lines.linewidth": 1.5,
    "pdf.fonttype": 42,  # TrueType (required by conferences)
    "ps.fonttype": 42,
    "axes.grid": True,
    "grid.alpha": 0.3,
    "grid.linewidth": 0.5,
}


def apply():
    matplotlib.rcParams.update(RCPARAMS)
