"""Plot the wire size of one BUS message per serialization.

Run from the repository root: python docs/img/plot_encoding_sizes.py
It reads docs/img/encoding-sizes-results.json.
"""
import json
import sys

sys.path.insert(0, "docs/img")
from plot_style import save  # noqa: E402

with open("docs/img/encoding-sizes-results.json", encoding="utf-8") as handle:
    sizes = json.load(handle)["bytes"]
data = dict(sorted(sizes.items(), key=lambda item: item[1], reverse=True))


def draw(fig, theme, data):
    ax = fig.subplots()
    names, values = list(data), list(data.values())
    bars = ax.barh(names, values, color=theme["series"][0])
    ax.bar_label(bars, padding=3, color=theme["text"])
    ax.set_xlabel("bytes on the wire for one BUS message")
    ax.grid(axis="y", visible=False)
    ax.set_xlim(0, max(values) * 1.12)


save("docs/img/encoding-sizes", draw, data, height=3.8)
