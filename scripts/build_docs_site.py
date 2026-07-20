#!/usr/bin/env python3
"""Build a tiny static HTML site from docs/*.md for GitHub Pages."""

from __future__ import annotations

import html
import re
from pathlib import Path

try:
    import markdown
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "Install markdown: python -m pip install markdown"
    ) from exc

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
OUT = ROOT / "_site"

CSS = """
:root { color-scheme: light; --fg:#1a1a1a; --muted:#555; --bg:#f7f7f5; --card:#fff; --link:#0b5fff; }
* { box-sizing: border-box; }
body { margin:0; font:16px/1.55 system-ui,Segoe UI,sans-serif; color:var(--fg); background:var(--bg); }
header,main,footer { max-width:720px; margin:0 auto; padding:1.25rem 1rem; }
header { padding-bottom:0; }
header h1 { margin:0 0 .25rem; font-size:1.5rem; }
header p { margin:0; color:var(--muted); }
nav { margin:1rem 0 0; display:flex; flex-wrap:wrap; gap:.5rem .75rem; }
nav a { color:var(--link); text-decoration:none; }
nav a:hover { text-decoration:underline; }
article { background:var(--card); border:1px solid #e5e5e0; border-radius:8px; padding:1.25rem 1.4rem; }
article h1,article h2,article h3 { line-height:1.25; }
article pre,article code { font-family:ui-monospace,Consolas,monospace; font-size:.9em; }
article pre { overflow:auto; padding:.85rem 1rem; background:#f0f0ec; border-radius:6px; }
article a { color:var(--link); }
footer { color:var(--muted); font-size:.9rem; }
"""

LAYOUT = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · Wireshark MCP</title>
<style>{css}</style>
</head>
<body>
<header>
  <h1>Wireshark MCP</h1>
  <p>Novice setup wiki — works with any stdio MCP host</p>
  <nav>{nav}</nav>
</header>
<main><article>{body}</article></main>
<footer>
  <p>Source: <a href="https://github.com/A-G-U-P-T-A/wireshark-mcp">A-G-U-P-T-A/wireshark-mcp</a></p>
</footer>
</body>
</html>
"""


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def md_to_html(text: str) -> str:
    return markdown.markdown(
        text,
        extensions=["fenced_code", "tables", "toc"],
    )


def main() -> None:
    if not DOCS.is_dir():
        raise SystemExit(f"Missing docs dir: {DOCS}")

    OUT.mkdir(parents=True, exist_ok=True)
    pages = sorted(DOCS.glob("*.md"))
    if not pages:
        raise SystemExit("No markdown files in docs/")

    # Prefer README.md as home
    ordered = sorted(
        pages,
        key=lambda p: (0 if p.name.upper() == "README.MD" else 1, p.name.lower()),
    )

    nav_items = []
    for path in ordered:
        title = "Home" if path.name.upper() == "README.MD" else path.stem
        href = "index.html" if path.name.upper() == "README.MD" else f"{slug(path.stem)}.html"
        nav_items.append(f'<a href="{href}">{html.escape(title)}</a>')
    nav = " · ".join(nav_items)

    for path in ordered:
        title = "Home" if path.name.upper() == "README.MD" else path.stem
        out_name = "index.html" if path.name.upper() == "README.MD" else f"{slug(path.stem)}.html"
        body = md_to_html(path.read_text(encoding="utf-8"))
        # Rewrite .md links to .html
        body = re.sub(
            r'href="([^"]+)\.md"',
            lambda m: f'href="{slug(Path(m.group(1)).stem)}.html"'
            if Path(m.group(1)).stem.upper() != "README"
            else 'href="index.html"',
            body,
        )
        html_page = LAYOUT.format(title=html.escape(title), css=CSS, nav=nav, body=body)
        (OUT / out_name).write_text(html_page, encoding="utf-8")
        print(f"wrote {OUT / out_name}")

    print(f"Built {len(ordered)} pages → {OUT}")


if __name__ == "__main__":
    main()
