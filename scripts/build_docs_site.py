#!/usr/bin/env python3
"""Build a useful static docs site from docs/*.md for GitHub Pages."""

from __future__ import annotations

import html
import re
from pathlib import Path

try:
    import markdown
except ImportError as exc:  # pragma: no cover
    raise SystemExit("Install markdown: python -m pip install markdown") from exc

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
OUT = ROOT / "_site"

# Display order and labels (README → home)
NAV = [
    ("README.md", "Start here", "index.html"),
    ("Setup.md", "Setup", "setup.html"),
    ("Clients.md", "Clients", "clients.html"),
    ("Troubleshooting.md", "Fix problems", "troubleshooting.html"),
    ("Security.md", "Security", "security.html"),
]

CSS = r"""
@import url("https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Sora:wght@400;500;600;700&display=swap");

:root {
  --ink: #e8eef7;
  --muted: #93a4bd;
  --dim: #6b7c95;
  --bg0: #071018;
  --bg1: #0c1a28;
  --panel: rgba(12, 28, 42, 0.82);
  --line: rgba(125, 211, 252, 0.16);
  --teal: #2dd4bf;
  --teal-dim: #14b8a6;
  --amber: #fbbf24;
  --code-bg: #050b12;
  --radius: 12px;
  --font: "Sora", ui-sans-serif, system-ui, sans-serif;
  --mono: "IBM Plex Mono", ui-monospace, Consolas, monospace;
}

* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  min-height: 100vh;
  color: var(--ink);
  font: 16px/1.6 var(--font);
  background:
    radial-gradient(900px 480px at 12% -10%, rgba(45, 212, 191, 0.18), transparent 55%),
    radial-gradient(700px 420px at 90% 0%, rgba(56, 189, 248, 0.12), transparent 50%),
    linear-gradient(180deg, var(--bg1), var(--bg0));
}

body::before {
  content: "";
  position: fixed;
  inset: 0;
  pointer-events: none;
  opacity: 0.35;
  background-image:
    linear-gradient(rgba(148, 163, 184, 0.06) 1px, transparent 1px),
    linear-gradient(90deg, rgba(148, 163, 184, 0.06) 1px, transparent 1px);
  background-size: 28px 28px;
  mask-image: radial-gradient(ellipse at 50% 20%, #000 20%, transparent 75%);
}

.shell {
  position: relative;
  z-index: 1;
  display: grid;
  grid-template-columns: 240px minmax(0, 1fr);
  gap: 0;
  max-width: 1100px;
  margin: 0 auto;
  min-height: 100vh;
}

.sidebar {
  position: sticky;
  top: 0;
  align-self: start;
  height: 100vh;
  padding: 1.75rem 1.1rem 1.5rem 1.25rem;
  border-right: 1px solid var(--line);
  background: rgba(7, 16, 24, 0.55);
  backdrop-filter: blur(10px);
}

.brand {
  display: block;
  text-decoration: none;
  color: inherit;
  margin-bottom: 1.5rem;
}
.brand-mark {
  font-size: 0.72rem;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--teal);
  font-weight: 600;
}
.brand-name {
  display: block;
  margin-top: 0.35rem;
  font-size: 1.35rem;
  font-weight: 700;
  letter-spacing: -0.03em;
  line-height: 1.15;
}
.brand-tag {
  display: block;
  margin-top: 0.4rem;
  color: var(--muted);
  font-size: 0.86rem;
  line-height: 1.35;
}

.nav {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}
.nav a {
  display: block;
  padding: 0.55rem 0.7rem;
  border-radius: 8px;
  color: var(--muted);
  text-decoration: none;
  font-weight: 500;
  font-size: 0.95rem;
  border: 1px solid transparent;
  transition: color .15s, background .15s, border-color .15s;
}
.nav a:hover { color: var(--ink); background: rgba(45, 212, 191, 0.08); }
.nav a.active {
  color: var(--ink);
  background: rgba(45, 212, 191, 0.12);
  border-color: rgba(45, 212, 191, 0.28);
}

.sidebar-foot {
  margin-top: 2rem;
  padding-top: 1rem;
  border-top: 1px solid var(--line);
  font-size: 0.8rem;
  color: var(--dim);
}
.sidebar-foot a { color: var(--teal); text-decoration: none; }
.sidebar-foot a:hover { text-decoration: underline; }

.content {
  padding: 2rem 2.25rem 3.5rem;
}

.hero {
  margin-bottom: 1.75rem;
  animation: rise .45s ease-out both;
}
.hero h1 {
  margin: 0 0 0.55rem;
  font-size: clamp(1.85rem, 3.5vw, 2.45rem);
  letter-spacing: -0.04em;
  line-height: 1.15;
  font-weight: 700;
}
.hero .lede {
  margin: 0;
  max-width: 40rem;
  color: var(--muted);
  font-size: 1.05rem;
}

article {
  animation: rise .55s ease-out both;
}
article > :first-child { margin-top: 0; }
article h1 {
  font-size: clamp(1.7rem, 3vw, 2.2rem);
  letter-spacing: -0.035em;
  margin: 0 0 0.85rem;
  line-height: 1.2;
}
article h2 {
  margin: 2rem 0 0.7rem;
  font-size: 1.2rem;
  letter-spacing: -0.02em;
  color: var(--ink);
  padding-bottom: 0.35rem;
  border-bottom: 1px solid var(--line);
}
article h3 {
  margin: 1.35rem 0 0.45rem;
  font-size: 1.02rem;
  color: #dbe7f5;
}
article p, article li { color: #c5d2e4; }
article a { color: var(--teal); }
article a:hover { color: #5eead4; }
article strong { color: #f1f6ff; font-weight: 600; }
article ul, article ol { padding-left: 1.2rem; }
article li + li { margin-top: 0.3rem; }

article table {
  width: 100%;
  border-collapse: collapse;
  margin: 1rem 0 1.4rem;
  font-size: 0.92rem;
  overflow: hidden;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--panel);
}
article th, article td {
  text-align: left;
  padding: 0.7rem 0.85rem;
  border-bottom: 1px solid var(--line);
  vertical-align: top;
}
article th {
  color: var(--teal);
  font-weight: 600;
  background: rgba(45, 212, 191, 0.06);
}
article tr:last-child td { border-bottom: 0; }

.codewrap {
  position: relative;
  margin: 1rem 0 1.35rem;
}
article pre {
  margin: 0;
  padding: 1rem 1.1rem;
  overflow: auto;
  background: var(--code-bg);
  border: 1px solid var(--line);
  border-radius: var(--radius);
  box-shadow: inset 0 1px 0 rgba(255,255,255,0.03);
}
article pre code,
article code {
  font-family: var(--mono);
  font-size: 0.84em;
}
article :not(pre) > code {
  background: rgba(45, 212, 191, 0.1);
  border: 1px solid rgba(45, 212, 191, 0.18);
  padding: 0.1em 0.35em;
  border-radius: 5px;
  color: #99f6e4;
}
.copybtn {
  position: absolute;
  top: 0.55rem;
  right: 0.55rem;
  border: 1px solid var(--line);
  background: rgba(12, 28, 42, 0.9);
  color: var(--muted);
  font: 500 0.72rem/1 var(--font);
  letter-spacing: 0.04em;
  text-transform: uppercase;
  padding: 0.4rem 0.55rem;
  border-radius: 6px;
  cursor: pointer;
}
.copybtn:hover { color: var(--ink); border-color: rgba(45, 212, 191, 0.4); }
.copybtn.ok { color: var(--teal); }

.page-foot {
  margin-top: 2.5rem;
  padding-top: 1rem;
  border-top: 1px solid var(--line);
  color: var(--dim);
  font-size: 0.85rem;
}
.page-foot a { color: var(--teal); }

@keyframes rise {
  from { opacity: 0; transform: translateY(8px); }
  to { opacity: 1; transform: none; }
}

@media (max-width: 860px) {
  .shell { grid-template-columns: 1fr; }
  .sidebar {
    position: relative;
    height: auto;
    border-right: 0;
    border-bottom: 1px solid var(--line);
    padding-bottom: 1rem;
  }
  .nav { flex-direction: row; flex-wrap: wrap; gap: 0.35rem; }
  .nav a { padding: 0.45rem 0.65rem; font-size: 0.88rem; }
  .content { padding: 1.35rem 1.1rem 2.5rem; }
  .sidebar-foot { display: none; }
}
"""

JS = r"""
document.querySelectorAll("article pre").forEach((pre) => {
  const wrap = document.createElement("div");
  wrap.className = "codewrap";
  pre.parentNode.insertBefore(wrap, pre);
  wrap.appendChild(pre);
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "copybtn";
  btn.textContent = "Copy";
  btn.addEventListener("click", async () => {
    const text = pre.innerText;
    try {
      await navigator.clipboard.writeText(text);
      btn.textContent = "Copied";
      btn.classList.add("ok");
      setTimeout(() => { btn.textContent = "Copy"; btn.classList.remove("ok"); }, 1400);
    } catch (_) {
      btn.textContent = "Failed";
    }
  });
  wrap.appendChild(btn);
});
"""

LAYOUT = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="Set up Wireshark MCP for Cursor, Claude, VS Code, and any stdio MCP host.">
<title>{title} · Wireshark MCP</title>
<style>{css}</style>
</head>
<body>
<div class="shell">
  <aside class="sidebar">
    <a class="brand" href="index.html">
      <span class="brand-mark">Packet tools for agents</span>
      <span class="brand-name">Wireshark MCP</span>
      <span class="brand-tag">TShark capture &amp; analysis over MCP</span>
    </a>
    <nav class="nav">{nav}</nav>
    <div class="sidebar-foot">
      <a href="https://github.com/A-G-U-P-T-A/wireshark-mcp">GitHub</a>
      ·
      <a href="https://github.com/A-G-U-P-T-A/wireshark-mcp/releases/tag/v0.2.2">v0.2.2</a>
    </div>
  </aside>
  <div class="content">
    <article>{body}</article>
    <footer class="page-foot">
      Works with any stdio MCP host.
      Source on
      <a href="https://github.com/A-G-U-P-T-A/wireshark-mcp">GitHub</a>.
    </footer>
  </div>
</div>
<script>{js}</script>
</body>
</html>
"""


def slug_heading(text: str) -> str:
    text = text.strip().lower()
    text = re.sub(r"[^\w\s-]", "", text)
    return re.sub(r"[-\s]+", "-", text).strip("-")


def md_to_html(text: str) -> str:
    md = markdown.Markdown(
        extensions=["fenced_code", "tables", "toc", "attr_list"],
        extension_configs={"toc": {"permalink": False}},
    )
    body = md.convert(text)
    # Add ids to h2/h3 for in-page anchors from home table links
    def add_id(match: re.Match[str]) -> str:
        level, inner = match.group(1), match.group(2)
        plain = re.sub(r"<[^>]+>", "", inner)
        return f'<h{level} id="{slug_heading(plain)}">{inner}</h{level}>'

    return re.sub(r"<h([23])>(.*?)</h\1>", add_id, body, flags=re.S)


def rewrite_md_links(body: str) -> str:
    def repl(match: re.Match[str]) -> str:
        target = match.group(1)
        # Keep external / anchors
        if "://" in target or target.startswith("#"):
            return match.group(0)
        name = Path(target).name
        stem = Path(name).stem
        if stem.upper() == "README":
            return 'href="index.html"'
        # map known pages
        for src, _label, href in NAV:
            if Path(src).stem.lower() == stem.lower():
                return f'href="{href}"'
        return f'href="{stem.lower()}.html"'

    return re.sub(r'href="([^"]+)\.md"', repl, body)


def main() -> None:
    if not DOCS.is_dir():
        raise SystemExit(f"Missing docs dir: {DOCS}")

    OUT.mkdir(parents=True, exist_ok=True)
    by_name = {p.name: p for p in DOCS.glob("*.md")}

    for src, _label, _href in NAV:
        if src not in by_name:
            raise SystemExit(f"Missing docs page: {src}")

    for src, label, out_name in NAV:
        path = by_name[src]
        is_home = out_name == "index.html"
        body = md_to_html(path.read_text(encoding="utf-8"))
        body = rewrite_md_links(body)
        # Drop duplicate H1 from markdown on non-home? keep all — style handles it

        nav_html = []
        for _src, nav_label, href in NAV:
            cls = ' class="active"' if href == out_name else ""
            nav_html.append(f'<a href="{href}"{cls}>{html.escape(nav_label)}</a>')

        page = LAYOUT.format(
            title=html.escape(label),
            css=CSS,
            js=JS,
            nav="\n".join(nav_html),
            body=body,
        )
        (OUT / out_name).write_text(page, encoding="utf-8")
        print(f"wrote {OUT / out_name}")

    # Ignore extra md files not in NAV (already covered)
    print(f"Built {len(NAV)} pages → {OUT}")


if __name__ == "__main__":
    main()
