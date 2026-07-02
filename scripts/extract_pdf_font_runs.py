#!/usr/bin/env python3
"""Extract PDF text while preserving code/prose font intent.

The bundled WireGuard paper uses Latin Modern Roman for prose and
LMMonoPropLt for technical tokens (commands, keys, addresses, paths). Generic
PDF text extraction flattens those font runs and often drops spaces around
mixed-font fragments. This helper converts monospaced runs to Markdown code
spans while keeping Roman text as prose.

Usage:
  python3 scripts/extract_pdf_font_runs.py wireguard.pdf > /tmp/wireguard.md

Requires:
  python3 -m pip install pdfminer.six
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

try:
    from pdfminer.high_level import extract_pages
    from pdfminer.layout import LTChar, LTTextContainer, LTTextLine
except ModuleNotFoundError as exc:  # pragma: no cover - operator guidance
    raise SystemExit(
        "missing dependency: install with `python3 -m pip install pdfminer.six`"
    ) from exc


LIGATURES = str.maketrans({
    "ﬀ": "ff",
    "ﬁ": "fi",
    "ﬂ": "fl",
    "ﬃ": "ffi",
    "ﬄ": "ffl",
    "ﬅ": "st",
    "ﬆ": "st",
})


@dataclass
class CharRun:
    text: str
    family: str
    x0: float
    x1: float


def font_family(fontname: str) -> str:
    name = fontname.split("+", 1)[-1]
    if "LMMono" in name or "Mono" in name:
        return "mono"
    if "Bold" in name:
        return "bold"
    if "Italic" in name or "Oblique" in name:
        return "italic"
    return "roman"


def iter_line_chars(line: LTTextLine) -> list[LTChar]:
    chars = [item for item in line if isinstance(item, LTChar)]
    chars.sort(key=lambda char: char.x0)
    return chars


def char_gap(prev: LTChar, current: LTChar) -> float:
    return max(0.0, current.x0 - prev.x1)


def should_insert_space(prev: LTChar, current: LTChar) -> bool:
    gap = char_gap(prev, current)
    if gap <= 0.8:
        return False
    # A half-em-ish gap is usually an actual word boundary in this paper.
    threshold = max(1.5, min(prev.size, current.size) * 0.22)
    return gap >= threshold


def line_runs(line: LTTextLine) -> list[CharRun]:
    chars = iter_line_chars(line)
    if not chars:
        return []

    runs: list[CharRun] = []
    buf = [chars[0].get_text()]
    family = font_family(chars[0].fontname)
    x0 = chars[0].x0
    x1 = chars[0].x1
    prev = chars[0]

    for current in chars[1:]:
        current_family = font_family(current.fontname)
        if should_insert_space(prev, current):
            # A spacing boundary belongs to the text flow, not to either font.
            if family == current_family:
                buf.append(" ")
            else:
                runs.append(CharRun("".join(buf), family, x0, x1))
                runs.append(CharRun(" ", "space", prev.x1, current.x0))
                buf = []
                x0 = current.x0
                family = current_family
        if current_family != family and buf:
            runs.append(CharRun("".join(buf), family, x0, x1))
            buf = []
            x0 = current.x0
            family = current_family
        buf.append(current.get_text())
        x1 = current.x1
        prev = current

    if buf:
        runs.append(CharRun("".join(buf), family, x0, x1))
    return merge_adjacent_runs(runs)


def merge_adjacent_runs(runs: list[CharRun]) -> list[CharRun]:
    merged: list[CharRun] = []
    for run in runs:
        if not run.text:
            continue
        if merged and merged[-1].family == run.family:
            merged[-1].text += run.text
            merged[-1].x1 = run.x1
        else:
            merged.append(run)
    return merged


def markdown_escape_code(text: str) -> str:
    text = text.translate(LIGATURES).replace("\n", " ").strip()
    if "`" not in text:
        return f"`{text}`"
    return "`` " + text.replace("``", "` `") + " ``"


def render_runs(runs: list[CharRun]) -> str:
    out: list[str] = []
    for i, run in enumerate(runs):
        text = run.text
        text = text.translate(LIGATURES)
        if run.family == "space":
            out.append(" ")
            continue
        if run.family == "mono":
            stripped = text.strip()
            if not stripped:
                out.append(text)
                continue
            prefix = " " if text[:1].isspace() else ""
            suffix = " " if text[-1:].isspace() else ""
            if out and out[-1] and not out[-1].endswith((" ", "\t", "\n", "(", "[", "{", "/", "-")):
                prev = out[-1][-1]
                if stripped[:1] and stripped[0].isalnum() and prev.isalnum():
                    prefix = " "
            code = markdown_escape_code(stripped)
            if i + 1 < len(runs):
                nxt = runs[i + 1].text[:1]
                if nxt and nxt.isalnum() and stripped[-1:].isalnum():
                    suffix = " "
            out.append(prefix + code + suffix)
        else:
            out.append(text)
    line = "".join(out)
    line = re.sub(r"[ \t]+", " ", line)
    line = re.sub(r" +([,.;:!?])", r"\1", line)
    return line.strip()


def extract_markdown(pdf_path: Path, max_pages: int | None = None) -> str:
    paragraphs: list[str] = []
    current: list[str] = []

    for page_number, page in enumerate(extract_pages(str(pdf_path)), start=1):
        if max_pages is not None and page_number > max_pages:
            break
        page_lines: list[str] = []
        for element in page:
            if not isinstance(element, LTTextContainer):
                continue
            for line in element:
                if not isinstance(line, LTTextLine):
                    continue
                rendered = render_runs(line_runs(line))
                if rendered:
                    page_lines.append(rendered)

        for line in page_lines:
            if not line:
                if current:
                    paragraphs.append(" ".join(current))
                    current = []
                continue
            if current and not current[-1].endswith("-") and line[:1].islower():
                current.append(line)
            else:
                if current:
                    paragraphs.append(" ".join(current))
                current = [line]
        if current:
            paragraphs.append(" ".join(current))
            current = []
        paragraphs.append(f"\n<!-- page {page_number} -->\n")

    return "\n\n".join(p for p in paragraphs if p.strip())


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("pdf", type=Path)
    parser.add_argument("--max-pages", type=int, default=None)
    args = parser.parse_args(argv)

    sys.stdout.write(extract_markdown(args.pdf, args.max_pages))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
