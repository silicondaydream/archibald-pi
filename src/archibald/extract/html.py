"""Web pages and SVG: every place text can live, and whether a person sees it.

Produces segments for:

* visible text, grouped by block element so "Ignore <b>previous</b> instructions"
  still reads as one sentence;
* hidden text — CSS, the `hidden` attribute, <template>, off-screen tricks, text
  coloured to match its background;
* form fields — placeholders, default values, labels-by-attribute, hidden inputs;
* attributes a model reads and a person usually does not: alt, title, aria-*,
  data-*;
* page metadata — <title>, <meta>, JSON-LD;
* HTML comments, <noscript>, non-JavaScript <script> blocks;
* embedded documents — iframe srcdoc and text/HTML data: URIs, scanned recursively.

The page is parsed, never rendered, and never has its scripts run. Parsing uses
the standard library's html.parser through BeautifulSoup, so there is no native
parser to exploit.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from urllib.parse import unquote

from bs4 import BeautifulSoup, CData, Comment, Doctype, NavigableString, Tag
from bs4.element import Declaration, ProcessingInstruction

from archibald.extract.css import (
    HIDING_CLASSES,
    background_color,
    contrast,
    hiding_reason,
    parse_color,
    parse_declarations,
    stylesheet_rules,
)
from archibald.models import Segment

MAX_HTML_BYTES = 5_000_000
MAX_DEPTH = 2
WHITE = (255, 255, 255)

BLOCKS = {
    "p", "div", "li", "td", "th", "h1", "h2", "h3", "h4", "h5", "h6", "section",
    "article", "main", "header", "footer", "nav", "aside", "blockquote", "pre",
    "figcaption", "dd", "dt", "label", "button", "form", "table", "tr", "ul", "ol",
    "body", "html", "textarea", "option", "summary", "details", "fieldset", "legend",
    "caption", "address", "svg", "text", "foreignobject",
}
# Attributes a model reads and a person usually does not.
ATTRS = ("alt", "title", "aria-label", "aria-description", "aria-roledescription",
         "aria-placeholder", "placeholder", "label", "summary")
SVG_NONRENDERED = {"desc", "title", "metadata"}


@dataclass
class _State:
    hidden: str | None     # reason, inherited
    color: tuple[int, int, int] | None
    background: tuple[int, int, int]
    in_form: str | None    # description of the enclosing form


def describe(tag: Tag) -> str:
    """A short, stable label: tag#id.class, with up to two ancestors."""
    def one(t: Tag) -> str:
        label = t.name
        if t.get("id"):
            label += f"#{t['id']}"
        elif t.get("name") and t.name in ("input", "textarea", "select", "button", "form"):
            label += f"[name={t['name']}]"
        classes = t.get("class") or []
        if classes and not t.get("id"):
            label += "." + ".".join(classes[:2])
        return label

    chain = [one(tag)]
    parent = tag.parent
    while parent is not None and isinstance(parent, Tag) and len(chain) < 3:
        if parent.name in ("[document]", "html", "body"):
            break
        chain.append(one(parent))
        parent = parent.parent
    return " > ".join(reversed(chain))


class _Extractor:
    def __init__(self, soup: BeautifulSoup, prefix: str, depth: int) -> None:
        self.soup = soup
        self.prefix = prefix
        self.depth = depth
        self.segments: list[Segment] = []
        self.notes: list[str] = []
        # (text, block tag, hidden reason, form) in document order, grouped later.
        self._runs: list[tuple[str, Tag, str | None, str | None]] = []
        self._decls: dict[int, dict[str, str]] = {}
        self.forms = 0
        self.fields = 0

    # -- helpers ------------------------------------------------------------

    def _loc(self, text: str) -> str:
        return f"{self.prefix} › {text}" if self.prefix else text

    def _add(self, text: str, source: str, location: str, hidden: str | None = None,
             routine: bool = False) -> None:
        text = text.strip()
        if text:
            self.segments.append(
                Segment(text=text, source=source, location=self._loc(location),
                        hidden=hidden is not None, hidden_reason=hidden, routine=routine)
            )

    def _load_stylesheets(self) -> None:
        for style in self.soup.find_all("style"):
            for selector, decls in stylesheet_rules(style.get_text()):
                try:
                    matched = self.soup.select(selector)
                except Exception:  # noqa: BLE001 — soupsieve rejects plenty of real CSS
                    continue
                for el in matched:
                    self._decls.setdefault(id(el), {}).update(decls)

    def _declarations(self, tag: Tag) -> dict[str, str]:
        d = dict(self._decls.get(id(tag), {}))
        # SVG presentation attributes behave like CSS.
        for attr in ("opacity", "visibility", "display", "font-size", "fill", "fill-opacity"):
            if tag.get(attr):
                d[attr] = str(tag[attr]).lower()
        if tag.get("style"):
            d.update(parse_declarations(str(tag["style"])))
        return d

    def _child_state(self, tag: Tag, state: _State) -> _State:
        d = self._declarations(tag)
        reason = state.hidden
        if reason is None:
            if tag.has_attr("hidden"):
                reason = "hidden attribute"
            elif tag.name == "template":
                reason = "inside <template> (never rendered)"
            elif tag.name in ("input",) and str(tag.get("type", "")).lower() == "hidden":
                reason = "input type=hidden"
            else:
                reason = hiding_reason(d)
                if reason is None:
                    for cls in tag.get("class") or []:
                        if cls.lower() in HIDING_CLASSES:
                            reason = HIDING_CLASSES[cls.lower()]
                            break
        color, _ = parse_color(d.get("color") or d.get("fill"))
        bg = background_color(d)
        form = state.in_form
        if tag.name == "form":
            self.forms += 1
            form = describe(tag)
        return _State(
            hidden=reason,
            color=color or state.color,
            background=bg or state.background,
            in_form=form,
        )

    # -- the walk ------------------------------------------------------------

    def run(self) -> None:
        self._load_stylesheets()
        self._metadata()
        root = self.soup.body or self.soup
        self._walk(root, _State(None, None, WHITE, None), root if isinstance(root, Tag) else None)
        self._flush_runs()
        if self.forms:
            self.notes.append(
                f"{self.forms} form{'s' if self.forms != 1 else ''}, "
                f"{self.fields} field{'s' if self.fields != 1 else ''} scanned"
            )

    def _walk(self, node: Tag | BeautifulSoup, state: _State, block: Tag | None) -> None:
        for child in node.children:
            if isinstance(child, Comment):
                self._add(str(child), "html.comment", f"comment in {describe(node)}"
                          if isinstance(node, Tag) and node.name != "[document]" else "comment",
                          hidden="HTML comment", routine=True)
            elif isinstance(child, (Doctype, Declaration, ProcessingInstruction)):
                continue
            elif isinstance(child, (NavigableString, CData)):
                text = str(child)
                if text.strip() and block is not None:
                    reason = state.hidden or self._colour_reason(state)
                    self._runs.append((text, block, reason, state.in_form))
            elif isinstance(child, Tag):
                self._element(child, state, block)

    def _colour_reason(self, state: _State) -> str | None:
        if state.color is None:
            return None
        if contrast(state.color, state.background) < 1.25:
            c, b = state.color, state.background
            return f"text colour matches background (rgb{c} on rgb{b})"
        return None

    def _element(self, tag: Tag, state: _State, block: Tag | None) -> None:
        name = tag.name.lower()
        if name == "head":
            return  # handled by _metadata
        if name == "style":
            return
        if name == "script":
            self._script(tag)
            return
        child_state = self._child_state(tag, state)

        if name == "noscript" and child_state.hidden is None:
            child_state.hidden = "<noscript> (only shown with JavaScript disabled)"
        if name in SVG_NONRENDERED and tag.find_parent("svg") is not None:
            self._add(tag.get_text(" "), "svg.text", describe(tag),
                      hidden=f"SVG <{name}> (not rendered)", routine=True)
            return

        self._attributes(tag, child_state)
        self._embedded(tag)

        new_block = tag if name in BLOCKS else block
        self._walk(tag, child_state, new_block)

    def _attributes(self, tag: Tag, state: _State) -> None:
        in_form = state.in_form
        is_field = tag.name in ("input", "textarea", "select", "button", "option")
        if is_field and in_form:
            self.fields += 1
        source_prefix = "form" if in_form else "html"
        where = describe(tag)
        if in_form and not where.startswith("form"):
            where = f"{in_form} › {where}"

        for attr in ATTRS:
            value = tag.get(attr)
            if value:
                # A placeholder is on screen; alt text and aria labels are not.
                visible_attr = attr in ("placeholder", "label") and state.hidden is None
                self._add(
                    str(value), f"{source_prefix}.{attr}", f"{where} @{attr}",
                    hidden=state.hidden if visible_attr else (state.hidden or f"{attr} attribute"),
                    routine=not visible_attr and state.hidden is None,
                )
        if tag.name in ("input", "button", "option") and tag.get("value"):
            input_type = str(tag.get("type", "text")).lower()
            shown = input_type in ("text", "search", "email", "url", "submit", "button", "tel")
            reason = state.hidden if shown else (state.hidden or f"input type={input_type} value")
            self._add(str(tag["value"]), f"{source_prefix}.value", f"{where} @value",
                      hidden=reason, routine=input_type not in ("hidden",) and not shown)
        for attr, value in tag.attrs.items():
            if attr.startswith("data-") and isinstance(value, str) and len(value) >= 20 \
                    and " " in value:
                self._add(value, f"{source_prefix}.data-attribute", f"{where} @{attr}",
                          hidden=state.hidden or "data attribute", routine=state.hidden is None)

    def _embedded(self, tag: Tag) -> None:
        if self.depth >= MAX_DEPTH:
            return
        if tag.name == "iframe" and tag.get("srcdoc"):
            self._nested(str(tag["srcdoc"]), f"{describe(tag)} srcdoc", "text/html")
        for attr in ("src", "data", "href"):
            value = tag.get(attr)
            if isinstance(value, str) and value.startswith("data:"):
                self._data_uri(value, f"{describe(tag)} @{attr}")

    def _data_uri(self, uri: str, where: str) -> None:
        header, _, payload = uri[5:].partition(",")
        mime = header.split(";")[0].lower() or "text/plain"
        if not (mime.startswith("text/") or mime in ("image/svg+xml", "application/xhtml+xml")):
            return
        try:
            raw = base64.b64decode(payload, validate=False) if ";base64" in header \
                else unquote(payload).encode()
            body = raw[:200_000].decode("utf-8", errors="replace")
        except (binascii.Error, ValueError):
            return
        if mime in ("text/html", "image/svg+xml", "application/xhtml+xml"):
            self._nested(body, f"data: URI in {where}", mime)
        else:
            self._add(body, "html.data-uri", f"data: URI in {where}",
                      hidden="embedded data: URI")

    def _nested(self, html: str, where: str, mime: str) -> None:
        inner, notes = extract_html(html, prefix=self._loc(where), depth=self.depth + 1)
        self.segments.extend(inner)
        self.notes.extend(notes)

    def _script(self, tag: Tag) -> None:
        kind = str(tag.get("type", "")).lower()
        text = tag.get_text()
        if not text.strip():
            return
        if kind == "application/ld+json":
            try:
                data = json.loads(text)
            except ValueError:
                self._add(text, "page.metadata", "JSON-LD (unparseable)",
                          hidden="structured data", routine=True)
                return
            for path, value in _flatten(data):
                if len(value) >= 12:
                    self._add(value, "page.metadata", f"JSON-LD {path}",
                              hidden="structured data", routine=True)
        elif kind and "javascript" not in kind and "module" not in kind:
            # text/plain, text/template, application/json… — data a model may read.
            self._add(text, "html.script-data", f"<script type={kind}>",
                      hidden="non-executable <script> block")
        # JavaScript itself is not scanned: code is not prose, and the rules would
        # mostly find variable names.

    def _metadata(self) -> None:
        head = self.soup.head
        title = self.soup.title
        if title and title.string:
            self._add(title.string, "page.metadata", "<title>", hidden="page title",
                      routine=True)
        for meta in self.soup.find_all("meta"):
            content = meta.get("content")
            key = meta.get("name") or meta.get("property") or meta.get("http-equiv") \
                or meta.get("itemprop")
            if content and key:
                self._add(str(content), "page.metadata", f"<meta {key}>",
                          hidden="page metadata", routine=True)
        for link in self.soup.find_all("link", title=True):
            self._add(str(link["title"]), "page.metadata", "<link title>",
                      hidden="page metadata", routine=True)
        if head is not None:
            # Scripts in <head> are not reached by the body walk.
            for script in head.find_all("script"):
                self._script(script)
            for c in head.find_all(string=lambda s: isinstance(s, Comment)):
                self._add(str(c), "html.comment", "comment in <head>",
                          hidden="HTML comment", routine=True)

    def _flush_runs(self) -> None:
        """Merge consecutive text runs that share a block, visibility and form."""
        buffer: list[str] = []
        key: tuple[int, str | None, str | None] | None = None
        block_tag: Tag | None = None

        def emit() -> None:
            if not buffer or block_tag is None or key is None:
                return
            reason, form = key[1], key[2]
            text = re.sub(r"\s+", " ", "".join(buffer))
            source = ("form.text" if form else "html.hidden" if reason else "html.visible")
            where = describe(block_tag)
            if form and not where.startswith("form"):
                where = f"{form} › {where}"
            self._add(text, source, where, hidden=reason)

        for text, block, reason, form in self._runs:
            k = (id(block), reason, form)
            if k != key:
                emit()
                buffer, key, block_tag = [], k, block
            buffer.append(text)
        emit()


def _flatten(data: object, path: str = "$") -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if isinstance(data, dict):
        for k, v in data.items():
            out.extend(_flatten(v, f"{path}.{k}"))
    elif isinstance(data, list):
        for i, v in enumerate(data[:200]):
            out.extend(_flatten(v, f"{path}[{i}]"))
    elif isinstance(data, str):
        out.append((path, data))
    return out


def extract_html(html: str, prefix: str = "", depth: int = 0) -> tuple[list[Segment], list[str]]:
    """Segments and notes for one HTML or SVG document."""
    notes: list[str] = []
    if len(html) > MAX_HTML_BYTES:
        html = html[:MAX_HTML_BYTES]
        notes.append(f"Page truncated to {MAX_HTML_BYTES // 1_000_000} MB before scanning")
    soup = BeautifulSoup(html, "html.parser")
    ex = _Extractor(soup, prefix, depth)
    ex.run()
    return ex.segments, notes + ex.notes


def looks_like_html(text: str) -> bool:
    head = text.lstrip()[:500].lower()
    if head.startswith(("<!doctype html", "<html", "<svg", "<?xml")):
        return True
    tags = re.findall(r"</?(div|p|span|body|head|form|input|a|img|meta|svg)\b", text[:5000], re.I)
    return len(tags) >= 3
