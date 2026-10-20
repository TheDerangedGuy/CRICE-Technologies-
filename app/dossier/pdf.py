"""
app/dossier/pdf.py – Pure-Python Valid %PDF-1.4 Generator for CRICE Dossiers.

Generates structurally valid, standards-compliant multi-page %PDF-1.4 binary documents
without any external native dependencies (e.g. WeasyPrint or ReportLab).
Compatible with macOS Preview, Acrobat Reader, Chrome PDF Viewer, and Linux evince.
"""
import datetime
import re
from typing import Any, List, Optional, Tuple


def _escape_pdf_text(text: str) -> str:
    """Escape special PDF text string characters and sanitize unicode."""
    if not text:
        return ""
    # Map common unicode punctuation to ASCII equivalents
    clean = (
        text.replace("\u2022", "-")
        .replace("\u2013", "-")
        .replace("\u2014", "--")
        .replace("\u2018", "'")
        .replace("\u2019", "'")
        .replace("\u201c", '"')
        .replace("\u201d", '"')
        .replace("\u2026", "...")
        .replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
    )
    out = []
    for ch in clean:
        code = ord(ch)
        if code > 127:
            out.append("?")
        else:
            out.append(ch)
    return "".join(out)


def _wrap_text(text: str, max_chars: int = 80) -> List[str]:
    """Wrap plain text at word boundaries."""
    if not text:
        return []
    lines = []
    for raw_line in text.split("\n"):
        raw_line = raw_line.strip()
        if not raw_line:
            lines.append("")
            continue
        words = raw_line.split(" ")
        curr = []
        curr_len = 0
        for w in words:
            if curr_len + len(w) + (1 if curr else 0) > max_chars:
                lines.append(" ".join(curr))
                curr = [w]
                curr_len = len(w)
            else:
                curr.append(w)
                curr_len += len(w) + (1 if len(curr) > 1 else 0)
        if curr:
            lines.append(" ".join(curr))
    return lines


class SimplePDFCanvas:
    """A minimal, deterministic multi-page PDF builder."""

    PAGE_WIDTH = 595.28   # A4 width in pt
    PAGE_HEIGHT = 841.89  # A4 height in pt
    MARGIN_LEFT = 40.0
    MARGIN_RIGHT = 555.28
    CONTENT_WIDTH = 515.28
    MARGIN_TOP = 790.0
    MARGIN_BOTTOM = 50.0

    def __init__(self, title: str = "CRICE INTELLIGENCE DOSSIER"):
        self.title = title
        self.pages_ops: List[List[str]] = []
        self.curr_page_ops: List[str] = []
        self.y = self.MARGIN_TOP
        self.page_number = 1
        self._new_page()

    def _new_page(self):
        if self.curr_page_ops:
            self.pages_ops.append(self.curr_page_ops)
        self.curr_page_ops = []
        self.y = self.MARGIN_TOP

        # Draw page running header
        self.curr_page_ops.append("q")
        self.curr_page_ops.append("0.4 0.4 0.4 rg")  # Muted grey
        self.curr_page_ops.append("BT /F1 8 Tf 40 810 Td (CRICE // CONFIDENTIAL // CLIENT-SCOPED) Tj ET")
        self.curr_page_ops.append("BT /F1 8 Tf 450 810 Td (INVESTIGATIVE REPORT) Tj ET")
        self.curr_page_ops.append("0.8 0.8 0.8 RG 0.5 w")
        self.curr_page_ops.append(f"40 802 m 555.28 802 l S")
        self.curr_page_ops.append("Q")

    def _check_space(self, height_needed: float):
        if self.y - height_needed < self.MARGIN_BOTTOM:
            self._new_page()

    def draw_rule(self, color=(0.8, 0.8, 0.8), width=0.5):
        self._check_space(10)
        self.curr_page_ops.append("q")
        self.curr_page_ops.append(f"{color[0]} {color[1]} {color[2]} RG {width} w")
        self.curr_page_ops.append(f"{self.MARGIN_LEFT} {self.y} m {self.MARGIN_RIGHT} {self.y} l S")
        self.curr_page_ops.append("Q")
        self.y -= 10

    def add_title_banner(self, case_ref: str, version: int):
        self._check_space(70)
        # Background box
        self.curr_page_ops.append("q")
        self.curr_page_ops.append("0.05 0.07 0.1 rg")  # Deep obsidian dark blue
        self.curr_page_ops.append(f"{self.MARGIN_LEFT} {self.y - 50} {self.CONTENT_WIDTH} 50 re f")

        # Cyan border strip on left
        self.curr_page_ops.append("0 0.94 1 RG 3 w")
        self.curr_page_ops.append(f"{self.MARGIN_LEFT} {self.y - 50} m {self.MARGIN_LEFT} {self.y} l S")

        # Text inside banner
        self.curr_page_ops.append("1 1 1 rg")
        self.curr_page_ops.append(f"BT /F2 16 Tf {self.MARGIN_LEFT + 15} {self.y - 24} Td ({_escape_pdf_text(self.title)}) Tj ET")

        self.curr_page_ops.append("0 0.94 1 rg")
        self.curr_page_ops.append(f"BT /F3 10 Tf {self.MARGIN_LEFT + 15} {self.y - 42} Td (CASE: {_escape_pdf_text(case_ref)}  |  VERSION: v{version}.0  |  STATUS: FINAL) Tj ET")
        self.curr_page_ops.append("Q")

        self.y -= 65

    def add_section_header(self, title: str):
        self._check_space(35)
        self.curr_page_ops.append("q")
        self.curr_page_ops.append("0.1 0.1 0.15 rg")
        self.curr_page_ops.append(f"{self.MARGIN_LEFT} {self.y - 18} {self.CONTENT_WIDTH} 20 re f")
        self.curr_page_ops.append("0 0.8 0.9 rg")
        self.curr_page_ops.append(f"BT /F2 10 Tf {self.MARGIN_LEFT + 8} {self.y - 14} Td ({_escape_pdf_text(title.upper())}) Tj ET")
        self.curr_page_ops.append("Q")
        self.y -= 26

    def add_kv_row(self, label: str, val: str, width_label: float = 140.0):
        self._check_space(14)
        safe_lbl = _escape_pdf_text(label)
        safe_val = _escape_pdf_text(val)
        self.curr_page_ops.append("q")
        self.curr_page_ops.append("0.4 0.45 0.5 rg")
        self.curr_page_ops.append(f"BT /F2 8.5 Tf {self.MARGIN_LEFT + 4} {self.y - 9} Td ({safe_lbl}:) Tj ET")
        self.curr_page_ops.append("0.1 0.1 0.1 rg")
        self.curr_page_ops.append(f"BT /F1 8.5 Tf {self.MARGIN_LEFT + width_label} {self.y - 9} Td ({safe_val}) Tj ET")
        self.curr_page_ops.append("Q")
        self.y -= 14

    def add_paragraph(self, text: str, font="F1", size=8.5, max_chars=95, color=(0.15, 0.15, 0.15)):
        wrapped = _wrap_text(text, max_chars=max_chars)
        line_height = size * 1.35
        self._check_space(len(wrapped) * line_height + 6)
        self.curr_page_ops.append("q")
        self.curr_page_ops.append(f"{color[0]} {color[1]} {color[2]} rg")
        for line in wrapped:
            safe = _escape_pdf_text(line)
            self.curr_page_ops.append(f"BT /{font} {size} Tf {self.MARGIN_LEFT + 4} {self.y - size} Td ({safe}) Tj ET")
            self.y -= line_height
        self.curr_page_ops.append("Q")
        self.y -= 4

    def add_callout_box(self, title: str, text: str, border_color=(0.9, 0.6, 0.1), bg_color=(0.99, 0.98, 0.94)):
        wrapped = _wrap_text(text, max_chars=88)
        box_height = 20 + (len(wrapped) * 11)
        self._check_space(box_height + 10)

        self.curr_page_ops.append("q")
        # Background
        self.curr_page_ops.append(f"{bg_color[0]} {bg_color[1]} {bg_color[2]} rg")
        self.curr_page_ops.append(f"{self.MARGIN_LEFT} {self.y - box_height} {self.CONTENT_WIDTH} {box_height} re f")
        # Left Border
        self.curr_page_ops.append(f"{border_color[0]} {border_color[1]} {border_color[2]} RG 3 w")
        self.curr_page_ops.append(f"{self.MARGIN_LEFT} {self.y - box_height} m {self.MARGIN_LEFT} {self.y} l S")

        # Title
        self.curr_page_ops.append(f"{border_color[0]} {border_color[1]} {border_color[2]} rg")
        self.curr_page_ops.append(f"BT /F2 9 Tf {self.MARGIN_LEFT + 10} {self.y - 12} Td ({_escape_pdf_text(title)}) Tj ET")

        # Body text
        self.curr_page_ops.append("0.2 0.2 0.2 rg")
        curr_y = self.y - 24
        for line in wrapped:
            self.curr_page_ops.append(f"BT /F1 8 Tf {self.MARGIN_LEFT + 10} {curr_y} Td ({_escape_pdf_text(line)}) Tj ET")
            curr_y -= 11

        self.curr_page_ops.append("Q")
        self.y -= (box_height + 8)

    def add_finding_card(
        self,
        score_badge: str,
        predicate: str,
        object_value: str,
        verbatim_quote: Optional[str],
        primary_record_id: int,
        snapshot_hash: str,
        is_adverse: bool = False,
    ):
        quote_lines = _wrap_text(f'"{verbatim_quote}"', max_chars=85) if verbatim_quote else []
        obj_lines = _wrap_text(object_value, max_chars=85)
        card_height = 42 + (len(obj_lines) * 11) + (len(quote_lines) * 10 if quote_lines else 0)
        self._check_space(card_height + 10)

        self.curr_page_ops.append("q")
        # Background
        if is_adverse:
            self.curr_page_ops.append("1 0.96 0.96 rg")  # Slight red tint
            self.curr_page_ops.append(f"{self.MARGIN_LEFT} {self.y - card_height} {self.CONTENT_WIDTH} {card_height} re f")
            self.curr_page_ops.append("0.9 0.15 0.2 RG 2 w")
            self.curr_page_ops.append(f"{self.MARGIN_LEFT} {self.y - card_height} m {self.MARGIN_LEFT} {self.y} l S")
        else:
            self.curr_page_ops.append("0.97 0.98 0.99 rg")
            self.curr_page_ops.append(f"{self.MARGIN_LEFT} {self.y - card_height} {self.CONTENT_WIDTH} {card_height} re f")
            self.curr_page_ops.append("0 0.7 0.8 RG 2 w")
            self.curr_page_ops.append(f"{self.MARGIN_LEFT} {self.y - card_height} m {self.MARGIN_LEFT} {self.y} l S")

        # Score Badge
        self.curr_page_ops.append("0 0 0 rg")
        self.curr_page_ops.append(f"BT /F3 9 Tf {self.MARGIN_LEFT + 8} {self.y - 13} Td ([{score_badge}]) Tj ET")

        # Predicate
        self.curr_page_ops.append("0.1 0.1 0.15 rg")
        self.curr_page_ops.append(f"BT /F2 9 Tf {self.MARGIN_LEFT + 55} {self.y - 13} Td ({_escape_pdf_text(predicate)}) Tj ET")

        if is_adverse:
            self.curr_page_ops.append("0.85 0.1 0.1 rg")
            self.curr_page_ops.append(f"BT /F2 8 Tf {self.MARGIN_RIGHT - 80} {self.y - 13} Td ([ADVERSE]) Tj ET")

        # Object Value lines
        self.curr_page_ops.append("0.15 0.15 0.15 rg")
        cy = self.y - 25
        for ol in obj_lines:
            self.curr_page_ops.append(f"BT /F1 8.5 Tf {self.MARGIN_LEFT + 8} {cy} Td ({_escape_pdf_text(ol)}) Tj ET")
            cy -= 11

        # Verbatim quote
        if quote_lines:
            self.curr_page_ops.append("0.35 0.35 0.4 rg")
            for ql in quote_lines:
                self.curr_page_ops.append(f"BT /F1 7.5 Tf {self.MARGIN_LEFT + 15} {cy} Td ({_escape_pdf_text(ql)}) Tj ET")
                cy -= 10

        # Provenance line
        self.curr_page_ops.append("0.5 0.55 0.6 rg")
        hash_snip = snapshot_hash[:16] + "..." if len(snapshot_hash) > 16 else snapshot_hash
        self.curr_page_ops.append(f"BT /F3 7 Tf {self.MARGIN_LEFT + 8} {self.y - card_height + 4} Td (Record #{primary_record_id} | SHA-256: {hash_snip}) Tj ET")

        self.curr_page_ops.append("Q")
        self.y -= (card_height + 8)

    def add_table(self, headers: List[str], rows: List[List[str]], col_widths: List[float]):
        row_height = 16.0
        header_height = 18.0
        self._check_space(header_height + (len(rows) * row_height) + 10)

        # Header
        self.curr_page_ops.append("q")
        self.curr_page_ops.append("0.9 0.92 0.94 rg")
        self.curr_page_ops.append(f"{self.MARGIN_LEFT} {self.y - header_height} {self.CONTENT_WIDTH} {header_height} re f")
        self.curr_page_ops.append("0.2 0.25 0.3 rg")
        cx = self.MARGIN_LEFT + 4
        for i, h in enumerate(headers):
            self.curr_page_ops.append(f"BT /F2 7.5 Tf {cx} {self.y - 12} Td ({_escape_pdf_text(h)}) Tj ET")
            cx += col_widths[i]
        self.curr_page_ops.append("Q")
        self.y -= header_height

        # Rows
        for r_idx, row in enumerate(rows):
            self._check_space(row_height)
            self.curr_page_ops.append("q")
            if r_idx % 2 == 1:
                self.curr_page_ops.append("0.98 0.98 0.99 rg")
                self.curr_page_ops.append(f"{self.MARGIN_LEFT} {self.y - row_height} {self.CONTENT_WIDTH} {row_height} re f")

            self.curr_page_ops.append("0.15 0.15 0.2 rg")
            cx = self.MARGIN_LEFT + 4
            for i, cell in enumerate(row):
                safe = _escape_pdf_text(str(cell)[:35])
                self.curr_page_ops.append(f"BT /F1 7 Tf {cx} {self.y - 11} Td ({safe}) Tj ET")
                cx += col_widths[i]

            self.curr_page_ops.append("0.88 0.88 0.9 RG 0.3 w")
            self.curr_page_ops.append(f"{self.MARGIN_LEFT} {self.y - row_height} m {self.MARGIN_RIGHT} {self.y - row_height} l S")
            self.curr_page_ops.append("Q")
            self.y -= row_height

        self.y -= 8

    def build(self) -> bytes:
        """Compile and return binary PDF bytes conforming to %PDF-1.4."""
        if self.curr_page_ops:
            self.pages_ops.append(self.curr_page_ops)
            self.curr_page_ops = []

        total_pages = len(self.pages_ops)
        objects: List[str] = []

        def add_obj(content: str) -> int:
            objects.append(content)
            return len(objects)

        # 1: Catalog
        cat_id = add_obj("<< /Type /Catalog /Pages 2 0 R >>")
        # 2: Pages (placeholder, updated later)
        pages_id = add_obj("<< /Type /Pages /Kids [] /Count 0 >>")

        # Fonts
        f1_id = add_obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        f2_id = add_obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
        f3_id = add_obj("<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")

        page_ids = []
        for p_idx, page_ops in enumerate(self.pages_ops, 1):
            # Add page running footer
            page_ops.append("q")
            page_ops.append("0.5 0.5 0.5 rg")
            now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            page_ops.append(f"BT /F1 7.5 Tf 40 30 Td (CRICE DOSSIER | Generated {now_str}) Tj ET")
            page_ops.append(f"BT /F1 7.5 Tf 480 30 Td (Page {p_idx} of {total_pages}) Tj ET")
            page_ops.append("0.8 0.8 0.8 RG 0.5 w")
            page_ops.append("40 40 m 555.28 40 l S")
            page_ops.append("Q")

            stream_data = "\n".join(page_ops)
            stream_bytes = stream_data.encode("latin1")
            content_id = add_obj(
                f"<< /Length {len(stream_bytes)} >>\nstream\n{stream_data}\nendstream"
            )

            page_obj = (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595.28 841.89] "
                f"/Contents {content_id} 0 R "
                f"/Resources << /Font << /F1 {f1_id} 0 R /F2 {f2_id} 0 R /F3 {f3_id} 0 R >> >> >>"
            )
            p_obj_id = add_obj(page_obj)
            page_ids.append(f"{p_obj_id} 0 R")

        # Update Pages object (#2)
        kids_str = " ".join(page_ids)
        objects[1] = f"<< /Type /Pages /Kids [{kids_str}] /Count {total_pages} >>"

        # Serialize PDF with exact xref table
        header = "%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
        out_chunks = [header.encode("latin1")]
        offsets = [0]
        curr_offset = len(header.encode("latin1"))

        for i, obj_content in enumerate(objects, 1):
            offsets.append(curr_offset)
            block = f"{i} 0 obj\n{obj_content}\nendobj\n"
            block_bytes = block.encode("latin1")
            out_chunks.append(block_bytes)
            curr_offset += len(block_bytes)

        xref_offset = curr_offset
        xref_table = [f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n"]
        for off in offsets[1:]:
            xref_table.append(f"{off:010d} 00000 n \n")

        trailer = (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        )
        xref_bytes = "".join(xref_table).encode("latin1")
        trailer_bytes = trailer.encode("latin1")
        out_chunks.append(xref_bytes)
        out_chunks.append(trailer_bytes)

        return b"".join(out_chunks)
