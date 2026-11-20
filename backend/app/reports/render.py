"""Render a report document to PDF (fpdf2) or CSV. Both carry generation time, generator and data sources."""
import csv
import io
import os

from fpdf import FPDF
from fpdf.enums import XPos, YPos

FONT_DIR = "/usr/share/fonts/truetype/dejavu"
# CSV cells that start with these are prefixed with ' so spreadsheet apps do not evaluate them as formulas
_FORMULA = ("=", "+", "-", "@", "\t", "\r")


def _cell(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s.startswith(_FORMULA) else s


def to_csv(doc: dict, meta: dict) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["# report", doc["title"]])
    w.writerow(["# generated_at", meta["generated_at"]])
    w.writerow(["# generated_by", meta["generated_by"]])
    w.writerow(["# sources", "; ".join(doc["sources"])])
    w.writerow(doc["primary"]["columns"])
    for r in doc["primary"]["rows"]:
        w.writerow([_cell(x) for x in r])
    return buf.getvalue().encode("utf-8")


class _PDF(FPDF):
    def __init__(self, footer_text: str):
        super().__init__(orientation="L", unit="mm", format="A4")
        self.footer_text = footer_text
        self.unicode = os.path.exists(f"{FONT_DIR}/DejaVuSans.ttf")
        if self.unicode:
            self.add_font("DV", "", f"{FONT_DIR}/DejaVuSans.ttf")
            self.add_font("DV", "B", f"{FONT_DIR}/DejaVuSans-Bold.ttf")
            self.family = "DV"
        else:
            self.family = "Helvetica"
        self.set_auto_page_break(True, margin=14)

    def txt(self, s) -> str:
        s = "" if s is None else str(s)
        return s if self.unicode else s.encode("latin-1", "replace").decode("latin-1")

    def footer(self):
        self.set_y(-10)
        self.set_font(self.family, "", 7)
        self.set_text_color(110, 110, 110)
        self.cell(0, 5, self.txt(f"{self.footer_text} · page {self.page_no()}/{{nb}}"), align="C")


def to_pdf(doc: dict, meta: dict) -> bytes:
    pdf = _PDF(f"CYBER RANGE · {doc['title']} · generated {meta['generated_at']} by {meta['generated_by']}")
    pdf.alias_nb_pages()
    pdf.add_page()
    f = pdf.family
    pdf.set_font(f, "B", 16)
    pdf.multi_cell(0, 8, pdf.txt(doc["title"]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font(f, "", 9)
    pdf.set_text_color(90, 90, 90)
    pdf.multi_cell(0, 5, pdf.txt(doc.get("subtitle", "")), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.multi_cell(0, 5, pdf.txt(f"Generated {meta['generated_at']} by {meta['generated_by']} · report #{meta['report_id']}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.multi_cell(0, 5, pdf.txt("Data sources: " + "; ".join(doc["sources"])), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(0, 0, 0)
    for sec in doc["sections"]:
        pdf.ln(3)
        pdf.set_font(f, "B", 12)
        pdf.cell(0, 7, pdf.txt(sec["heading"]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font(f, "", 9)
        for k, v in sec.get("kv", []):
            pdf.set_font(f, "B", 9)
            pdf.cell(45, 5, pdf.txt(k))
            pdf.set_font(f, "", 9)
            pdf.multi_cell(0, 5, pdf.txt(v), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        if sec.get("text"):
            pdf.ln(1)
            pdf.multi_cell(0, 5, pdf.txt(sec["text"]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        t = sec.get("table")
        if t is not None:
            if not t["rows"]:
                pdf.set_text_color(110, 110, 110)
                pdf.cell(0, 5, pdf.txt("No records."), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_text_color(0, 0, 0)
                continue
            pdf.set_font(f, "", 7)
            with pdf.table(text_align="LEFT", line_height=4, first_row_as_headings=True, padding=1) as table:
                table.row([pdf.txt(c) for c in t["columns"]])
                for r in t["rows"][:2000]:
                    table.row([pdf.txt(x)[:400] for x in r])
            if len(t["rows"]) > 2000:
                pdf.cell(0, 5, pdf.txt(f"… {len(t['rows']) - 2000} more rows in the CSV export"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    return bytes(pdf.output())
