"""PDF report (reportlab). Uses only the built-in PDF fonts so it renders the same on every computer."""

from __future__ import annotations

import re
from collections import defaultdict
from xml.sax.saxutils import escape

from reportlab.graphics.charts.barcharts import HorizontalBarChart
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, KeepTogether, NextPageTemplate, PageBreak, PageTemplate, Paragraph, Spacer, Table, TableStyle,
)

from . import __version__
from .engine import IMPACT, LIKELIHOOD, Report, risk_level
from .frameworks import FRAMEWORKS, MANUAL_CHECKS, SOURCES
from .model import Status

# --- Look and feel ------------------------------------------------------------------------------------

INK = colors.HexColor("#1b2430")
MUTED = colors.HexColor("#5b6675")
LINE = colors.HexColor("#d7dde5")
SOFT = colors.HexColor("#f3f5f8")
ACCENT = colors.HexColor("#0b6e99")
STATUS_COLORS = {
    Status.PASS: colors.HexColor("#1f8a4c"), Status.WARN: colors.HexColor("#c77700"),
    Status.FAIL: colors.HexColor("#c62f3b"), Status.MANUAL: colors.HexColor("#4a5d80"),
    Status.NA: colors.HexColor("#8a94a3"),
}
LEVEL_COLORS = {"High": STATUS_COLORS[Status.FAIL], "Medium": STATUS_COLORS[Status.WARN], "Low": STATUS_COLORS[Status.PASS]}
APPLICABILITY_COLORS = {"Applies": colors.HexColor("#c62f3b"), "Indirect": colors.HexColor("#c77700"),
                        "Likely out of scope": colors.HexColor("#4a5d80"), "Voluntary": colors.HexColor("#0b6e99"),
                        "Not applicable": colors.HexColor("#8a94a3")}

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm
CONTENT_W = PAGE_W - 2 * MARGIN

base = getSampleStyleSheet()
S = {
    "body": ParagraphStyle("body", parent=base["Normal"], fontName="Helvetica", fontSize=9.2, leading=13, textColor=INK),
    "small": ParagraphStyle("small", parent=base["Normal"], fontName="Helvetica", fontSize=8, leading=10.5, textColor=INK),
    "muted": ParagraphStyle("muted", parent=base["Normal"], fontName="Helvetica", fontSize=8, leading=10.5, textColor=MUTED),
    "mono": ParagraphStyle("mono", parent=base["Normal"], fontName="Courier", fontSize=7.3, leading=9.4, textColor=INK),
    "h1": ParagraphStyle("h1", parent=base["Heading1"], fontName="Helvetica-Bold", fontSize=17, leading=21,
                         textColor=INK, spaceBefore=0, spaceAfter=8),
    "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=12, leading=15,
                         textColor=INK, spaceBefore=12, spaceAfter=5),
    "h3": ParagraphStyle("h3", parent=base["Heading3"], fontName="Helvetica-Bold", fontSize=9.6, leading=12.5,
                         textColor=INK, spaceBefore=0, spaceAfter=0),
    "cell": ParagraphStyle("cell", parent=base["Normal"], fontName="Helvetica", fontSize=8, leading=10.2, textColor=INK),
    "cellb": ParagraphStyle("cellb", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=8, leading=10.2, textColor=INK),
    "head": ParagraphStyle("head", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=7.6, leading=9.5,
                           textColor=colors.white),
    "chip": ParagraphStyle("chip", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=7.4, leading=9,
                           textColor=colors.white, alignment=TA_CENTER),
}


def P(text: str, style: str = "body") -> Paragraph:
    return Paragraph(text, S[style])


def E(text: object) -> str:
    """Escape text coming from the scanned repository before it goes into a Paragraph."""
    return escape(str(text))


def C(text: object) -> str:
    """Escape text and show `code` spans in a monospaced font."""
    return re.sub(r"`([^`]+)`", r"<font name='Courier'>\1</font>", E(text))


def chip(label: str, color, width: float = 17 * mm) -> Table:
    t = Table([[Paragraph(E(label), S["chip"])]], colWidths=[width], rowHeights=[5.2 * mm])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), color), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                           ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0)]))
    return t


def grid(rows: list[list], widths: list[float], header: bool = True, zebra: bool = True) -> Table:
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
    ]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), INK), ("VALIGN", (0, 0), (-1, 0), "MIDDLE")]
    if zebra:
        start = 1 if header else 0
        style += [("BACKGROUND", (0, i), (-1, i), SOFT) for i in range(start + 1, len(rows), 2)]
    t.setStyle(TableStyle(style))
    return t


def H(*labels: str) -> list[Paragraph]:
    return [Paragraph(E(label), S["head"]) for label in labels]


# --- Page templates ----------------------------------------------------------------------------------------

class ReportDoc(BaseDocTemplate):
    def __init__(self, path: str, report: Report) -> None:
        super().__init__(path, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=MARGIN + 6 * mm,
                         bottomMargin=MARGIN, title=f"Compliance readiness report: {report.repo.root.name}",
                         author="compliance-check", subject="NIS2, DORA, CRA, ISO/IEC 27001, ISO/IEC 27005, AI Act, GDPR")
        self.report = report
        frame = Frame(MARGIN, MARGIN, CONTENT_W, PAGE_H - 2 * MARGIN - 6 * mm, id="body", leftPadding=0, rightPadding=0,
                      topPadding=0, bottomPadding=0)
        self.addPageTemplates([PageTemplate("cover", frames=[frame], onPage=self._cover),
                               PageTemplate("normal", frames=[frame], onPage=self._normal)])

    def _cover(self, canvas, doc) -> None:
        canvas.saveState()
        canvas.setFillColor(INK)
        canvas.rect(0, PAGE_H - 92 * mm, PAGE_W, 92 * mm, stroke=0, fill=1)
        canvas.setFillColor(ACCENT)
        canvas.rect(0, PAGE_H - 94 * mm, PAGE_W, 2 * mm, stroke=0, fill=1)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica", 10)
        canvas.drawString(MARGIN, PAGE_H - 30 * mm, "TECHNICAL COMPLIANCE READINESS REPORT")
        canvas.setFont("Helvetica-Bold", 26)
        canvas.drawString(MARGIN, PAGE_H - 44 * mm, self.report.repo.root.name)
        canvas.setFont("Helvetica", 11)
        canvas.drawString(MARGIN, PAGE_H - 54 * mm, "NIS2  |  DORA  |  CRA  |  ISO/IEC 27001:2022  |  ISO/IEC 27005:2022  |  AI Act  |  GDPR")
        canvas.setFont("Helvetica", 9)
        canvas.setFillColor(colors.HexColor("#b9c4d2"))
        meta = f"Generated {self.report.generated_at}"
        if self.report.repo.head:
            meta += f"   |   commit {self.report.repo.head} on {self.report.repo.branch}"
        canvas.drawString(MARGIN, PAGE_H - 66 * mm, meta)
        canvas.drawString(MARGIN, PAGE_H - 72 * mm, f"compliance-check {__version__}   |   "
                          f"{len(self.report.findings)} automated checks   |   {len(self.report.repo.files)} files scanned")
        canvas.restoreState()

    def _normal(self, canvas, doc) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(MARGIN, PAGE_H - MARGIN + 1 * mm, f"Compliance readiness report  |  {self.report.repo.root.name}")
        canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - MARGIN + 1 * mm, self.report.generated_at)
        canvas.setStrokeColor(LINE)
        canvas.line(MARGIN, PAGE_H - MARGIN - 1 * mm, PAGE_W - MARGIN, PAGE_H - MARGIN - 1 * mm)
        canvas.drawString(MARGIN, MARGIN - 8 * mm, "Automated technical assessment. Not legal advice or a certification audit.")
        canvas.drawRightString(PAGE_W - MARGIN, MARGIN - 8 * mm, f"Page {doc.page}")
        canvas.restoreState()


# --- Sections ----------------------------------------------------------------------------------------------

ORDER = ["NIS2", "DORA", "CRA", "ISO27001", "ISO27005", "AIACT", "GDPR"]


def cover(report: Report) -> list:
    c = report.counts
    story = [Spacer(1, 82 * mm), P("Summary", "h2")]
    tiles = [[P(f"<font size=20><b>{c[s.value]}</b></font>", "body") for s in Status],
             [P(f"<font color='#5b6675'>{label}</font>", "small") for label in
              ("controls in place", "partly in place", "missing", "need a manual check", "not applicable")]]
    t = Table(tiles, colWidths=[CONTENT_W / 5] * 5)
    t.setStyle(TableStyle([("LINEABOVE", (i, 0), (i, 0), 3, STATUS_COLORS[s]) for i, s in enumerate(Status)] +
                          [("TOPPADDING", (0, 0), (-1, 0), 7), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
    story += [t, Spacer(1, 6 * mm)]

    high = [r for r in report.risks if r["level"] == "High"]
    story.append(P(
        f"This report scans the <b>{E(report.repo.root.name)}</b> repository ({len(report.repo.projects)} Python projects, "
        f"{len(report.repo.files)} files) against technical requirements derived from seven frameworks. "
        f"<b>{c['PASS']}</b> of {len(report.findings) - c['N/A']} applicable controls are fully in place, "
        f"<b>{c['WARN']}</b> partly, and <b>{c['FAIL']}</b> are missing. The risk register lists "
        f"<b>{len(report.risks)}</b> risks, {len(high)} of them rated high."))
    story.append(Spacer(1, 4 * mm))

    rows = [H("Framework", "Relation to this project", "Readiness", "Pass", "Warn", "Fail")]
    for key in ORDER:
        fw, s = FRAMEWORKS[key], report.scores[key]
        level = fw.applicability_level
        rows.append([P(f"<b>{E(fw.name)}</b>", "cell"),
                     P(f"<font color='{APPLICABILITY_COLORS[level].hexval().replace('0x', '#')}'><b>{E(level)}</b></font>", "cell"),
                     P("-" if s.readiness is None else f"<b>{s.readiness}%</b>", "cell"),
                     P(str(s.passed), "cell"), P(str(s.warned), "cell"), P(str(s.failed), "cell")])
    story.append(grid(rows, [40 * mm, 52 * mm, 24 * mm, 18 * mm, 18 * mm, CONTENT_W - 152 * mm]))
    story.append(Spacer(1, 6 * mm))

    note = Table([[P("<b>What this report is, and isn't.</b> A script can verify technical controls in code, configuration "
                     "and documentation. It cannot verify governance, contracts, training, or legal applicability, which "
                     "decide compliance. Readiness percentages show how many <i>automatically verifiable</i> controls are in "
                     "place (partial counts half); they are not a compliance score. Section 6 lists the organisational "
                     "requirements to check by hand. Facts about the laws were verified on 31 October 2026.", "small")]],
                 colWidths=[CONTENT_W])
    note.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), SOFT), ("LINEBEFORE", (0, 0), (0, -1), 3, ACCENT),
                              ("LEFTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 6),
                              ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    story += [note, NextPageTemplate("normal"), PageBreak()]
    return story


def chart(report: Report) -> Drawing:
    keys = [k for k in reversed(ORDER) if report.scores[k].assessed or report.scores[k].manual]
    data = [[getattr(report.scores[k], attr) for k in keys] for attr in ("passed", "warned", "failed", "manual")]
    h = 22 + 15 * len(keys)
    d = Drawing(CONTENT_W, h + 44)
    bc = HorizontalBarChart()
    bc.x, bc.y, bc.width, bc.height = 62, 18, CONTENT_W - 80, h
    bc.data = data
    bc.categoryAxis.categoryNames = [FRAMEWORKS[k].name.replace("ISO/IEC ", "ISO ") for k in keys]
    bc.categoryAxis.style = "stacked"
    bc.categoryAxis.labels.fontName, bc.categoryAxis.labels.fontSize = "Helvetica", 7.5
    bc.categoryAxis.strokeColor = LINE
    bc.valueAxis.valueMin = 0
    bc.valueAxis.labels.fontName, bc.valueAxis.labels.fontSize = "Helvetica", 7
    bc.valueAxis.strokeColor = LINE
    bc.valueAxis.visibleGrid = True
    bc.valueAxis.gridStrokeColor = colors.HexColor("#eceff3")
    bc.barSpacing, bc.groupSpacing = 0, 5
    for i, s in enumerate((Status.PASS, Status.WARN, Status.FAIL, Status.MANUAL)):
        bc.bars[i].fillColor = STATUS_COLORS[s]
        bc.bars[i].strokeColor = colors.white
        bc.bars[i].strokeWidth = 0.5
    d.add(bc)
    x = 62
    for s, label in ((Status.PASS, "In place"), (Status.WARN, "Partly"), (Status.FAIL, "Missing"), (Status.MANUAL, "Manual")):
        d.add(Rect(x, h + 28, 7, 7, fillColor=STATUS_COLORS[s], strokeColor=None))
        d.add(String(x + 10, h + 29, label, fontName="Helvetica", fontSize=7.5, fillColor=MUTED))
        x += 62
    return d


def summary(report: Report) -> list:
    story = [P("1. Executive summary", "h1"),
             P("Number of automated checks per framework and their result. One check can provide evidence for several "
               "frameworks (for example, missing dependency updates affect NIS2, DORA, the CRA and ISO 27001).", "body"),
             Spacer(1, 3 * mm), chart(report), Spacer(1, 2 * mm), P("Top priorities", "h2"),
             P("The highest-rated risks from the register (section 5), with what to do about each.", "body"), Spacer(1, 2 * mm)]
    rows = [H("Risk", "Level", "What to do")]
    for r in report.risks[:7]:
        rows.append([P(f"<b>{E(r['id'])}</b> {E(r['risk'])}", "cell"), chip(r["level"], LEVEL_COLORS[r["level"]]),
                     P(C(r["action"]), "cell")])
    story.append(grid(rows, [58 * mm, 21 * mm, CONTENT_W - 79 * mm]))

    strengths = [f for f in report.findings if f.status == Status.PASS]
    story += [P("What is already in place", "h2"),
              P("; ".join(f"<b>{E(f.check_id)}</b> {E(f.title)}" for f in strengths) + ".", "body"),
              PageBreak()]
    return story


def applicability(report: Report) -> list:
    story = [P("2. Scope and applicability", "h1"),
             P("Whether each framework applies depends on <i>who</i> uses the software and <i>how</i>. This section "
               "states how each one relates to the scanned project, based on what the scan found.", "body"), Spacer(1, 3 * mm)]
    for key in ORDER:
        fw = FRAMEWORKS[key]
        color = APPLICABILITY_COLORS[fw.applicability_level]
        head = Table([[P(f"<b>{E(fw.name)}</b>  <font color='#5b6675' size=8>{E(fw.kind)}</font>", "h3"),
                       chip(fw.applicability_level, color, 31 * mm)]],
                     colWidths=[CONTENT_W - 31 * mm, 31 * mm])
        head.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                                  ("RIGHTPADDING", (0, 0), (-1, -1), 0)]))
        rows = [[P("Instrument", "muted"), P(E(fw.full_name), "cell")],
                [P("Applies to", "muted"), P(E(fw.applies_to), "cell")],
                [P("This project", "muted"), P(f"<b>{E(fw.applicability_level)}.</b> {E(fw.applicability)}", "cell")],
                [P("Key dates", "muted"), P("<br/>".join(E(d) for d in fw.key_dates), "cell")]]
        body = Table(rows, colWidths=[24 * mm, CONTENT_W - 24 * mm])
        body.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                                  ("TOPPADDING", (0, 0), (-1, -1), 1.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5)]))
        story.append(KeepTogether([head, Spacer(1, 1.5 * mm), body, Spacer(1, 2 * mm)]))
        line = Table([[""]], colWidths=[CONTENT_W], rowHeights=[0.1])
        line.setStyle(TableStyle([("LINEABOVE", (0, 0), (-1, -1), 0.5, LINE)]))
        story += [line, Spacer(1, 3 * mm)]
    story.append(PageBreak())
    return story


def by_framework(report: Report) -> list:
    story = [P("3. Results by framework", "h1"),
             P("Each referenced article, annex point or control, with the checks that provide evidence for it. "
               "Details for every check are in section 4.", "body")]
    for key in ORDER:
        fw, score = FRAMEWORKS[key], report.scores[key]
        refs: dict[str, list] = defaultdict(list)
        for f in score.findings:
            for ref in f.references[key]:
                refs[ref].append(f)
        if not refs:
            continue
        title = f"{fw.name}  -  readiness {score.readiness}%" if score.readiness is not None else f"{fw.name}"
        rows = [H("Reference", "Requirement", "Check", "Result")]
        for ref in sorted(refs, key=_ref_sort):
            for i, f in enumerate(refs[ref]):
                rows.append([P(f"<b>{E(ref)}</b>" if i == 0 else "", "cell"),
                             P(E(fw.references.get(ref, "")) if i == 0 else "", "cell"),
                             P(f"{E(f.check_id)} {E(f.title)}", "cell"), chip(f.status.value, STATUS_COLORS[f.status])])
        story += [P(E(title), "h2"),
                  P(f"<font color='#5b6675'>{E(fw.applicability_level)}: {E(fw.applicability.split('. ')[0])}.</font>", "small"),
                  Spacer(1, 2 * mm), grid(rows, [27 * mm, 58 * mm, CONTENT_W - 107 * mm, 22 * mm], zebra=False)]
    story.append(PageBreak())
    return story


def _ref_sort(ref: str):
    parts = re.findall(r"\d+|\D+", ref)
    return [(0, int(p)) if p.isdigit() else (1, p) for p in parts]


def findings(report: Report) -> list:
    story = [P("4. Detailed findings", "h1"),
             P("Every automated check: what was found, the evidence (file and line), what to do, and the references it "
               "supports.", "body")]
    category = None
    for f in report.findings:
        if f.category != category:
            category = f.category
            story.append(P(E(category), "h2"))
        head = Table([[P(f"<b>{E(f.check_id)}</b>  {E(f.title)}", "h3"), chip(f.status.value, STATUS_COLORS[f.status])]],
                     colWidths=[CONTENT_W - 19 * mm, 19 * mm])
        head.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("BACKGROUND", (0, 0), (-1, -1), SOFT),
                                  ("LEFTPADDING", (0, 0), (0, 0), 6), ("RIGHTPADDING", (-1, 0), (-1, 0), 4),
                                  ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                                  ("LINEBEFORE", (0, 0), (0, -1), 3, STATUS_COLORS[f.status])]))
        parts = [head, Spacer(1, 1.5 * mm), P(E(f.summary), "body")]
        if f.evidence:
            ev = "<br/>".join(E(e if len(e) < 150 else e[:147] + "...") for e in f.evidence[:8])
            more = f"<br/>... and {len(f.evidence) - 8} more" if len(f.evidence) > 8 else ""
            parts += [Spacer(1, 1 * mm), P(ev + more, "mono")]
        if f.recommendation:
            parts += [Spacer(1, 1.2 * mm), P(f"<b>Recommendation:</b> {C(f.recommendation)}", "small")]
        refs = "   ".join(f"<b>{E(FRAMEWORKS[k].name)}</b> {E(', '.join(v))}" for k, v in f.references.items())
        parts += [Spacer(1, 1.2 * mm), P(refs, "muted"), Spacer(1, 4 * mm)]
        story.append(KeepTogether(parts))
    story.append(PageBreak())
    return story


def risk_register(report: Report) -> list:
    story = [P("5. Risk register (ISO/IEC 27005:2022)", "h1")]
    story.append(P("Each missing or partial control is treated as a vulnerability (clause 7.2) and analysed on a 3 x 3 "
                   "qualitative scale (clause 7.3): <b>likelihood</b> that the gap is exploited or causes harm, times "
                   "<b>impact</b> if it does. Scores of 6-9 are high, 3-4 medium, 1-2 low (clause 7.4). A partly implemented "
                   "control lowers the likelihood by one step. Ratings are defaults set per check: review them with the "
                   "risk owner before accepting or treating a risk (clause 8).", "body"))
    story.append(Spacer(1, 3 * mm))

    counts = defaultdict(int)
    for r in report.risks:
        counts[(r["likelihood"], r["impact"])] += 1
    lik = sorted(LIKELIHOOD, key=LIKELIHOOD.get, reverse=True)
    imp = sorted(IMPACT, key=IMPACT.get)
    rows = [[P("<b>Likelihood \\ Impact</b>", "cell")] + [P(f"<b>{i.capitalize()}</b>", "cell") for i in imp]]
    style = [("GRID", (0, 0), (-1, -1), 0.6, colors.white), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
             ("ALIGN", (1, 1), (-1, -1), "CENTER")]
    for ri, li in enumerate(lik, 1):
        row = [P(f"<b>{li.capitalize()}</b>", "cell")]
        for ci, im in enumerate(imp, 1):
            n = counts[(li, im)]
            row.append(Paragraph(f"<b>{n or ''}</b>", ParagraphStyle("m", parent=S["chip"], fontSize=11)))
            level = risk_level(li, im)[1]
            style.append(("BACKGROUND", (ci, ri), (ci, ri), LEVEL_COLORS[level] if n else LEVEL_COLORS[level].clone(alpha=0.25)))
        rows.append(row)
    matrix = Table(rows, colWidths=[34 * mm, 22 * mm, 22 * mm, 22 * mm], rowHeights=[7 * mm] + [10 * mm] * 3)
    matrix.setStyle(TableStyle(style))
    story += [matrix, Spacer(1, 5 * mm)]

    rows = [H("ID", "Risk and finding", "L", "I", "Level", "Treatment and action")]
    for r in report.risks:
        rows.append([P(f"<b>{E(r['id'])}</b><br/><font size=7 color='#5b6675'>{E(r['check_id'])}</font>", "cell"),
                     P(f"<b>{E(r['risk'])}</b><br/>{E(r['finding'])}", "cell"),
                     P(str(LIKELIHOOD[r["likelihood"]]), "cell"), P(str(IMPACT[r["impact"]]), "cell"),
                     chip(r["level"], LEVEL_COLORS[r["level"]]),
                     P(f"<b>{E(r['treatment'])}.</b> {C(r['action'])}<br/><font color='#5b6675'>Owner: {E(r['owner'])}</font>",
                       "cell")])
    story += [grid(rows, [15 * mm, 62 * mm, 7 * mm, 7 * mm, 20 * mm, CONTENT_W - 111 * mm]),
              Spacer(1, 2 * mm), P("L = likelihood (1 unlikely, 2 possible, 3 likely). I = impact (1 low, 2 medium, 3 high). Score = L x I.",
                                   "muted"), PageBreak()]
    return story


def manual(report: Report) -> list:
    story = [P("6. Organisational requirements to check by hand", "h1"),
             P("These requirements depend on the organisation that builds or uses the tools, not on the code, so no scan "
               "can verify them. Tick them off with evidence (policy, record, contract, training log).", "body"),
             Spacer(1, 3 * mm)]
    rows = [H("", "Framework", "Reference", "Requirement")]
    for m in MANUAL_CHECKS:
        fw = FRAMEWORKS[m["framework"]]
        faded = fw.applicability_level in ("Not applicable",)
        style = "muted" if faded else "cell"
        rows.append([P("[  ]", "mono"), P(f"<b>{E(fw.name)}</b>", style), P(E(m["ref"]), style), P(E(m["item"]), style)])
    story += [grid(rows, [9 * mm, 30 * mm, 24 * mm, CONTENT_W - 63 * mm]), PageBreak()]
    return story


def appendix(report: Report) -> list:
    story = [P("Appendix A. Software bill of materials", "h1"),
             P("Runtime dependencies declared in each pyproject.toml, with the version installed where the scan ran. "
               "Run with <font name='Courier'>--sbom FILE</font> to export this as CycloneDX 1.5 JSON.", "body"),
             Spacer(1, 3 * mm)]
    rows = [H("Project", "Component", "Requirement", "Installed", "License")]
    for project, comps in report.components.items():
        for i, c in enumerate(comps):
            rows.append([P(f"<b>{E(project)}</b>" if i == 0 else "", "cell"), P(E(c["name"]), "cell"),
                         P(E(c["requirement"]), "mono"), P(E(c["version"] or "not installed"), "cell"),
                         P(E(c["license"] or "unknown"), "cell")])
    story.append(grid(rows, [32 * mm, 30 * mm, 38 * mm, 25 * mm, CONTENT_W - 125 * mm]))

    story += [Spacer(1, 6 * mm), P("Appendix B. Method and limitations", "h2"),
              P("The scanner reads the files git would publish (tracked, plus untracked files not ignored by .gitignore), "
                "parses every Python file into a syntax tree, and inspects CI workflows, pyproject.toml files, templates, "
                "documentation and test data. Checks look for concrete evidence and report file and line. "
                f"{'Known vulnerabilities were looked up on OSV.dev.' if report.online else 'The scan ran offline, so known vulnerabilities were not looked up (SC-03).'}",
                "body"), Spacer(1, 2 * mm),
              P("Limits: heuristics can miss problems or flag safe code (each FAIL and WARN should be confirmed by reading "
                "the evidence); GitHub settings such as branch protection, secret scanning and private vulnerability "
                "reporting are not visible from a clone; and legal applicability depends on facts outside the repository "
                "(commercial activity, sector, size, real data processed). This report is not legal advice, a certification "
                "audit, or a conformity assessment.", "body"),
              Spacer(1, 6 * mm), P("Appendix C. Sources", "h2")]
    story.append(P("<br/>".join(f"{E(title)}<br/><font color='#0b6e99' size=7.5>{E(url)}</font>" for title, url in SOURCES),
                   "small"))
    return story


def write_pdf(report: Report, path: str) -> None:
    doc = ReportDoc(path, report)
    story = (cover(report) + summary(report) + applicability(report) + by_framework(report) + findings(report)
             + risk_register(report) + manual(report) + appendix(report))
    doc.build(story)
