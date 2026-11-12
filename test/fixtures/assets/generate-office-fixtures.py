#!/usr/bin/env python3
"""Generate deterministic Office fixtures for the AtkBrain extraction tests.

Usage: python3 generate-office-fixtures.py <output-dir>

The script is dependency-tolerant: a missing library is reported in the JSON
summary as a `skipped` entry and the remaining fixtures are still generated.
"""

import json
import sys
from pathlib import Path


def short_error(exc):
    return "%s: %s" % (type(exc).__name__, exc)


def main():
    if len(sys.argv) < 2:
        print("usage: generate-office-fixtures.py <output-dir>", file=sys.stderr)
        return 2
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    result = {"ok": False, "files": [], "skipped": []}

    try:
        from openpyxl import Workbook

        workbook = Workbook()
        assets = workbook.active
        assets.title = "Assets"
        assets.append(["Host", "Port", "URL"])
        assets.append(["www.example.com", 443, "https://www.example.com/"])
        assets.append(["api.example.com", 8443, "https://api.example.com:8443/v1?x=1"])
        inventory = workbook.create_sheet("Inventory")
        inventory.append(["internal.example.com", None, "192.0.2.16"])
        workbook.save(out / "assets.xlsx")
        result["files"].append("assets.xlsx")
    except Exception as exc:  # noqa: BLE001 - fixture generation is best effort
        result["skipped"].append({"file": "assets.xlsx", "reason": short_error(exc)})

    try:
        from docx import Document

        document = Document()
        document.add_heading("Asset inventory", 0)
        document.add_paragraph("Web front end:")
        document.add_paragraph("www.example.com")
        document.add_paragraph("API:")
        document.add_paragraph("api.example.com")
        table = document.add_table(rows=2, cols=2)
        table.cell(0, 0).text = "Host"
        table.cell(0, 1).text = "IP"
        table.cell(1, 0).text = "report.example.com"
        table.cell(1, 1).text = "192.0.2.20"
        document.save(out / "assets.docx")
        result["files"].append("assets.docx")
    except Exception as exc:  # noqa: BLE001
        result["skipped"].append({"file": "assets.docx", "reason": short_error(exc)})

    try:
        from pptx import Presentation
        from pptx.util import Inches

        presentation = Presentation()
        title_slide = presentation.slides.add_slide(presentation.slide_layouts[1])
        title_slide.shapes.title.text = "Asset inventory"
        title_slide.placeholders[1].text = "www.example.com\napi.example.com"
        table_slide = presentation.slides.add_slide(presentation.slide_layouts[5])
        table_slide.shapes.title.text = "Hosts"
        table = table_slide.shapes.add_table(2, 2, Inches(1), Inches(2), Inches(4), Inches(1)).table
        table.cell(0, 0).text = "Host"
        table.cell(0, 1).text = "IP"
        table.cell(1, 0).text = "cdn.example.com"
        table.cell(1, 1).text = "192.0.2.30"
        presentation.save(out / "assets.pptx")
        result["files"].append("assets.pptx")
    except Exception as exc:  # noqa: BLE001
        result["skipped"].append({"file": "assets.pptx", "reason": short_error(exc)})

    result["ok"] = len(result["files"]) > 0
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
