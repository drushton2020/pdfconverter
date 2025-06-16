import re
import csv
from pdfminer.high_level import extract_text


def parse_findings(text):
    findings = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if re.match(r"^(\d+[\.)]|[-*\u2022])\s+", line):
            findings.append(line)
            continue
        if re.search(r"\b(Finding|Issue|Vulnerability|Observation)\b", line, re.IGNORECASE):
            findings.append(line)
    return findings


def parse_severity(text):
    match = re.search(r"\[(.*?)\]", text)
    severity = match.group(1) if match else ""
    description = re.sub(r"\[.*?\]", "", text).strip()
    return severity, description


def convert_pdf_to_csv(pdf_path, csv_path):
    text = extract_text(pdf_path)
    lines = parse_findings(text)
    with open(csv_path, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Severity", "Finding"])
        for line in lines:
            severity, desc = parse_severity(line)
            writer.writerow([severity, desc])


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Extract findings from a pentest PDF to CSV.")
    parser.add_argument("pdf", help="Input PDF file")
    parser.add_argument("csv", help="Output CSV file")
    args = parser.parse_args()
    convert_pdf_to_csv(args.pdf, args.csv)
