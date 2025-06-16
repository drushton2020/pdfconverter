# PDF Converter

This simple tool extracts potential findings from a pentest report in PDF format and exports them to a CSV file.

## Requirements

Install dependencies with:

```bash
pip install -r requirements.txt
```

## Usage

```bash
python pdf_to_csv.py input.pdf output.csv
```

The script uses a few simple heuristics to detect lines that look like findings (numbered or containing keywords such as "Finding" or "Vulnerability"). The output CSV contains the detected severity (if the line contains text like `[High]`) and the finding description.

