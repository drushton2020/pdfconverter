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


## Web Interface

The project now includes a basic Flask web interface. Start the development server with:

```bash
python run.py
```

Then navigate to `http://localhost:5000/` and upload a pentest report PDF. Uploaded files are stored in the `uploads/` directory.

After uploading, you will be redirected to `/review` where the extracted findings are displayed in an editable table. You can add or remove rows and columns, rename the headers, and toggle a debug view that shows the raw text next to the parsed data. A "Save Parsing Rule" button lets you store custom column configurations to the `rules/` directory.
