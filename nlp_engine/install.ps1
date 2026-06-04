# Install dependencies inside project\.venv
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".venv\Scripts\Activate.ps1")) {
    Write-Host "Creating virtual environment in project\.venv ..."
    python -m venv .venv
}

& ".\.venv\Scripts\Activate.ps1"
python -m pip install --upgrade pip
pip install -r requirements.txt
Write-Host ""
Write-Host "Done. Next: place PDFs in data\pdf, then run:"
Write-Host "  python prepare_data.py --processed_json `"..\processed_reports.json`" --raw_pdf_dir data\pdf"
Write-Host "  python train.py --processed_json `"..\processed_reports.json`" --raw_text_dir data\raw --raw_pdf_dir data\pdf"
