import { execFile } from 'child_process'
import { promises as fs } from 'fs'
import os from 'os'
import path from 'path'

type PythonCandidate = {
  command: string
  prefixArgs: string[]
}

type ExtractionMeta = {
  text: string
  detectedType: 'PDF' | 'DOCX' | 'TXT' | 'HTML'
  extractionMethod?: string
  ocrUsed?: boolean
  warnings?: string[]
}

function stripQuotes(value: string) {
  return value.replace(/^["']|["']$/g, '').trim()
}

function uniqueCandidates(candidates: PythonCandidate[]) {
  const seen = new Set<string>()

  return candidates.filter((candidate) => {
    const key = `${candidate.command}|${candidate.prefixArgs.join(' ')}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

function getPythonCandidates(): PythonCandidate[] {
  const envPython = process.env.NLP_PYTHON
    ? stripQuotes(process.env.NLP_PYTHON)
    : ''

  const projectPythonCmd = path.join(process.cwd(), 'python.cmd')
  const candidates: PythonCandidate[] = []

  if (envPython) {
    candidates.push({ command: envPython, prefixArgs: [] })
  }

  if (process.platform === 'win32') {
    candidates.push({ command: projectPythonCmd, prefixArgs: [] })
    candidates.push({ command: 'py', prefixArgs: ['-3'] })
    candidates.push({ command: 'python', prefixArgs: [] })
  } else {
    candidates.push({ command: 'python3', prefixArgs: [] })
    candidates.push({ command: 'python', prefixArgs: [] })
  }

  return uniqueCandidates(candidates)
}

function execPython(
  candidate: PythonCandidate,
  code: string,
  args: string[]
): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(
      candidate.command,
      [...candidate.prefixArgs, '-c', code, ...args],
      {
        maxBuffer: 120 * 1024 * 1024,
        windowsHide: true,
        timeout: 180_000,
        encoding: 'utf8',
        env: {
          ...process.env,
          PYTHONUTF8: '1',
          PYTHONIOENCODING: 'utf-8',
          PYTHONLEGACYWINDOWSSTDIO: '0',
        },
      },
      (error, stdout, stderr) => {
        if (error) {
          reject(new Error(String(stderr || error.message)))
          return
        }

        resolve(String(stdout || ''))
      }
    )
  })
}

async function runPython(code: string, args: string[]): Promise<string> {
  const errors: string[] = []

  for (const candidate of getPythonCandidates()) {
    try {
      return await execPython(candidate, code, args)
    } catch (error) {
      errors.push(
        `${candidate.command} ${candidate.prefixArgs.join(' ')} failed: ${
          error instanceof Error ? error.message : String(error)
        }`
      )
    }
  }

  throw new Error(
    [
      'Python could not be executed by the text extraction pipeline.',
      'Set NLP_PYTHON in .env.local to your real python.exe path.',
      ...errors,
    ].join('\n')
  )
}

function bufferLooksLikePdf(buffer: Buffer) {
  return buffer.slice(0, 5).toString('utf8') === '%PDF-'
}

async function extractPdfText(filePath: string): Promise<{
  text: string
  method: string
  ocrUsed: boolean
  warnings: string[]
}> {
  const code = String.raw`
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

path = Path(sys.argv[1])
warnings = []

def norm(text: str) -> str:
    text = text or ""
    text = text.replace("\x00", "")
    text = text.replace("\r", "\n")
    text = text.replace("\u00a0", " ")
    text = text.replace("\uf0b7", "- ")
    text = text.replace("\u2022", "- ")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{4,}", "\n\n\n", text)
    return text.strip()

def emit(payload: dict):
    sys.stdout.write(json.dumps(payload, ensure_ascii=True))
    sys.stdout.flush()

def pdfminer_text() -> str:
    try:
        from pdfminer.high_level import extract_text
        return extract_text(str(path)) or ""
    except Exception as exc:
        warnings.append(f"pdfminer failed: {exc}")
        return ""

def pymupdf_text() -> str:
    try:
        import fitz
        doc = fitz.open(str(path))
        pages = []
        for page in doc:
            pages.append(page.get_text("text") or "")
        return "\n".join(pages)
    except Exception as exc:
        warnings.append(f"pymupdf text failed: {exc}")
        return ""

def pdftotext_text() -> str:
    try:
        result = subprocess.run(
            ["pdftotext", "-layout", str(path), "-"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=45,
        )
        if result.returncode == 0:
            return result.stdout.decode("utf-8", "ignore")
        warnings.append("pdftotext failed: " + result.stderr.decode("utf-8", "ignore")[:500])
    except Exception as exc:
        warnings.append(f"pdftotext failed: {exc}")
    return ""

def ocr_text(max_pages: int = 20, scale: float = 1.7) -> str:
    try:
        import os
        import fitz
        import pytesseract
        import io
        from PIL import Image

        tesseract_cmd = os.environ.get("TESSERACT_CMD", "").strip()
        if tesseract_cmd:
            pytesseract.pytesseract.tesseract_cmd = tesseract_cmd
    except Exception as exc:
        warnings.append(
            f"OCR dependencies unavailable: {exc}. Install tesseract + pytesseract + pymupdf + pillow for scanned PDFs."
        )
        return ""

    try:
        doc = fitz.open(str(path))
        matrix = fitz.Matrix(scale, scale)
        pages = min(len(doc), max_pages)
        out = []

        for index in range(pages):
            pix = doc[index].get_pixmap(matrix=matrix, alpha=False)
            img = Image.open(io.BytesIO(pix.tobytes("png")))
            txt = pytesseract.image_to_string(img, lang="eng")
            if txt.strip():
                out.append(f"Page {index + 1}\\n{txt}")

        return "\n\n".join(out)
    except Exception as exc:
        warnings.append(f"OCR failed: {exc}")
        return ""

best_method = "none"
best_text = ""

for method, extractor in (
    ("pdfminer", pdfminer_text),
    ("pymupdf", pymupdf_text),
    ("pdftotext", pdftotext_text),
):
    text = norm(extractor())

    if len(text) > len(best_text):
        best_method = method
        best_text = text

    if len(text) >= 200:
        emit({
            "text": text,
            "method": method,
            "ocrUsed": False,
            "warnings": warnings,
        })
        raise SystemExit(0)

ocr = norm(ocr_text())

if len(ocr) > len(best_text):
    emit({
        "text": ocr,
        "method": "ocr-pymupdf-tesseract",
        "ocrUsed": True,
        "warnings": warnings,
    })
else:
    if len(best_text) < 80:
        warnings.append("PDF appears scanned, image-based, encrypted, or has an empty text layer. OCR did not return enough text.")

    emit({
        "text": best_text,
        "method": best_method,
        "ocrUsed": False,
        "warnings": warnings,
    })
`

  const raw = await runPython(code, [filePath])
  const parsed = JSON.parse(raw) as {
    text?: string
    method?: string
    ocrUsed?: boolean
    warnings?: string[]
  }

  return {
    text: String(parsed.text ?? '').trim(),
    method: parsed.method ?? 'python-pdf',
    ocrUsed: Boolean(parsed.ocrUsed),
    warnings: Array.isArray(parsed.warnings) ? parsed.warnings : [],
  }
}

async function extractDocxText(filePath: string): Promise<{
  text: string
  warnings: string[]
}> {
  const code = String.raw`
from __future__ import annotations

import json
import re
import sys

warnings = []

def norm(text: str) -> str:
    text = text or ""
    text = text.replace("\x00", "")
    text = text.replace("\r", "\n")
    text = text.replace("\u00a0", " ")
    text = text.replace("\uf0b7", "- ")
    text = text.replace("\u2022", "- ")
    text = re.sub(r"\n{4,}", "\n\n\n", text)
    return text.strip()

try:
    from docx import Document
    doc = Document(sys.argv[1])
    parts = []

    for p in doc.paragraphs:
        if p.text and p.text.strip():
            parts.append(p.text.strip())

    for table in doc.tables:
        for row in table.rows:
            row_text = " | ".join(
                cell.text.strip()
                for cell in row.cells
                if cell.text and cell.text.strip()
            )
            if row_text:
                parts.append(row_text)

    text = norm("\n".join(parts))
    sys.stdout.write(json.dumps({"text": text, "warnings": warnings}, ensure_ascii=True))
    sys.stdout.flush()
except Exception as exc:
    warnings.append(f"python-docx failed: {exc}")
    sys.stdout.write(json.dumps({"text": "", "warnings": warnings}, ensure_ascii=True))
    sys.stdout.flush()
`

  const raw = await runPython(code, [filePath])
  const parsed = JSON.parse(raw) as { text?: string; warnings?: string[] }

  return {
    text: String(parsed.text ?? '').trim(),
    warnings: Array.isArray(parsed.warnings) ? parsed.warnings : [],
  }
}

function extractPlainText(buffer: Buffer) {
  return buffer
    .toString('utf8')
    .replace(/\u0000/g, '')
    .replace(/\r/g, '\n')
    .trim()
}

function extractHtmlText(buffer: Buffer) {
  return extractPlainText(buffer)
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<br\s*\/?\s*>/gi, '\n')
    .replace(/<\/(?:p|div|section|article|h[1-6]|li|tr|table)>/gi, '\n')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/g, "'")
    .replace(/[ \t]+/g, ' ')
    .replace(/\n{3,}/g, '\n\n')
    .trim()
}

export async function extractTextFromUpload(
  buffer: Buffer,
  filename: string,
  mimeType?: string
): Promise<ExtractionMeta> {
  const lower = filename.toLowerCase()
  const ext = path.extname(lower)
  const normalizedMime = String(mimeType ?? '').toLowerCase()

  const textExtensions = new Set([
    '.txt',
    '.md',
    '.log',
    '.csv',
    '.json',
    '.xml',
    '.html',
    '.htm',
    '.yml',
    '.yaml',
  ])

  if (
    textExtensions.has(ext) ||
    normalizedMime.startsWith('text/') ||
    normalizedMime.includes('json')
  ) {
    const isHtml = ext === '.html' || ext === '.htm' || normalizedMime.includes('html')

    return {
      text: isHtml ? extractHtmlText(buffer) : extractPlainText(buffer),
      detectedType: isHtml ? 'HTML' : 'TXT',
      extractionMethod: isHtml ? 'html-text' : 'raw-text',
      ocrUsed: false,
      warnings: [],
    }
  }

  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'ctix-'))
  const safeName = path
    .basename(filename)
    .replace(/[<>:"/\\|?*\x00-\x1F]/g, '_')

  const tempFile = path.join(tempDir, safeName || 'upload.bin')

  await fs.writeFile(tempFile, buffer)

  try {
    if (ext === '.pdf' || normalizedMime.includes('pdf') || bufferLooksLikePdf(buffer)) {
      const result = await extractPdfText(tempFile)

      return {
        text: result.text,
        detectedType: 'PDF',
        extractionMethod: result.method,
        ocrUsed: result.ocrUsed,
        warnings: result.warnings,
      }
    }

    if (ext === '.docx' || normalizedMime.includes('wordprocessingml')) {
      const result = await extractDocxText(tempFile)

      return {
        text: result.text,
        detectedType: 'DOCX',
        extractionMethod: 'python-docx',
        ocrUsed: false,
        warnings: result.warnings,
      }
    }

    if (ext === '.doc') {
      return {
        text: '',
        detectedType: 'TXT',
        extractionMethod: 'unsupported-doc',
        ocrUsed: false,
        warnings: [
          'Legacy .doc files are not supported. Convert to .docx, .pdf, or .txt.',
        ],
      }
    }

    return {
      text: extractPlainText(buffer),
      detectedType: 'TXT',
      extractionMethod: 'raw-fallback',
      ocrUsed: false,
      warnings: [],
    }
  } finally {
    await fs.rm(tempDir, { recursive: true, force: true })
  }
}