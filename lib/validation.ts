export const ALLOWED_FILE_TYPES = [
  'text/plain',
  'text/markdown',
  'text/csv',
  'application/json',
  'application/pdf',
  'application/octet-stream',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
]

export const ALLOWED_FILE_EXTENSIONS = [
  '.txt',
  '.md',
  '.log',
  '.csv',
  '.json',
  '.pdf',
  '.docx',
]

export const MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024 // 25MB
export const MIN_TEXT_LENGTH = 50

function getFileExtension(filename: string) {
  const dotIndex = filename.lastIndexOf('.')
  if (dotIndex === -1) return ''
  return filename.slice(dotIndex).toLowerCase()
}

export function validateUploadedFile(file: File) {
  const extension = getFileExtension(file.name)
  const mimeType = String(file.type ?? '').toLowerCase()

  const isAllowedByExtension = ALLOWED_FILE_EXTENSIONS.includes(extension)
  const isAllowedByMime =
    ALLOWED_FILE_TYPES.includes(mimeType) ||
    mimeType.startsWith('text/')

  if (!isAllowedByExtension && !isAllowedByMime) {
    return 'Unsupported file type. Please upload PDF, DOCX, TXT, MD, LOG, CSV, or JSON.'
  }

  if (file.size > MAX_FILE_SIZE_BYTES) {
    return 'File is too large. Maximum allowed size is 25MB.'
  }

  return null
}

export function validateAnalysisText(text: string) {
  const trimmed = text.trim()

  if (!trimmed) {
    return 'Please paste report text or upload a supported file.'
  }

  if (trimmed.length < MIN_TEXT_LENGTH) {
    return 'The provided content is too short to analyze.'
  }

  return null
}