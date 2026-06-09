import { ingestAnalysisReport } from '@/lib/server/analysis-ingest'
import { getCurrentSessionFromCookies } from '@/lib/server/current-session'
import { runPostAnalysisPipeline } from '@/lib/server/pipeline/post-analysis'
import { toPublicFinding, toPublicReport } from '@/lib/server/public-data'
import { extractTextFromUpload } from '@/lib/server/text-extraction'
import { validateAnalysisText, validateUploadedFile } from '@/lib/validation'
import { NextResponse } from 'next/server'

export const dynamic = 'force-dynamic'
export const runtime = 'nodejs'

export async function POST(request: Request) {
  try {
    const session = await getCurrentSessionFromCookies()

    if (!session) {
      return NextResponse.json(
        { error: 'Authentication required.' },
        { status: 401 }
      )
    }

    const formData = await request.formData()
    const text = String(formData.get('text') ?? '').trim()
    const file = formData.get('file') as File | null

    let content = text
    let name = 'Analyzed Report'
    let type: 'PDF' | 'DOCX' | 'TXT' | 'HTML' = 'TXT'
    let sourceFileName: string | undefined

   if (file && file.size > 0) {
  const fileValidationError = validateUploadedFile(file)

  if (fileValidationError) {
    return NextResponse.json(
      { error: fileValidationError },
      { status: 400 }
    )
  }

  const buffer = Buffer.from(await file.arrayBuffer())

  const extracted = await extractTextFromUpload(
    buffer,
    file.name,
    file.type
  )

  const extractedText = String(extracted.text ?? '').trim()

  if (!extractedText) {
    const warnings = extracted.warnings ?? []

    return NextResponse.json(
      {
        error:
          `Could not extract readable text from "${file.name}". ` +
          'The file may be scanned, image-based, encrypted, corrupted, or unsupported. ' +
        'Please upload a text-based PDF/DOCX/HTML/TXT file or paste the report text.',
        extractionMethod: extracted.extractionMethod ?? 'unknown',
        ocrUsed: extracted.ocrUsed ?? false,
        warnings,
        details: warnings.length
          ? warnings.join(' | ')
          : 'No extraction warnings were returned.',
      },
      { status: 400 }
    )
  }

  content = [content, extractedText]
    .filter(Boolean)
    .join('\n\n')
    .trim()

  name = file.name.replace(/\.[^.]+$/, '') || name
  type = extracted.detectedType
  sourceFileName = file.name
}

    const textValidationError = validateAnalysisText(content)

    if (textValidationError) {
      return NextResponse.json(
        { error: textValidationError },
        { status: 400 }
      )
    }

    const result = await ingestAnalysisReport({
      userId: session.userId,
      name,
      type,
      content,
      sourceFileName,
    })

    let postAnalysis: any = null

    try {
      postAnalysis = await runPostAnalysisPipeline(result, session.userId)
    } catch (pipelineError) {
      console.error('Post-analysis pipeline failed:', pipelineError)

      postAnalysis = {
        ok: false,
        reportId: result.report.id,
        error:
          pipelineError instanceof Error
            ? pipelineError.message
            : 'Post-analysis pipeline failed.',
      }
    }

    const graphResult = postAnalysis?.graph

    const graphBuildStatus =
      graphResult?.ok === false
        ? {
            ok: false as const,
            error: String(
              graphResult.error ?? 'Knowledge graph build failed.'
            ),
          }
        : graphResult
          ? {
              ok: true as const,
              reportId: String(graphResult.reportId ?? result.report.id),
              findingsInserted: Number(
                graphResult.findingsInserted ?? result.findings.length
              ),
            }
          : null

    return NextResponse.json({
      report: toPublicReport(result.report),
      findings: result.findings.map(toPublicFinding),
      run: result.run,

      /**
       * Backward compatibility:
       * لو أي جزء قديم في الواجهة بيستخدم graphBuildStatus يفضل شغال.
       */
      graphBuildStatus,

      /**
       * New full automatic pipeline result:
       * الواجهة تقدر تسحب منه Attack Paths / Threat Intel / Scenarios
       * بدون ما المستخدم يفتح API يدوي.
       */
      postAnalysis,
    })
  } catch (error) {
    console.error('Analysis failed:', error)

    return NextResponse.json(
      {
        error:
          error instanceof Error
            ? error.message
            : 'Analysis failed.',
      },
      { status: 500 }
    )
  }
}