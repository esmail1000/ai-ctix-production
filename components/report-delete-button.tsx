'use client'

import { useRef, useState } from 'react'

type ReportDeleteButtonProps = {
  reportId: string
  reportName: string
  findingCount?: number
}

export function ReportDeleteButton({
  reportId,
  reportName,
  findingCount = 0,
}: ReportDeleteButtonProps) {
  const rootRef = useRef<HTMLDivElement | null>(null)
  const [confirming, setConfirming] = useState(false)
  const [isDeleting, setIsDeleting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function deleteReport() {
    if (isDeleting) return

    setIsDeleting(true)
    setError(null)

    try {
      const response = await fetch(`/api/reports/${encodeURIComponent(reportId)}`, {
        method: 'DELETE',
        cache: 'no-store',
        headers: {
          Accept: 'application/json',
        },
      })

      const payload = await response.json().catch(() => ({}))

      if (!response.ok) {
        throw new Error(
          typeof payload?.error === 'string'
            ? payload.error
            : 'Failed to delete report.'
        )
      }

      const reportCard = rootRef.current?.closest('article')

      if (reportCard instanceof HTMLElement) {
        reportCard.style.pointerEvents = 'none'
        reportCard.style.transition = 'opacity 180ms ease, transform 180ms ease'
        reportCard.style.opacity = '0'
        reportCard.style.transform = 'scale(0.98)'

        window.setTimeout(() => {
          reportCard.remove()
        }, 190)
      } else {
        setConfirming(false)
      }
    } catch (deleteError) {
      setError(
        deleteError instanceof Error
          ? deleteError.message
          : 'Failed to delete report.'
      )
      setIsDeleting(false)
    }
  }

  if (confirming) {
    return (
      <div
        ref={rootRef}
        className="w-full rounded-2xl border border-[#fecaca] bg-[#fff7f7] p-3 sm:w-auto"
        onClick={(event) => {
          event.preventDefault()
          event.stopPropagation()
        }}
      >
        <p className="max-w-[260px] text-xs font-semibold leading-5 text-[#991b1b]">
          Delete “{reportName}” and {findingCount.toLocaleString()} linked finding(s)?
        </p>

        {error ? (
          <p className="mt-2 max-w-[260px] text-xs font-semibold leading-5 text-[#dc2626]">
            {error}
          </p>
        ) : null}

        <div className="mt-3 flex flex-wrap gap-2">
          <button
            type="button"
            onClick={(event) => {
              event.preventDefault()
              event.stopPropagation()
              setConfirming(false)
              setError(null)
            }}
            disabled={isDeleting}
            className="rounded-xl border border-[#dceee3] bg-white px-3 py-2 text-xs font-semibold text-[#44554b] transition hover:bg-[#f4fff7] disabled:cursor-not-allowed disabled:opacity-60"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={(event) => {
              event.preventDefault()
              event.stopPropagation()
              void deleteReport()
            }}
            disabled={isDeleting}
            className="rounded-xl bg-[#dc2626] px-3 py-2 text-xs font-semibold text-white transition hover:bg-[#b91c1c] disabled:cursor-not-allowed disabled:opacity-60"
          >
            {isDeleting ? 'Deleting...' : 'Confirm delete'}
          </button>
        </div>
      </div>
    )
  }

  return (
    <div ref={rootRef} className="inline-flex">
      <button
        type="button"
        onClick={(event) => {
          event.preventDefault()
          event.stopPropagation()
          setError(null)
          setConfirming(true)
        }}
        disabled={isDeleting}
        className="rounded-xl border border-[#fecaca] bg-[#fff7f7] px-3 py-2 text-xs font-semibold text-[#dc2626] transition hover:-translate-y-0.5 hover:border-[#fca5a5] hover:bg-[#fff1f2] disabled:cursor-not-allowed disabled:opacity-60"
      >
        Delete
      </button>
    </div>
  )
}
