'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'

const pathLabels: Record<string, string> = {
  '/dashboard': 'SOC Dashboard',
  '/dashboard/waf': 'WAF Dashboard',
  '/analyzer': 'Analyze Report',
  '/reports': 'Reports',
  '/results': 'Findings',
  '/graph': 'Knowledge Graph',
  '/attack-paths': 'Attack Paths',
  '/risk-scoring': 'Risk Scoring',
  '/summarization': 'Summarization',
  '/threat-intel': 'Threat Intel',
  '/recommendations': 'Recommendations',
  '/waf-admin-control': 'WAF Control',
  '/export': 'Export Center',
}

function prettify(segment: string) {
  return segment
    .replace(/-/g, ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase())
}

function getDynamicLabel(previousSegment?: string) {
  if (previousSegment === 'reports') return 'Report Details'
  if (previousSegment === 'results') return 'Finding Details'
  if (previousSegment === 'graph') return 'Report Graph'
  return 'Details'
}

export default function Breadcrumbs() {
  const pathname = usePathname()

  const ignoredRoutes = [
    '/',
    '/login',
    '/register',
    '/forgot-password',
    '/reset-password',
    '/check-email',
  ]

  if (ignoredRoutes.includes(pathname)) return null

  const segments = pathname.split('/').filter(Boolean)
  if (!segments.length) return null

  return (
    <nav aria-label="Breadcrumb" className="hidden text-sm text-[#5a7668] sm:block">
      <ol className="flex flex-wrap items-center gap-2">
        <li>
          <Link href="/dashboard" className="font-medium hover:text-[#15803d]">
            Platform
          </Link>
        </li>

        {segments.map((segment, index) => {
          const href = `/${segments.slice(0, index + 1).join('/')}`
          const isLast = index === segments.length - 1
          const isLikelyId = /^[a-zA-Z0-9_-]{12,}$/.test(segment) || /^\d+$/.test(segment)

          const label =
            pathLabels[href] ||
            (isLikelyId ? getDynamicLabel(segments[index - 1]) : prettify(segment))

          return (
            <li key={href} className="flex items-center gap-2">
              <span aria-hidden="true" className="text-[#9db2a6]">
                /
              </span>

              {isLast ? (
                <span className="font-semibold text-[#173128]" aria-current="page">
                  {label}
                </span>
              ) : (
                <Link href={href} className="font-medium hover:text-[#15803d]">
                  {label}
                </Link>
              )}
            </li>
          )
        })}
      </ol>
    </nav>
  )
}