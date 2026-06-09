export type NavItem = {
  label: string
  href: string
}

export type NavGroup = {
  title: string
  items: NavItem[]
}

export const navGroups: NavGroup[] = [
  {
    title: 'Overview',
    items: [
      { label: 'Dashboard', href: '/dashboard' },
    ],
  },
  {
    title: 'Analysis',
    items: [
      { label: 'Analyze Report', href: '/analyzer' },
      { label: 'Reports', href: '/reports' },
      { label: 'Findings', href: '/results' },
    ],
  },
  {
    title: 'Intelligence',
    items: [
      { label: 'Threat Intel', href: '/threat-intel' },
      { label: 'Knowledge Graph', href: '/graph' },
      { label: 'Attack Paths', href: '/attack-paths' },
      { label: 'Risk Scoring', href: '/risk-scoring' },
      { label: 'Summarization', href: '/summarization' },
    ],
  },
  {
    title: 'Defense',
    items: [
      { label: 'Recommendations', href: '/recommendations' },
      { label: 'WAF Control', href: '/waf-admin-control' },
    ],
  },
  {
    title: 'Output',
    items: [
      { label: 'Export', href: '/export' },
    ],
  },
]

export function isActivePath(pathname: string, href: string) {
  if (href === '/') return pathname === '/'
  if (href === '/dashboard') {
    return pathname === '/dashboard' || pathname === '/dashboard/waf'
  }

  return pathname === href || pathname.startsWith(`${href}/`)
}