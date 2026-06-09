export type NavItem = {
  label: string
  href: string
  shortLabel?: string
  eyebrow?: string
  description?: string
}

export type NavGroup = {
  title: string
  description: string
  items: NavItem[]
}

export const navGroups: NavGroup[] = [
  {
    title: 'Command',
    description: 'Platform overview',
    items: [
      {
        label: 'SOC Dashboard',
        shortLabel: 'Dashboard',
        href: '/dashboard',
        eyebrow: 'Overview',
        description: 'Security posture, reports, risk, and recent activity',
      },
    ],
  },
  {
    title: 'Analysis Pipeline',
    description: 'From raw report to structured findings',
    items: [
      {
        label: 'Analyze Report',
        shortLabel: 'Analyze',
        href: '/analyzer',
        eyebrow: 'Ingest',
        description: 'Upload or paste pentesting reports',
      },
      {
        label: 'Reports',
        shortLabel: 'Reports',
        href: '/reports',
        eyebrow: 'Archive',
        description: 'Manage analyzed reports and generated outputs',
      },
      {
        label: 'Findings',
        shortLabel: 'Findings',
        href: '/results',
        eyebrow: 'Extract',
        description: 'Review vulnerabilities, assets, CVEs, and evidence',
      },
    ],
  },
  {
    title: 'Intelligence Layer',
    description: 'Enrichment, relationships, and prediction',
    items: [
      {
        label: 'Threat Intelligence',
        shortLabel: 'Intel',
        href: '/threat-intel',
        eyebrow: 'Enrich',
        description: 'CVE feeds, advisories, exploit signals, and source freshness',
      },
      {
        label: 'Knowledge Graph',
        shortLabel: 'Graph',
        href: '/graph',
        eyebrow: 'Model',
        description: 'Explore relationships between CVEs, assets, techniques, and impact',
      },
      {
        label: 'Attack Paths',
        shortLabel: 'Paths',
        href: '/attack-paths',
        eyebrow: 'Predict',
        description: 'Likely attack chains and compromise routes',
      },
      {
        label: 'Risk Scoring',
        shortLabel: 'Risk',
        href: '/risk-scoring',
        eyebrow: 'Prioritize',
        description: 'Risk score, likelihood, exposure, and confidence',
      },
      {
        label: 'Summarization',
        shortLabel: 'Summary',
        href: '/summarization',
        eyebrow: 'Brief',
        description: 'Executive and technical summaries',
      },
    ],
  },
  {
    title: 'Response',
    description: 'Mitigation and operational control',
    items: [
      {
        label: 'Recommendations',
        shortLabel: 'Actions',
        href: '/recommendations',
        eyebrow: 'Defend',
        description: 'Prioritized remediation and mitigation actions',
      },
      {
        label: 'WAF Control',
        shortLabel: 'WAF',
        href: '/waf-admin-control',
        eyebrow: 'Control',
        description: 'Blocked requests, sessions, and administrative actions',
      },
    ],
  },
  {
    title: 'Delivery',
    description: 'Reports and handoff',
    items: [
      {
        label: 'Export Center',
        shortLabel: 'Export',
        href: '/export',
        eyebrow: 'Output',
        description: 'Export executive, technical, JSON, CSV, and SOC briefs',
      },
    ],
  },
]

export const mobilePrimaryItems: NavItem[] = [
  {
    label: 'Dashboard',
    href: '/dashboard',
  },
  {
    label: 'Analyze',
    href: '/analyzer',
  },
  {
    label: 'Reports',
    href: '/reports',
  },
  {
    label: 'Graph',
    href: '/graph',
  },
]

export function isActivePath(pathname: string, href: string) {
  if (href === '/') return pathname === '/'
  if (href === '/dashboard') return pathname === '/dashboard' || pathname === '/dashboard/waf'
  return pathname === href || pathname.startsWith(`${href}/`)
}

export function getAllNavItems() {
  return navGroups.flatMap((group) => group.items)
}

export function getCurrentNavItem(pathname: string) {
  return getAllNavItems().find((item) => isActivePath(pathname, item.href))
}