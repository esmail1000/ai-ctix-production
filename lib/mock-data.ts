export type Severity = 'Critical' | 'High' | 'Medium' | 'Low'
export type ReportStatus = 'Ready' | 'Reviewed' | 'Pending'
export type FindingStatus = 'Open' | 'In Review' | 'Resolved'

export type Report = {
  id: string
  slug: string
  name: string
  type: 'PDF' | 'DOCX' | 'TXT' | 'HTML'
  uploadedAt: string
  owner: string
  status: ReportStatus
  findings: number
  critical: number
  high: number
  medium: number
  low: number
  summary: string
}
export type Finding = {
  id: string
  slug: string
  reportId: string
  title: string
  cve: string
  severity: Severity
  asset: string
  score: number
  status: FindingStatus
  detectedAt: string
  summary: string
  impact: string
  evidence: string
  remediation: string
  exploitationSteps?: string[]
  reportCvss?: number | null
  reportCvssVector?: string | null
  intelCvss?: number | null
  intelCvssSeverity?: string | null
  intelCvssVector?: string | null
  knownExploited?: boolean
  cisaKev?: boolean
  mispMatches?: number
  exploitAvailable?: boolean
  attackVector?: string | null
  finalRiskScore?: number
  riskBand?: 'Low' | 'Medium' | 'High' | 'Critical'
  riskFactors?: string[]
  recommendations?: string[]
  recommendationSources?: string[]
 provenance?: {
  extractionMethod: 'seed' | 'structured-parser' | 'heuristic-fallback' | 'nlp-hybrid' | 'manual'
  parserConfidence?: number
}
}
export const reports: Report[] = [
  {
    id: 'R-001',
    slug: 'internal-network-pentest-report',
    name: 'Internal Network Pentest Report',
    type: 'PDF',
    uploadedAt: '2026-03-08',
    owner: 'Security Team',
    status: 'Ready',
    findings: 4,
    critical: 1,
    high: 1,
    medium: 1,
    low: 1,
    summary:
      'This report highlights several issues related to authentication, access control, and exposed internal services across critical business assets.',
  },
  {
    id: 'R-002',
    slug: 'web-application-assessment',
    name: 'Web Application Assessment',
    type: 'DOCX',
    uploadedAt: '2026-03-07',
    owner: 'AppSec Team',
    status: 'Reviewed',
    findings: 3,
    critical: 1,
    high: 1,
    medium: 0,
    low: 1,
    summary:
      'The assessment identified weaknesses in input handling, session protections, and error disclosure patterns in internet-facing applications.',
  },
  {
    id: 'R-003',
    slug: 'external-attack-surface-review',
    name: 'External Attack Surface Review',
    type: 'PDF',
    uploadedAt: '2026-03-06',
    owner: 'Threat Exposure Team',
    status: 'Pending',
    findings: 3,
    critical: 0,
    high: 1,
    medium: 1,
    low: 1,
    summary:
      'This review focuses on exposed assets, insecure public configurations, and policy weaknesses affecting the external security posture.',
  },
  {
    id: 'R-004',
    slug: 'cloud-exposure-review',
    name: 'Cloud Exposure Review',
    type: 'PDF',
    uploadedAt: '2026-03-05',
    owner: 'Cloud Security Team',
    status: 'Ready',
    findings: 2,
    critical: 0,
    high: 1,
    medium: 1,
    low: 0,
    summary:
      'The cloud review surfaced permission drift, weak access boundaries, and storage exposure scenarios requiring prioritization.',
  },
]

export const findings: Finding[] = [
  {
    id: 'F-001',
    slug: 'sql-injection-login-endpoint',
    reportId: 'R-002',
    title: 'SQL Injection in Login Endpoint',
    cve: 'CVE-2024-1234',
    severity: 'Critical',
    asset: 'auth.company.com',
    score: 95,
    status: 'Open',
    detectedAt: '2026-03-08',
    summary:
      'Unsanitized input in the login flow may allow attackers to manipulate backend queries and access unauthorized data.',
    impact:
      'This issue may lead to unauthorized data access, authentication bypass, and possible compromise of sensitive application records.',
    evidence:
      'The application accepted crafted payloads in the username field and returned database-related error behavior under malformed input.',
    remediation:
      'Use parameterized queries, validate input server-side, and restrict database permissions for the affected service.',
  },
  {
    id: 'F-002',
    slug: 'privilege-escalation-misconfigured-role',
    reportId: 'R-001',
    title: 'Privilege Escalation via Misconfigured Role',
    cve: 'CVE-2024-5678',
    severity: 'High',
    asset: 'admin.company.com',
    score: 88,
    status: 'In Review',
    detectedAt: '2026-03-08',
    summary:
      'Incorrect access control allows low-privileged users to invoke administrative actions.',
    impact:
      'Attackers with standard accounts may gain elevated permissions and pivot into privileged workflows.',
    evidence:
      'Role mapping checks were bypassed in internal admin endpoints during privilege boundary validation.',
    remediation:
      'Enforce server-side authorization checks, review privilege inheritance, and verify least-privilege role design.',
  },
  {
    id: 'F-003',
    slug: 'weak-password-policy',
    reportId: 'R-003',
    title: 'Weak Password Policy',
    cve: '—',
    severity: 'Medium',
    asset: 'vpn.company.com',
    score: 61,
    status: 'Open',
    detectedAt: '2026-03-07',
    summary:
      'Password policy does not enforce strong length and complexity requirements.',
    impact:
      'Weak credentials increase the likelihood of successful brute-force and credential stuffing attacks.',
    evidence:
      'Testing confirmed short passwords without complexity were accepted for external access accounts.',
    remediation:
      'Require stronger minimum length, block known weak passwords, and add adaptive authentication controls.',
  },
  {
    id: 'F-004',
    slug: 'verbose-error-disclosure',
    reportId: 'R-002',
    title: 'Verbose Error Disclosure',
    cve: '—',
    severity: 'Low',
    asset: 'portal.company.com',
    score: 32,
    status: 'Resolved',
    detectedAt: '2026-03-07',
    summary:
      'The application reveals stack traces and internal paths in error messages.',
    impact:
      'Leaked implementation details can help attackers refine exploit attempts and map internal technologies.',
    evidence:
      'Unhandled exceptions exposed framework traces, path references, and endpoint names in browser responses.',
    remediation:
      'Replace verbose exception output with generic user-safe errors and centralize server-side logging.',
  },
  {
    id: 'F-005',
    slug: 'outdated-apache-server',
    reportId: 'R-001',
    title: 'Outdated Apache Server',
    cve: 'CVE-2023-25690',
    severity: 'High',
    asset: 'web-gateway-02',
    score: 84,
    status: 'Open',
    detectedAt: '2026-03-06',
    summary:
      'An outdated Apache deployment remains exposed with known security weaknesses.',
    impact:
      'Known vulnerabilities in unsupported or outdated versions increase exploitation risk across exposed services.',
    evidence:
      'Banner checks and package inventory confirmed an outdated Apache version with public security advisories.',
    remediation:
      'Upgrade to a supported release, validate module compatibility, and retest exposed routes after patching.',
  },
  {
    id: 'F-006',
    slug: 'public-storage-bucket-exposure',
    reportId: 'R-004',
    title: 'Public Storage Bucket Exposure',
    cve: '—',
    severity: 'High',
    asset: 'storage.company.com',
    score: 86,
    status: 'In Review',
    detectedAt: '2026-03-06',
    summary:
      'Public object permissions expose internal artifacts and operational files.',
    impact:
      'Sensitive cloud data may be viewed or copied without authentication, expanding business and compliance risk.',
    evidence:
      'Anonymous access tests returned internal documents from a cloud object storage bucket.',
    remediation:
      'Restrict bucket ACLs, enable access policies with least privilege, and rotate exposed secrets if necessary.',
  },
  {
    id: 'F-007',
    slug: 'stale-session-tokens',
    reportId: 'R-002',
    title: 'Stale Session Token Lifetime',
    cve: '—',
    severity: 'Low',
    asset: 'app.company.com',
    score: 29,
    status: 'Resolved',
    detectedAt: '2026-03-05',
    summary:
      'User sessions remain valid longer than expected after inactivity.',
    impact:
      'Extended token lifetime raises account takeover risk on shared or compromised endpoints.',
    evidence:
      'Session cookies remained active beyond intended idle timeout during authentication workflow checks.',
    remediation:
      'Shorten token lifetime, enforce idle timeout server-side, and support token revocation on logout.',
  },
  {
    id: 'F-008',
    slug: 'missing-mfa-admin-portal',
    reportId: 'R-004',
    title: 'Missing MFA on Admin Portal',
    cve: '—',
    severity: 'Medium',
    asset: 'admin.cloud.company.com',
    score: 69,
    status: 'Open',
    detectedAt: '2026-03-05',
    summary:
      'Administrative access is not protected by multi-factor authentication.',
    impact:
      'Single-factor access increases the chance of privileged account compromise from reused or stolen credentials.',
    evidence:
      'Testing confirmed direct admin portal access with username and password only.',
    remediation:
      'Require MFA for administrative roles, monitor high-risk logins, and review access exceptions.',
  },
  {
    id: 'F-009',
    slug: 'exposed-debug-endpoint',
    reportId: 'R-003',
    title: 'Exposed Debug Endpoint',
    cve: '—',
    severity: 'Low',
    asset: 'api.company.com',
    score: 37,
    status: 'Resolved',
    detectedAt: '2026-03-04',
    summary:
      'A publicly reachable debug route exposes runtime metadata and health details.',
    impact:
      'Leaking service internals may help attackers fingerprint dependencies and target attack paths.',
    evidence:
      'A debug route returned environment information and version details over unauthenticated requests.',
    remediation:
      'Disable debug routes in production, restrict internal tooling access, and review deployment defaults.',
  },
  {
    id: 'F-010',
    slug: 'insecure-cors-policy',
    reportId: 'R-001',
    title: 'Insecure CORS Policy',
    cve: '—',
    severity: 'Medium',
    asset: 'portal.company.com',
    score: 58,
    status: 'In Review',
    detectedAt: '2026-03-04',
    summary:
      'The application allows broad cross-origin access beyond trusted origins.',
    impact:
      'Overly permissive CORS settings may expose authenticated endpoints to browser-based abuse.',
    evidence:
      'The response reflected untrusted origins and enabled credentialed requests in test scenarios.',
    remediation:
      'Restrict allowed origins, disable credential sharing where not needed, and validate CORS centrally.',
  },
  {
    id: 'F-011',
    slug: 'open-redirect-in-password-reset',
    reportId: 'R-002',
    title: 'Open Redirect in Password Reset',
    cve: '—',
    severity: 'High',
    asset: 'accounts.company.com',
    score: 77,
    status: 'Open',
    detectedAt: '2026-03-03',
    summary:
      'Password reset flow allows redirection to attacker-controlled destinations.',
    impact:
      'The issue may support phishing and token theft during account recovery workflows.',
    evidence:
      'The return URL parameter accepted external destinations without adequate validation.',
    remediation:
      'Use allowlisted redirect targets and validate all callback destinations server-side.',
  },
  {
    id: 'F-012',
    slug: 'overprivileged-service-account',
    reportId: 'R-004',
    title: 'Overprivileged Service Account',
    cve: '—',
    severity: 'Medium',
    asset: 'ci.company.internal',
    score: 64,
    status: 'Open',
    detectedAt: '2026-03-03',
    summary:
      'A service account retains permissions exceeding its operational requirements.',
    impact:
      'Compromise of the account could grant broad access to sensitive cloud resources and pipelines.',
    evidence:
      'IAM review showed administrative permissions assigned to an automation identity with limited runtime need.',
    remediation:
      'Reduce permissions to required actions only, segment duties, and monitor privilege changes continuously.',
  },
]
