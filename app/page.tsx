// app/page.tsx
import Link from 'next/link'

const stats = [
  { value: '50K+', label: 'Reports analyzed' },
  { value: '2.4M+', label: 'Indicators extracted' },
  { value: '98.6%', label: 'Detection accuracy' },
  { value: '24/7', label: 'Threat monitoring' },
]

const features = [
  {
    title: 'Threat Intelligence',
    description: 'AI-curated intelligence, IOCs, entities, and actionable threat signals.',
    visual: 'stack',
  },
  {
    title: 'Smart Extraction',
    description: 'Extract findings, assets, CVEs, MITRE techniques, and evidence with precision.',
    visual: 'cube',
  },
  {
    title: 'Attack Graph',
    description: 'Visualize relationships, attack paths, assets, and risk dependencies.',
    visual: 'graph',
  },
  {
    title: 'Export & Reports',
    description: 'Generate clean reports and structured outputs for analysts and teams.',
    visual: 'report',
  },
]

export default function HomePage() {
  return (
    <main className="relative min-h-screen overflow-hidden bg-[#fbfefd] text-[#102019]">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_70%_18%,rgba(34,197,94,0.16),transparent_30%),radial-gradient(circle_at_20%_78%,rgba(16,185,129,0.10),transparent_34%)]" />
      <div className="pointer-events-none absolute bottom-0 left-0 right-0 h-72 opacity-70">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_100%,rgba(34,197,94,0.18),transparent_34%),radial-gradient(circle_at_90%_100%,rgba(6,120,58,0.13),transparent_36%)]" />
        <div className="absolute inset-x-0 bottom-0 h-44 bg-[linear-gradient(135deg,rgba(8,122,58,0.08)_25%,transparent_25%,transparent_50%,rgba(8,122,58,0.08)_50%,rgba(8,122,58,0.08)_75%,transparent_75%,transparent)] bg-[length:22px_22px] opacity-25" />
      </div>

      <section className="relative mx-auto max-w-[1520px] px-6 pb-16 pt-14 lg:px-10">
        <div className="grid min-h-[650px] items-center gap-12 xl:grid-cols-[0.9fr_1.1fr]">
          <div className="relative z-10">
            <div className="inline-flex items-center gap-3 rounded-full border border-[#c9ead5] bg-white/90 px-4 py-2 text-xs font-semibold uppercase tracking-[0.18em] text-[#087a3a] shadow-sm">
              <span className="relative flex h-2.5 w-2.5">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-[#16a34a] opacity-30" />
                <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-[#16a34a]" />
              </span>
              AI-powered cyber threat analysis
            </div>

            <h1 className="mt-8 max-w-3xl text-6xl font-semibold leading-[0.98] tracking-[-0.055em] text-[#13251c] md:text-7xl">
              Welcome to
              <span className="mt-3 block bg-gradient-to-r from-[#087a3a] via-[#16a34a] to-[#0f6c3a] bg-clip-text text-transparent">
                AI CTIX
              </span>
            </h1>

            <p className="mt-7 max-w-xl text-xl font-medium text-[#087a3a]">
              AI-powered cyber threat analysis
            </p>

            <p className="mt-4 max-w-2xl text-lg leading-8 text-[#5d6f66]">
              Extract, analyze, and visualize cyber threats with AI-driven insights,
              attack relationships, risk scoring, and executive-ready intelligence.
            </p>

            <div className="mt-9 flex flex-wrap gap-4">
              <Link
                href="/analyzer"
                className="group inline-flex items-center justify-center rounded-2xl bg-[#087a3a] px-6 py-4 text-sm font-semibold text-white shadow-[0_22px_40px_rgba(8,122,58,0.22)] transition duration-300 hover:-translate-y-1 hover:bg-[#066b33]"
              >
                Analyze Report
                <span className="ml-3 transition duration-300 group-hover:translate-x-1">→</span>
              </Link>

              <Link
                href="/dashboard"
                className="inline-flex items-center justify-center rounded-2xl border border-[#b8dec7] bg-white/90 px-6 py-4 text-sm font-semibold text-[#087a3a] shadow-sm transition duration-300 hover:-translate-y-1 hover:bg-[#f4fff7]"
              >
                View Dashboard
              </Link>

              <Link
                href="/reports"
                className="inline-flex items-center justify-center rounded-2xl border border-[#d8eee0] bg-white/70 px-6 py-4 text-sm font-semibold text-[#315242] shadow-sm transition duration-300 hover:-translate-y-1 hover:bg-white"
              >
                Explore Platform
              </Link>
            </div>

            <div className="mt-8 flex flex-wrap items-center gap-4 text-sm text-[#66786e]">
              <span className="h-2 w-2 rounded-full bg-[#16a34a]" />
              Trusted workspace for turning cyber reports into actionable intelligence.
            </div>
          </div>

          <div className="relative min-h-[590px]">
            <div className="absolute left-1/2 top-1/2 h-[470px] w-[470px] -translate-x-1/2 -translate-y-1/2 rounded-full bg-[#dff7e8] blur-3xl" />
            <div className="absolute left-1/2 top-1/2 h-[520px] w-[700px] -translate-x-1/2 -translate-y-1/2 rounded-full border border-[#b9e5c7]/80 opacity-70 ai-orbit" />
            <div className="absolute left-1/2 top-1/2 h-[360px] w-[580px] -translate-x-1/2 -translate-y-1/2 rounded-full border border-[#d6efdf] opacity-90 ai-orbit-reverse" />

            <div className="absolute left-1/2 top-1/2 z-20 h-[300px] w-[420px] -translate-x-1/2 -translate-y-1/2 ai-float-slow">
              <div className="absolute inset-x-10 bottom-0 h-24 rounded-[50%] bg-[#0d7a3d]/15 blur-2xl" />
              <div className="absolute left-1/2 top-[54%] h-28 w-[330px] -translate-x-1/2 rounded-[50%] border border-[#9de0b3] bg-white/70 shadow-[0_30px_80px_rgba(8,122,58,0.18)]" />
              <div className="absolute left-1/2 top-[45%] h-32 w-[370px] -translate-x-1/2 rounded-[50%] border border-[#c4ead0] bg-gradient-to-b from-white to-[#eefaf3] shadow-[0_30px_80px_rgba(8,122,58,0.12)]" />
              <div className="absolute left-1/2 top-[20%] h-56 w-48 -translate-x-1/2 rounded-[38px] border border-white/70 bg-gradient-to-br from-white via-[#dff6e8] to-[#087a3a] shadow-[0_30px_80px_rgba(8,122,58,0.22)] [transform:perspective(900px)_rotateX(10deg)_rotateY(-10deg)]">
                <div className="absolute inset-4 rounded-[30px] border border-white/60 bg-gradient-to-br from-[#16a34a] to-[#075d31] shadow-inner" />
                <div className="absolute left-1/2 top-1/2 h-20 w-20 -translate-x-1/2 -translate-y-1/2 rounded-full border-4 border-white/80">
                  <div className="absolute left-1/2 top-[-20px] h-8 w-1 -translate-x-1/2 rounded-full bg-white/80" />
                  <div className="absolute bottom-[-20px] left-1/2 h-8 w-1 -translate-x-1/2 rounded-full bg-white/80" />
                  <div className="absolute left-[-20px] top-1/2 h-1 w-8 -translate-y-1/2 rounded-full bg-white/80" />
                  <div className="absolute right-[-20px] top-1/2 h-1 w-8 -translate-y-1/2 rounded-full bg-white/80" />
                </div>
              </div>
            </div>

            <FloatingPanel className="left-[4%] top-[8%] w-[220px] ai-float">
              <p className="text-xs font-semibold text-[#49665a]">Threat overview</p>
              <div className="mt-3 flex items-center gap-4">
                <Ring value={72} />
                <div>
                  <p className="text-2xl font-semibold text-[#14251c]">1,248</p>
                  <p className="text-xs text-[#708076]">Total indicators</p>
                  <p className="mt-1 text-sm font-semibold text-[#087a3a]">+18.6%</p>
                </div>
              </div>
            </FloatingPanel>

            <FloatingPanel className="left-[1%] top-[32%] w-[250px] ai-float-delay">
              <p className="text-xs font-semibold text-[#49665a]">Top threat types</p>
              <ThreatBar label="Malware" value="42%" width="75%" />
              <ThreatBar label="Phishing" value="28%" width="62%" />
              <ThreatBar label="C2 activity" value="18%" width="48%" />
              <ThreatBar label="Exploit" value="12%" width="34%" />
            </FloatingPanel>

            <FloatingPanel className="left-[14%] bottom-[18%] w-[190px] ai-float-slow">
              <p className="text-xs font-semibold text-[#49665a]">Risk score</p>
              <div className="mt-3 flex items-center gap-3">
                <Ring value={82} compact />
                <div>
                  <p className="text-lg font-semibold text-[#14251c]">82</p>
                  <p className="text-xs font-semibold text-orange-600">High</p>
                </div>
              </div>
              <p className="mt-3 text-xs text-[#087a3a]">+12 from last scan</p>
            </FloatingPanel>

            <FloatingPanel className="right-[4%] top-[12%] w-[300px] ai-float-delay">
              <p className="text-xs font-semibold text-[#49665a]">Attack graph</p>
              <MiniGraph />
            </FloatingPanel>

            <FloatingPanel className="right-[5%] top-[42%] w-[260px] ai-float">
              <p className="text-xs font-semibold text-[#49665a]">Recent findings</p>
              <FindingLine label="Suspicious IP 192.168.1.45" severity="High" />
              <FindingLine label="Malware hash a1b2c3d4..." severity="Medium" />
              <FindingLine label="Phishing domain evil-site.com" severity="High" />
            </FloatingPanel>

            <FloatingPanel className="right-[15%] bottom-[12%] w-[250px] ai-float-slow">
              <p className="text-xs font-semibold text-[#49665a]">AI insight</p>
              <p className="mt-2 text-sm leading-6 text-[#66786e]">
                This report contains indicators of command and control activity with high confidence.
              </p>
              <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-[#e1f2e7]">
                <div className="h-full w-[92%] rounded-full bg-[#087a3a]" />
              </div>
              <p className="mt-2 text-xs font-semibold text-[#087a3a]">Confidence: 92%</p>
            </FloatingPanel>

            <div className="absolute right-[7%] bottom-[30%] h-16 w-16 rounded-2xl border border-white/70 bg-gradient-to-br from-[#dcf8e6] to-[#9ce4b7] shadow-[0_20px_50px_rgba(8,122,58,0.16)] ai-cube" />
            <div className="absolute left-[18%] bottom-[34%] h-10 w-10 rounded-xl border border-white/70 bg-gradient-to-br from-[#eefaf3] to-[#b8eccc] shadow-[0_20px_50px_rgba(8,122,58,0.16)] ai-cube-delay" />
          </div>
        </div>

        <section className="relative z-10 -mt-2 rounded-[30px] border border-[#dceee3] bg-white/90 p-6 shadow-[0_26px_70px_rgba(15,43,29,0.08)] backdrop-blur">
          <div className="grid gap-6 md:grid-cols-4">
            {stats.map((item) => (
              <div key={item.label} className="border-[#e6f3eb] px-3 md:border-r last:md:border-r-0">
                <p className="text-3xl font-semibold tracking-tight text-[#14251c]">{item.value}</p>
                <p className="mt-1 text-sm text-[#66786e]">{item.label}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="relative z-10 mt-7 grid gap-5 md:grid-cols-2 xl:grid-cols-4">
          {features.map((feature) => (
            <article
              key={feature.title}
              className="group relative min-h-[230px] overflow-hidden rounded-[30px] border border-[#dceee3] bg-white p-6 shadow-[0_22px_60px_rgba(15,43,29,0.06)] transition duration-300 hover:-translate-y-2 hover:shadow-[0_30px_80px_rgba(15,43,29,0.11)]"
            >
              <div className="absolute right-5 top-7 h-24 w-24 rounded-[28px] bg-[#e5f7ec] shadow-[inset_0_-12px_25px_rgba(8,122,58,0.10)] [transform:perspective(700px)_rotateX(58deg)_rotateZ(-35deg)] transition duration-500 group-hover:rotate-6" />
              <div className="absolute right-12 top-12 h-10 w-10 rounded-xl bg-[#a9e9bd]/70 blur-sm" />

              <p className="relative text-xl font-semibold text-[#14251c]">{feature.title}</p>
              <p className="relative mt-4 max-w-[230px] text-sm leading-7 text-[#66786e]">{feature.description}</p>

              <Link
                href={feature.title === 'Attack Graph' ? '/graph' : feature.title === 'Export & Reports' ? '/export' : '/dashboard'}
                className="relative mt-6 inline-flex text-sm font-semibold text-[#087a3a]"
              >
                Learn more →
              </Link>
            </article>
          ))}
        </section>
      </section>

      <style>{`
        @keyframes ai-float {
          0%, 100% { transform: translateY(0px) rotate(0deg); }
          50% { transform: translateY(-14px) rotate(1deg); }
        }

        @keyframes ai-orbit {
          0% { transform: translate(-50%, -50%) rotate(0deg); }
          100% { transform: translate(-50%, -50%) rotate(360deg); }
        }

        @keyframes ai-orbit-reverse {
          0% { transform: translate(-50%, -50%) rotate(360deg); }
          100% { transform: translate(-50%, -50%) rotate(0deg); }
        }

        @keyframes ai-cube {
          0%, 100% { transform: translateY(0px) rotate(0deg); }
          50% { transform: translateY(-18px) rotate(12deg); }
        }

        .ai-float { animation: ai-float 5.2s ease-in-out infinite; }
        .ai-float-delay { animation: ai-float 6.4s ease-in-out infinite; animation-delay: -1.2s; }
        .ai-float-slow { animation: ai-float 7.6s ease-in-out infinite; animation-delay: -0.6s; }
        .ai-orbit { animation: ai-orbit 26s linear infinite; }
        .ai-orbit-reverse { animation: ai-orbit-reverse 34s linear infinite; }
        .ai-cube { animation: ai-cube 6s ease-in-out infinite; }
        .ai-cube-delay { animation: ai-cube 7s ease-in-out infinite; animation-delay: -1.4s; }
      `}</style>
    </main>
  )
}

function FloatingPanel({
  className,
  children,
}: {
  className: string
  children: React.ReactNode
}) {
  return (
    <div
      className={`absolute z-30 rounded-[24px] border border-[#cfe8d8] bg-white/86 p-4 shadow-[0_24px_70px_rgba(15,43,29,0.13)] backdrop-blur-xl ${className}`}
    >
      {children}
    </div>
  )
}

function Ring({ value, compact = false }: { value: number; compact?: boolean }) {
  const size = compact ? 'h-14 w-14' : 'h-16 w-16'
  const inner = compact ? 'h-9 w-9' : 'h-11 w-11'

  return (
    <div
      className={`grid place-items-center rounded-full ${size}`}
      style={{
        background: `conic-gradient(#087a3a ${value * 3.6}deg, #e5f4eb 0deg)`,
      }}
    >
      <div className={`grid place-items-center rounded-full bg-white ${inner}`}>
        <span className="text-sm font-semibold text-[#14251c]">{compact ? value : ''}</span>
      </div>
    </div>
  )
}

function ThreatBar({
  label,
  value,
  width,
}: {
  label: string
  value: string
  width: string
}) {
  return (
    <div className="mt-3 grid grid-cols-[70px_1fr_40px] items-center gap-3 text-xs text-[#66786e]">
      <span>{label}</span>
      <span className="h-2 overflow-hidden rounded-full bg-[#e6f4eb]">
        <span className="block h-full rounded-full bg-[#087a3a]" style={{ width }} />
      </span>
      <span className="text-right font-semibold">{value}</span>
    </div>
  )
}

function FindingLine({ label, severity }: { label: string; severity: 'High' | 'Medium' }) {
  return (
    <div className="mt-3 flex items-center justify-between gap-3 text-xs">
      <span className="truncate text-[#66786e]">{label}</span>
      <span
        className={`rounded-full px-2 py-1 font-semibold ${
          severity === 'High' ? 'bg-red-50 text-red-600' : 'bg-orange-50 text-orange-600'
        }`}
      >
        {severity}
      </span>
    </div>
  )
}

function MiniGraph() {
  return (
    <svg viewBox="0 0 220 105" className="mt-3 h-[110px] w-full">
      <line x1="110" y1="52" x2="48" y2="35" stroke="#9cb6aa" />
      <line x1="110" y1="52" x2="76" y2="78" stroke="#9cb6aa" />
      <line x1="110" y1="52" x2="150" y2="32" stroke="#9cb6aa" />
      <line x1="110" y1="52" x2="172" y2="70" stroke="#9cb6aa" />
      <circle cx="110" cy="52" r="12" fill="#087a3a" />
      <circle cx="48" cy="35" r="7" fill="#dff7e8" stroke="#087a3a" strokeWidth="2" />
      <circle cx="76" cy="78" r="7" fill="#dff7e8" stroke="#087a3a" strokeWidth="2" />
      <circle cx="150" cy="32" r="7" fill="#dff7e8" stroke="#087a3a" strokeWidth="2" />
      <circle cx="172" cy="70" r="7" fill="#fee2e2" stroke="#ef4444" strokeWidth="2" />
      <circle cx="110" cy="52" r="4" fill="white" />
    </svg>
  )
}
