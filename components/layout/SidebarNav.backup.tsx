'use client'

import Link from 'next/link'
import { isActivePath, navGroups } from './navigation-data'

type SidebarNavProps = {
  pathname: string
  userName?: string
  onLogout: () => void
}

export default function SidebarNav({ pathname, userName, onLogout }: SidebarNavProps) {
  return (
    <aside className="hidden lg:fixed lg:inset-y-0 lg:left-0 lg:z-40 lg:flex lg:w-[19rem] lg:flex-col lg:border-r lg:border-[#d9eadf] lg:bg-[#fbfffc]">
      <div className="border-b border-[#d9eadf] px-6 py-6">
        <Link href="/dashboard" className="block" aria-label="AI CTIX Dashboard">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-[11px] font-black uppercase tracking-[0.28em] text-[#15803d]">
                AI CTIX
              </p>
              <h1 className="mt-2 text-xl font-black tracking-tight text-[#0d2217]">
                Command Workspace
              </h1>
            </div>

            <div className="h-3 w-3 rounded-full bg-[#15803d] shadow-[0_0_0_6px_rgba(21,128,61,0.12)]" />
          </div>

          <p className="mt-4 text-sm leading-6 text-[#5a7668]">
            Cyber threat intelligence extraction, analysis, graphing, and response.
          </p>
        </Link>
      </div>

      <nav className="flex-1 overflow-y-auto px-4 py-5" aria-label="Platform navigation">
        <div className="space-y-6">
          {navGroups.map((group, groupIndex) => (
            <section key={group.title}>
              <div className="mb-3 flex items-end justify-between px-2">
                <div>
                  <h2 className="text-xs font-black uppercase tracking-[0.2em] text-[#0f2b1d]">
                    {group.title}
                  </h2>
                  <p className="mt-1 text-[11px] font-medium text-[#7a9386]">
                    {group.description}
                  </p>
                </div>

                <span className="text-[11px] font-black tabular-nums text-[#b0c5b9]">
                  {String(groupIndex + 1).padStart(2, '0')}
                </span>
              </div>

              <div className="space-y-1.5">
                {group.items.map((item) => {
                  const active = isActivePath(pathname, item.href)

                  return (
                    <Link
                      key={item.href}
                      href={item.href}
                      aria-current={active ? 'page' : undefined}
                      className={`relative block rounded-2xl border px-4 py-3.5 transition ${
                        active
                          ? 'border-[#15803d] bg-[#0f2b1d] text-white shadow-[0_18px_36px_rgba(15,43,29,0.16)]'
                          : 'border-transparent bg-transparent text-[#173128] hover:border-[#d9eadf] hover:bg-white hover:shadow-sm'
                      }`}
                    >
                      <span
                        className={`absolute left-0 top-1/2 h-8 w-1 -translate-y-1/2 rounded-r-full ${
                          active ? 'bg-[#3ee985]' : 'bg-transparent'
                        }`}
                        aria-hidden="true"
                      />

                      <span className="flex items-start justify-between gap-4">
                        <span className="min-w-0">
                          {item.eyebrow ? (
                            <span
                              className={`block text-[10px] font-black uppercase tracking-[0.18em] ${
                                active ? 'text-[#9df7bd]' : 'text-[#15803d]'
                              }`}
                            >
                              {item.eyebrow}
                            </span>
                          ) : null}

                          <span className="mt-1 block truncate text-sm font-black tracking-tight">
                            {item.label}
                          </span>

                          {item.description ? (
                            <span
                              className={`mt-1.5 block text-xs leading-5 ${
                                active ? 'text-white/70' : 'text-[#6f897b]'
                              }`}
                            >
                              {item.description}
                            </span>
                          ) : null}
                        </span>

                        <span
                          className={`mt-0.5 h-2 w-2 shrink-0 rounded-full ${
                            active ? 'bg-[#3ee985]' : 'bg-[#c7dbd0]'
                          }`}
                          aria-hidden="true"
                        />
                      </span>
                    </Link>
                  )
                })}
              </div>
            </section>
          ))}
        </div>
      </nav>

      <div className="border-t border-[#d9eadf] p-4">
        <div className="rounded-3xl border border-[#d9eadf] bg-white p-4 shadow-sm">
          <p className="text-[10px] font-black uppercase tracking-[0.2em] text-[#7a9386]">
            Active analyst
          </p>

          <p className="mt-2 truncate text-sm font-black text-[#0f2b1d]">
            {userName || 'Analyst'}
          </p>

          <button
            type="button"
            onClick={onLogout}
            className="mt-4 w-full rounded-2xl border border-[#f2c4c4] bg-[#fff7f7] px-4 py-2.5 text-sm font-black text-[#b42318] transition hover:bg-[#ffecec]"
          >
            Sign out
          </button>
        </div>
      </div>
    </aside>
  )
}