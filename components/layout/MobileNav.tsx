'use client'

import Link from 'next/link'
import { useState } from 'react'
import { isActivePath, mobilePrimaryItems, navGroups } from './navigation-data'

type MobileNavProps = {
  pathname: string
}

export default function MobileNav({ pathname }: MobileNavProps) {
  const [open, setOpen] = useState(false)

  return (
    <>
      <nav
        className="fixed inset-x-0 bottom-0 z-50 border-t border-[#d9eadf] bg-white/95 px-3 py-2 shadow-[0_-18px_42px_rgba(15,43,29,0.12)] backdrop-blur lg:hidden"
        aria-label="Mobile primary navigation"
      >
        <div className="grid grid-cols-5 gap-1">
          {mobilePrimaryItems.map((item) => {
            const active = isActivePath(pathname, item.href)

            return (
              <Link
                key={item.href}
                href={item.href}
                aria-current={active ? 'page' : undefined}
                className={`relative flex min-h-14 items-center justify-center rounded-2xl px-2 text-[11px] font-black transition ${
                  active
                    ? 'bg-[#0f2b1d] text-white shadow-sm'
                    : 'text-[#5a7668] hover:bg-[#edfdf3] hover:text-[#0f2b1d]'
                }`}
              >
                {active ? (
                  <span
                    className="absolute top-1.5 h-1 w-6 rounded-full bg-[#3ee985]"
                    aria-hidden="true"
                  />
                ) : null}

                <span className="pt-1">{item.shortLabel || item.label}</span>
              </Link>
            )
          })}

          <button
            type="button"
            onClick={() => setOpen(true)}
            className="relative flex min-h-14 items-center justify-center rounded-2xl px-2 text-[11px] font-black text-[#5a7668] transition hover:bg-[#edfdf3] hover:text-[#0f2b1d]"
            aria-haspopup="dialog"
            aria-expanded={open}
          >
            More
          </button>
        </div>
      </nav>

      {open ? (
        <div className="fixed inset-0 z-[60] lg:hidden" role="dialog" aria-modal="true">
          <button
            type="button"
            aria-label="Close menu"
            className="absolute inset-0 bg-[#0f2b1d]/45"
            onClick={() => setOpen(false)}
          />

          <div className="absolute inset-x-0 bottom-0 max-h-[86vh] overflow-y-auto rounded-t-[32px] bg-[#fbfffc] shadow-2xl">
            <div className="sticky top-0 z-10 border-b border-[#d9eadf] bg-[#fbfffc]/95 px-5 py-5 backdrop-blur">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-[11px] font-black uppercase tracking-[0.26em] text-[#15803d]">
                    Navigation
                  </p>
                  <h2 className="mt-1 text-xl font-black tracking-tight text-[#0f2b1d]">
                    Command modules
                  </h2>
                  <p className="mt-1 text-sm text-[#6f897b]">
                    Choose the workspace you need.
                  </p>
                </div>

                <button
                  type="button"
                  onClick={() => setOpen(false)}
                  className="rounded-2xl border border-[#d9eadf] bg-white px-4 py-2 text-sm font-black text-[#0f2b1d]"
                  aria-label="Close platform menu"
                >
                  Close
                </button>
              </div>
            </div>

            <div className="space-y-6 px-5 py-5 pb-28">
              {navGroups.map((group, groupIndex) => (
                <section key={group.title}>
                  <div className="mb-3 flex items-end justify-between">
                    <div>
                      <h3 className="text-xs font-black uppercase tracking-[0.2em] text-[#0f2b1d]">
                        {group.title}
                      </h3>
                      <p className="mt-1 text-xs text-[#7a9386]">
                        {group.description}
                      </p>
                    </div>

                    <span className="text-xs font-black tabular-nums text-[#b0c5b9]">
                      {String(groupIndex + 1).padStart(2, '0')}
                    </span>
                  </div>

                  <div className="grid gap-2">
                    {group.items.map((item) => {
                      const active = isActivePath(pathname, item.href)

                      return (
                        <Link
                          key={item.href}
                          href={item.href}
                          onClick={() => setOpen(false)}
                          aria-current={active ? 'page' : undefined}
                          className={`relative rounded-3xl border px-4 py-4 transition ${
                            active
                              ? 'border-[#15803d] bg-[#0f2b1d] text-white shadow-[0_16px_32px_rgba(15,43,29,0.16)]'
                              : 'border-[#d9eadf] bg-white text-[#173128] hover:border-[#b9d8c5]'
                          }`}
                        >
                          <span
                            className={`absolute left-0 top-1/2 h-9 w-1 -translate-y-1/2 rounded-r-full ${
                              active ? 'bg-[#3ee985]' : 'bg-transparent'
                            }`}
                            aria-hidden="true"
                          />

                          <span className="flex items-start justify-between gap-4">
                            <span>
                              {item.eyebrow ? (
                                <span
                                  className={`block text-[10px] font-black uppercase tracking-[0.18em] ${
                                    active ? 'text-[#9df7bd]' : 'text-[#15803d]'
                                  }`}
                                >
                                  {item.eyebrow}
                                </span>
                              ) : null}

                              <span className="mt-1 block text-base font-black tracking-tight">
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
                              className={`mt-1 h-2 w-2 shrink-0 rounded-full ${
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
          </div>
        </div>
      ) : null}
    </>
  )
}