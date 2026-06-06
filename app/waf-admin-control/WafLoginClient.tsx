'use client'

import { FormEvent, useState } from 'react'

export default function WafLoginClient() {
  const [token, setToken] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setLoading(true)
    setError('')

    try {
      const res = await fetch('/api/admin/waf/session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(data.error || 'Invalid owner token.')
      window.location.reload()
    } catch (err: any) {
      setError(err.message || 'Invalid owner token.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="min-h-screen bg-[#f7fbf8] px-6 py-10 text-[#0d2217]">
      <section className="mx-auto flex min-h-[70vh] max-w-xl items-center justify-center">
        <form onSubmit={submit} className="w-full rounded-[2rem] border border-emerald-100 bg-white p-7 shadow-sm">
          <p className="text-sm font-semibold uppercase tracking-[0.2em] text-emerald-700">Owner Access</p>
          <h1 className="mt-2 text-3xl font-semibold tracking-tight text-[#0f2b1d]">WAF Control Center</h1>
          <p className="mt-3 text-sm leading-6 text-[#5a7668]">This area is separate from normal user accounts. Enter the owner token to create a short admin session.</p>

          <label className="mt-6 block text-xs font-semibold uppercase tracking-[0.16em] text-[#5a7668]">Owner Token</label>
          <input
            value={token}
            onChange={(event) => setToken(event.target.value)}
            type="password"
            autoComplete="off"
            placeholder="Paste WAF_ADMIN_TOKEN"
            className="mt-3 w-full rounded-xl border border-[#cbe8d6] bg-white px-4 py-3 text-sm outline-none focus:border-emerald-500 focus:ring-2 focus:ring-emerald-100"
          />

          {error ? <div className="mt-4 rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm font-medium text-red-700">{error}</div> : null}

          <button disabled={loading || !token} className="mt-5 w-full rounded-xl bg-[#15803d] px-4 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-[#166534] disabled:opacity-60">
            {loading ? 'Checking...' : 'Open Owner Console'}
          </button>
        </form>
      </section>
    </main>
  )
}
