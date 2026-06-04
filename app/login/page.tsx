'use client'

import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { useState, type FormEvent } from 'react'

export default function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const router = useRouter()

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    setLoading(true)

    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || 'Login failed')
      }

      router.push('/')
      router.refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong')
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="relative min-h-screen overflow-hidden bg-[#fbfefd] text-[#111827]">

      <style>{`
        @keyframes auth-orbit-spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        @keyframes auth-logo-float { 0%, 100% { transform: translateY(0) rotate(0deg); } 50% { transform: translateY(-12px) rotate(2deg); } }
        .auth-orbit { animation: auth-orbit-spin 15s linear infinite; }
        .auth-orbit > div:first-child { animation: auth-logo-float 6s ease-in-out infinite; }
        .auth-platform { transform: perspective(800px) rotateX(58deg); }
      `}</style>
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_18%_10%,rgba(34,197,94,0.10),transparent_30%),radial-gradient(circle_at_86%_18%,rgba(8,122,58,0.08),transparent_34%)]" />
      <div className="pointer-events-none absolute right-0 top-24 h-[420px] w-[560px] rounded-full bg-[#dcf7e7]/60 blur-3xl" />
      <div className="pointer-events-none absolute left-0 top-[560px] h-[320px] w-[520px] rounded-full bg-[#eefaf3] blur-3xl" />

      <section className="relative mx-auto grid min-h-screen max-w-[1280px] items-center gap-8 px-6 py-10 lg:grid-cols-[1fr_480px] lg:px-8">
        <div className="hidden lg:block">
          <p className="text-xs font-semibold uppercase tracking-[0.22em] text-[#087a3a]">
            AI CTIX Workspace
          </p>
          <h1 className="mt-4 max-w-3xl text-5xl font-semibold tracking-[-0.05em] text-[#0d2217]">
            Secure access to your cyber intelligence command center
          </h1>
          <p className="mt-5 max-w-2xl text-base leading-8 text-[#5f6f66]">
            Sign in to review reports, findings, risk scoring, summaries, graph analysis, and export packages.
          </p>

          <div className="relative mt-10 h-[260px] max-w-[520px] rounded-[34px] border border-[#dceee3] bg-white/82 p-6 shadow-[0_24px_80px_rgba(15,43,29,0.07)] backdrop-blur">
            <div className="pointer-events-none absolute right-14 bottom-10 h-20 w-52 rounded-[50%] border border-[#bfe6cc] bg-gradient-to-b from-white to-[#e5f8ec] shadow-[0_24px_60px_rgba(8,122,58,0.12)] auth-platform" />
            <div className="pointer-events-none absolute right-20 top-8 h-28 w-28 rounded-full border border-[#c7efd4] bg-white/70 shadow-[0_22px_55px_rgba(8,122,58,0.12)] auth-orbit">
              <div className="absolute left-1/2 top-1/2 h-14 w-14 -translate-x-1/2 -translate-y-1/2 rounded-full bg-gradient-to-br from-[#dff7e8] to-[#087a3a] shadow-[0_18px_45px_rgba(8,122,58,0.18)]" />
              <div className="absolute left-1/2 top-1/2 h-5 w-5 -translate-x-1/2 -translate-y-[58px] rounded-full bg-[#087a3a] shadow-[0_12px_28px_rgba(8,122,58,0.20)]" />
            </div>

            <div className="relative max-w-[280px]">
              <p className="text-sm font-semibold text-[#087a3a]">Authentication gateway</p>
              <p className="mt-3 text-sm leading-7 text-[#5a7668]">
                The UI update only changes this client page. The login request still goes to the existing backend route.
              </p>
            </div>
          </div>
        </div>

        <div className="rounded-[34px] border border-[#dceee3] bg-white/95 p-7 shadow-[0_24px_80px_rgba(15,43,29,0.08)] backdrop-blur sm:p-9">
          <div className="text-center">
            <div className="mx-auto flex h-16 w-16 items-center justify-center overflow-hidden rounded-2xl border border-[#dceee3] bg-[#f8fffa]">
              <img src="/logo.jpeg" alt="AI CTIX" className="h-full w-full object-contain" />
            </div>
            <h2 className="mt-6 text-3xl font-semibold tracking-[-0.035em] text-[#0d2217]">
              Welcome back
            </h2>
            <p className="mt-2 text-sm leading-6 text-[#5a7668]">
              Sign in to continue to your workspace.
            </p>
          </div>

          <form className="mt-8 space-y-5" onSubmit={handleSubmit}>
            {error ? <Alert tone="error">{error}</Alert> : null}

            <Field
              id="username"
              label="Username"
              value={username}
              onChange={setUsername}
              placeholder="Enter your username"
              autoComplete="username"
            />

            <PasswordField
              id="password"
              label="Password"
              value={password}
              onChange={setPassword}
              placeholder="Enter your password"
              autoComplete="current-password"
            />

            <div className="flex items-center justify-between gap-3 text-sm">
              <Link href="/forgot-password" className="font-semibold text-[#087a3a] hover:underline">
                Forgot password?
              </Link>
              <Link href="/register" className="font-semibold text-[#087a3a] hover:underline">
                Create account
              </Link>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full rounded-2xl bg-[#087a3a] px-5 py-3.5 text-sm font-semibold text-white shadow-[0_16px_32px_rgba(8,122,58,0.18)] transition hover:-translate-y-0.5 hover:bg-[#066b33] disabled:cursor-not-allowed disabled:opacity-60"
            >
              {loading ? 'Signing in...' : 'Sign in'}
            </button>
          </form>
        </div>
      </section>
    </main>
  )
}

function Field({
  id,
  label,
  value,
  onChange,
  placeholder,
  autoComplete,
}: {
  id: string
  label: string
  value: string
  onChange: (value: string) => void
  placeholder: string
  autoComplete?: string
}) {
  return (
    <div>
      <label htmlFor={id} className="block text-sm font-semibold text-[#173128]">
        {label}
      </label>
      <input
        id={id}
        name={id}
        type="text"
        required
        value={value}
        onChange={(event) => onChange(event.target.value)}
        autoComplete={autoComplete}
        placeholder={placeholder}
        className="mt-2 block w-full rounded-2xl border border-[#dceee3] bg-[#fbfffd] px-4 py-3 text-sm text-[#0d2217] outline-none transition placeholder:text-[#9aa9a0] focus:border-[#087a3a] focus:bg-white focus:ring-4 focus:ring-[#087a3a]/10"
      />
    </div>
  )
}

function PasswordField({
  id,
  label,
  value,
  onChange,
  placeholder,
  autoComplete,
}: {
  id: string
  label: string
  value: string
  onChange: (value: string) => void
  placeholder: string
  autoComplete?: string
}) {
  return (
    <div>
      <label htmlFor={id} className="block text-sm font-semibold text-[#173128]">
        {label}
      </label>
      <input
        id={id}
        name={id}
        type="password"
        required
        value={value}
        onChange={(event) => onChange(event.target.value)}
        autoComplete={autoComplete}
        placeholder={placeholder}
        className="mt-2 block w-full rounded-2xl border border-[#dceee3] bg-[#fbfffd] px-4 py-3 text-sm text-[#0d2217] outline-none transition placeholder:text-[#9aa9a0] focus:border-[#087a3a] focus:bg-white focus:ring-4 focus:ring-[#087a3a]/10"
      />
    </div>
  )
}

function Alert({ children, tone }: { children: React.ReactNode; tone: 'error' | 'success' }) {
  return (
    <div
      className={
        tone === 'error'
          ? 'rounded-2xl border border-red-200 bg-red-50 p-4 text-sm leading-6 text-red-700'
          : 'rounded-2xl border border-emerald-200 bg-emerald-50 p-4 text-sm leading-6 text-emerald-700'
      }
    >
      {children}
    </div>
  )
}
