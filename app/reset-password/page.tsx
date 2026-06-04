'use client'

import Link from 'next/link'
import { useRouter, useSearchParams } from 'next/navigation'
import { Suspense, useState, type FormEvent } from 'react'

export default function ResetPasswordPage() {
  return (
    <Suspense fallback={<ResetLoading />}>
      <ResetPasswordContent />
    </Suspense>
  )
}

function ResetPasswordContent() {
  const searchParams = useSearchParams()
  const token = searchParams.get('token') ?? ''
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [loading, setLoading] = useState(false)
  const router = useRouter()

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    setSuccess('')

    if (!token) {
      setError('Reset token is missing.')
      return
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match')
      return
    }

    setLoading(true)

    try {
      const response = await fetch('/api/auth/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, password }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || 'Password reset failed')
      }

      setSuccess('Password updated. Redirecting to sign in...')
      window.setTimeout(() => router.push('/login'), 900)
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
            Password reset
          </p>
          <h1 className="mt-4 max-w-3xl text-5xl font-semibold tracking-[-0.05em] text-[#0d2217]">
            Set a new password for your AI CTIX workspace
          </h1>
          <p className="mt-5 max-w-2xl text-base leading-8 text-[#5f6f66]">
            This page only updates the client interface. The reset token is still validated by the existing API route.
          </p>
        </div>

        <div className="rounded-[34px] border border-[#dceee3] bg-white/95 p-7 shadow-[0_24px_80px_rgba(15,43,29,0.08)] backdrop-blur sm:p-9">
          <AuthHeader title="Reset password" description="Choose a new secure password for your account." />

          <form className="mt-8 space-y-5" onSubmit={handleSubmit}>
            {error ? <Alert tone="error">{error}</Alert> : null}
            {success ? <Alert tone="success">{success}</Alert> : null}
            {!token ? <Alert tone="error">The reset link is missing a token.</Alert> : null}

            <PasswordField id="password" label="New password" value={password} onChange={setPassword} placeholder="Enter new password" />
            <PasswordField id="confirmPassword" label="Confirm password" value={confirmPassword} onChange={setConfirmPassword} placeholder="Repeat new password" />

            <button
              type="submit"
              disabled={loading || !token}
              className="w-full rounded-2xl bg-[#087a3a] px-5 py-3.5 text-sm font-semibold text-white shadow-[0_16px_32px_rgba(8,122,58,0.18)] transition hover:-translate-y-0.5 hover:bg-[#066b33] disabled:cursor-not-allowed disabled:opacity-60"
            >
              {loading ? 'Updating password...' : 'Update password'}
            </button>
          </form>

          <p className="mt-6 text-center text-sm text-[#5a7668]">
            Back to{' '}
            <Link href="/login" className="font-semibold text-[#087a3a] hover:underline">
              sign in
            </Link>
          </p>
        </div>
      </section>
    </main>
  )
}

function ResetLoading() {
  return (
    <main className="relative min-h-screen bg-[#fbfefd]">
      <section className="mx-auto flex min-h-screen max-w-7xl items-center justify-center px-6">
        <div className="rounded-[28px] border border-[#dceee3] bg-white p-8 text-center shadow-[0_22px_60px_rgba(15,43,29,0.06)]">
          <div className="mx-auto h-12 w-12 animate-spin rounded-full border-4 border-[#087a3a] border-t-transparent" />
          <p className="mt-4 text-sm font-semibold text-[#087a3a]">Loading reset page...</p>
        </div>
      </section>
    </main>
  )
}

function AuthHeader({ title, description }: { title: string; description: string }) {
  return (
    <div className="text-center">
      <div className="mx-auto flex h-16 w-16 items-center justify-center overflow-hidden rounded-2xl border border-[#dceee3] bg-[#f8fffa]">
        <img src="/logo.jpeg" alt="AI CTIX" className="h-full w-full object-contain" />
      </div>
      <h2 className="mt-6 text-3xl font-semibold tracking-[-0.035em] text-[#0d2217]">{title}</h2>
      <p className="mt-2 text-sm leading-6 text-[#5a7668]">{description}</p>
    </div>
  )
}

function PasswordField({
  id,
  label,
  value,
  onChange,
  placeholder,
}: {
  id: string
  label: string
  value: string
  onChange: (value: string) => void
  placeholder: string
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
