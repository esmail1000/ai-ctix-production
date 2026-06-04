'use client'

import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { useState, type FormEvent } from 'react'

type VerificationChannel = 'email' | 'sms'

export default function RegisterPage() {
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [phone, setPhone] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [verificationChannel, setVerificationChannel] = useState<VerificationChannel>('email')
  const [userId, setUserId] = useState('')
  const [otp, setOtp] = useState('')
  const [receivedOtp, setReceivedOtp] = useState('')
  const [showOtpScreen, setShowOtpScreen] = useState(false)
  const [showNotification, setShowNotification] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [loading, setLoading] = useState(false)
  const router = useRouter()

  async function handleRegisterSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    setSuccess('')

    if (password !== confirmPassword) {
      setError('Passwords do not match')
      return
    }

    setLoading(true)

    try {
      const response = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, email, phone, verificationChannel }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || 'Registration failed')
      }

      setUserId(String(data.userId ?? ''))
      setReceivedOtp(String(data.otp ?? ''))
      setSuccess('Account created. Verification code is ready.')

      window.setTimeout(() => {
        setSuccess('')
        setShowOtpScreen(true)
        window.setTimeout(() => setShowNotification(true), 700)
      }, 900)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong')
    } finally {
      setLoading(false)
    }
  }

  async function handleOtpVerifySubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    setSuccess('')
    setLoading(true)

    try {
      const response = await fetch('/api/auth/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, otp }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || 'Verification failed')
      }

      setSuccess('Verification successful. Opening your workspace...')
      setShowNotification(false)

      window.setTimeout(() => {
        router.push('/')
        router.refresh()
      }, 900)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed')
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

      {showNotification ? (
        <div className="fixed right-4 top-20 z-50 w-full max-w-sm sm:right-6 sm:top-24">
          <div className="rounded-[26px] border border-[#dceee3] bg-white/95 p-4 text-[#0d2217] shadow-[0_24px_80px_rgba(15,43,29,0.12)] backdrop-blur">
            <div className="flex items-center justify-between border-b border-[#e6f4ea] pb-3">
              <p className="text-xs font-semibold uppercase tracking-[0.16em] text-[#087a3a]">
                Verification message
              </p>
              <span className="text-[11px] text-[#7a8d83]">now</span>
            </div>
            <div className="mt-3">
              <p className="text-sm font-semibold text-[#0d2217]">
                {verificationChannel === 'sms' ? 'SMS verification' : 'Email verification'}
              </p>
              <p className="mt-2 text-sm leading-6 text-[#5a7668]">
                Your security code is{' '}
                <span className="rounded-lg border border-[#cbe8d6] bg-[#edfdf3] px-2 py-1 font-mono text-base font-bold tracking-[0.22em] text-[#087a3a]">
                  {receivedOtp}
                </span>
              </p>
            </div>
          </div>
        </div>
      ) : null}

      <section className="relative mx-auto grid min-h-screen max-w-[1320px] items-center gap-8 px-6 py-10 lg:grid-cols-[1fr_540px] lg:px-8">
        <div className="hidden lg:block">
          <p className="text-xs font-semibold uppercase tracking-[0.22em] text-[#087a3a]">
            Workspace activation
          </p>
          <h1 className="mt-4 max-w-3xl text-5xl font-semibold tracking-[-0.05em] text-[#0d2217]">
            Create a secure AI CTIX analyst account
          </h1>
          <p className="mt-5 max-w-2xl text-base leading-8 text-[#5f6f66]">
            Register, verify your security code, and start analyzing reports with the same backend authentication workflow.
          </p>

          <div className="mt-10 grid max-w-[560px] gap-3 sm:grid-cols-2">
            <MiniStat label="Step 01" value="Account" />
            <MiniStat label="Step 02" value="Verify" />
            <MiniStat label="Step 03" value="Workspace" />
            <MiniStat label="Access" value="Protected" />
          </div>
        </div>

        <div className="rounded-[34px] border border-[#dceee3] bg-white/95 p-7 shadow-[0_24px_80px_rgba(15,43,29,0.08)] backdrop-blur sm:p-9">
          {showOtpScreen ? (
            <div>
              <AuthHeader
                title="Verify your account"
                description={
                  verificationChannel === 'sms'
                    ? `Enter the 6-digit code sent to ${phone}.`
                    : `Enter the 6-digit code sent to ${email}.`
                }
              />

              <form className="mt-8 space-y-5" onSubmit={handleOtpVerifySubmit}>
                {error ? <Alert tone="error">{error}</Alert> : null}
                {success ? <Alert tone="success">{success}</Alert> : null}

                <div>
                  <label htmlFor="otp" className="block text-center text-sm font-semibold text-[#173128]">
                    Verification code
                  </label>
                  <input
                    id="otp"
                    name="otp"
                    type="text"
                    required
                    maxLength={6}
                    value={otp}
                    onChange={(event) => setOtp(event.target.value.replace(/\D/g, ''))}
                    placeholder="000000"
                    className="mt-3 block w-full rounded-2xl border border-[#dceee3] bg-[#fbfffd] px-4 py-3 text-center font-mono text-2xl font-semibold tracking-[0.5em] text-[#0d2217] outline-none transition placeholder:text-[#c6d0ca] focus:border-[#087a3a] focus:bg-white focus:ring-4 focus:ring-[#087a3a]/10"
                  />
                </div>

                <button
                  type="submit"
                  disabled={loading || otp.length !== 6}
                  className="w-full rounded-2xl bg-[#087a3a] px-5 py-3.5 text-sm font-semibold text-white shadow-[0_16px_32px_rgba(8,122,58,0.18)] transition hover:-translate-y-0.5 hover:bg-[#066b33] disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {loading ? 'Verifying...' : 'Verify and continue'}
                </button>

                <button
                  type="button"
                  onClick={() => setShowNotification(true)}
                  className="w-full rounded-2xl border border-[#c4e3cf] bg-white px-5 py-3 text-sm font-semibold text-[#173128] transition hover:bg-[#f4fff7]"
                >
                  Show code message again
                </button>
              </form>
            </div>
          ) : (
            <div>
              <AuthHeader title="Create account" description="Start your AI CTIX workspace with verified access." />

              <form className="mt-8 space-y-5" onSubmit={handleRegisterSubmit}>
                {error ? <Alert tone="error">{error}</Alert> : null}
                {success ? <Alert tone="success">{success}</Alert> : null}

                <Field id="username" label="Username" value={username} onChange={setUsername} placeholder="Choose a username" />
                <div className="grid gap-4 sm:grid-cols-2">
                  <Field id="email" label="Email" type="email" value={email} onChange={setEmail} placeholder="name@domain.com" />
                  <Field id="phone" label="Phone" type="tel" value={phone} onChange={setPhone} placeholder="+20 123456789" />
                </div>

                <div>
                  <p className="block text-sm font-semibold text-[#173128]">Verification channel</p>
                  <div className="mt-2 grid grid-cols-2 gap-3">
                    <ChannelButton active={verificationChannel === 'email'} onClick={() => setVerificationChannel('email')}>
                      Email
                    </ChannelButton>
                    <ChannelButton active={verificationChannel === 'sms'} onClick={() => setVerificationChannel('sms')}>
                      SMS
                    </ChannelButton>
                  </div>
                </div>

                <PasswordField id="password" label="Password" value={password} onChange={setPassword} placeholder="At least 6 characters" />
                <PasswordField id="confirmPassword" label="Confirm password" value={confirmPassword} onChange={setConfirmPassword} placeholder="Repeat password" />

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full rounded-2xl bg-[#087a3a] px-5 py-3.5 text-sm font-semibold text-white shadow-[0_16px_32px_rgba(8,122,58,0.18)] transition hover:-translate-y-0.5 hover:bg-[#066b33] disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {loading ? 'Creating account...' : 'Create account'}
                </button>
              </form>

              <p className="mt-6 text-center text-sm text-[#5a7668]">
                Already have an account?{' '}
                <Link href="/login" className="font-semibold text-[#087a3a] hover:underline">
                  Sign in
                </Link>
              </p>
            </div>
          )}
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

function Field({
  id,
  label,
  value,
  onChange,
  placeholder,
  type = 'text',
}: {
  id: string
  label: string
  value: string
  onChange: (value: string) => void
  placeholder: string
  type?: string
}) {
  return (
    <div>
      <label htmlFor={id} className="block text-sm font-semibold text-[#173128]">
        {label}
      </label>
      <input
        id={id}
        name={id}
        type={type}
        required
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="mt-2 block w-full rounded-2xl border border-[#dceee3] bg-[#fbfffd] px-4 py-3 text-sm text-[#0d2217] outline-none transition placeholder:text-[#9aa9a0] focus:border-[#087a3a] focus:bg-white focus:ring-4 focus:ring-[#087a3a]/10"
      />
    </div>
  )
}

function PasswordField(props: {
  id: string
  label: string
  value: string
  onChange: (value: string) => void
  placeholder: string
}) {
  return <Field {...props} type="password" />
}

function ChannelButton({
  active,
  onClick,
  children,
}: {
  active: boolean
  onClick: () => void
  children: React.ReactNode
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={
        active
          ? 'rounded-2xl border border-[#087a3a] bg-[#edfdf3] px-4 py-3 text-sm font-semibold text-[#087a3a]'
          : 'rounded-2xl border border-[#dceee3] bg-white px-4 py-3 text-sm font-semibold text-[#5a7668] transition hover:bg-[#f8fffa]'
      }
    >
      {children}
    </button>
  )
}

function MiniStat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-2xl border border-[#dceee3] bg-white/88 p-4 shadow-[0_18px_45px_rgba(15,43,29,0.05)]">
      <p className="text-xs font-semibold uppercase tracking-wide text-[#5a7668]">{label}</p>
      <p className="mt-2 text-xl font-semibold text-[#0d2217]">{value}</p>
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
