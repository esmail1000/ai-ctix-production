import Link from 'next/link'

export default function CheckEmailPage({
  searchParams,
}: {
  searchParams?: Promise<Record<string, string | string[] | undefined>>
}) {
  return <CheckEmailContent searchParamsPromise={searchParams} />
}

async function CheckEmailContent({
  searchParamsPromise,
}: {
  searchParamsPromise?: Promise<Record<string, string | string[] | undefined>>
}) {
  const params = (await searchParamsPromise) ?? {}
  const rawEmail = params.email
  const email = Array.isArray(rawEmail) ? rawEmail[0] ?? '' : rawEmail ?? ''

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

      <section className="relative mx-auto flex min-h-screen max-w-[1180px] items-center justify-center px-6 py-10 lg:px-8">
        <div className="w-full max-w-[760px] overflow-hidden rounded-[34px] border border-[#dceee3] bg-white/95 shadow-[0_24px_80px_rgba(15,43,29,0.08)] backdrop-blur">
          <div className="relative border-b border-[#dceee3] bg-[#fbfffd] p-8 text-center">
            <div className="pointer-events-none absolute right-10 top-8 h-24 w-24 rounded-full border border-[#c7efd4] bg-white/70 shadow-[0_22px_55px_rgba(8,122,58,0.10)] auth-orbit">
              <div className="absolute left-1/2 top-1/2 h-12 w-12 -translate-x-1/2 -translate-y-1/2 rounded-full bg-gradient-to-br from-[#dff7e8] to-[#087a3a]" />
              <div className="absolute left-1/2 top-1/2 h-4 w-4 -translate-x-1/2 -translate-y-[50px] rounded-full bg-[#087a3a]" />
            </div>

            <div className="mx-auto flex h-16 w-16 items-center justify-center overflow-hidden rounded-2xl border border-[#dceee3] bg-white">
              <img src="/logo.jpeg" alt="AI CTIX" className="h-full w-full object-contain" />
            </div>

            <p className="mt-6 text-xs font-semibold uppercase tracking-[0.22em] text-[#087a3a]">
              Recovery message sent
            </p>
            <h1 className="mt-3 text-4xl font-semibold tracking-[-0.045em] text-[#0d2217]">
              Check your email
            </h1>
            <p className="mx-auto mt-4 max-w-xl text-sm leading-7 text-[#5a7668]">
              We sent password reset instructions to {email ? <span className="font-semibold text-[#173128]">{email}</span> : 'your account email'}.
            </p>
          </div>

          <div className="p-8">
            <div className="grid gap-4 md:grid-cols-3">
              <Step label="Step 01" value="Open email" />
              <Step label="Step 02" value="Use reset link" />
              <Step label="Step 03" value="Sign in" />
            </div>

            <div className="mt-6 rounded-[26px] border border-[#dceee3] bg-[#f8fffa] p-5">
              <p className="text-sm font-semibold text-[#173128]">Did not receive it?</p>
              <p className="mt-2 text-sm leading-7 text-[#5a7668]">
                Check spam or request a new reset link from the forgot password page.
              </p>
            </div>

            <div className="mt-7 flex flex-wrap justify-center gap-3">
              <Link
                href="/forgot-password"
                className="rounded-2xl border border-[#c4e3cf] bg-white px-5 py-3 text-sm font-semibold text-[#173128] transition hover:bg-[#f4fff7]"
              >
                Send another link
              </Link>
              <Link
                href="/login"
                className="rounded-2xl bg-[#087a3a] px-5 py-3 text-sm font-semibold text-white shadow-[0_16px_32px_rgba(8,122,58,0.18)] transition hover:-translate-y-0.5 hover:bg-[#066b33]"
              >
                Back to sign in
              </Link>
            </div>
          </div>
        </div>
      </section>
    </main>
  )
}

function Step({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-2xl border border-[#e4f2e9] bg-white p-4 text-center">
      <p className="text-xs font-semibold uppercase tracking-wide text-[#5a7668]">{label}</p>
      <p className="mt-2 text-sm font-semibold text-[#0d2217]">{value}</p>
    </div>
  )
}
