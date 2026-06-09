import Navigation from '@/components/Navigation'
import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'AI CTIX',
  description: 'AI CTIX - Cyber report analysis workspace',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="bg-white text-[#0d2217] antialiased">
        <Navigation />
        <div className="min-h-screen">{children}</div>
      </body>
    </html>
  )
}