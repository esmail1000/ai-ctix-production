const fs = require('fs')
const path = require('path')
const nodemailer = require('nodemailer')

function loadEnvFile(filePath) {
  if (!fs.existsSync(filePath)) return

  const lines = fs.readFileSync(filePath, 'utf8').split(/\r?\n/)

  for (const line of lines) {
    const trimmed = line.trim()

    if (!trimmed || trimmed.startsWith('#')) continue

    const equalsIndex = trimmed.indexOf('=')
    if (equalsIndex === -1) continue

    const key = trimmed.slice(0, equalsIndex).trim()
    let value = trimmed.slice(equalsIndex + 1).trim()

    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1)
    }

    process.env[key] = value
  }
}

function required(name) {
  const value = process.env[name]

  if (!value || !value.trim()) {
    throw new Error(`${name} is missing in .env.local`)
  }

  return value.trim()
}

async function main() {
  loadEnvFile(path.join(process.cwd(), '.env.local'))

  const host = required('SMTP_HOST')
  const port = Number(process.env.SMTP_PORT || 587)
  const secure = process.env.SMTP_SECURE === 'true'
  const user = required('SMTP_USER')
  const pass = required('SMTP_PASS')
  const from = required('SMTP_FROM')
  const to = required('SMTP_TEST_TO')

  const transporter = nodemailer.createTransport({
    host,
    port,
    secure,
    auth: {
      user,
      pass,
    },
  })

  console.log('Verifying SMTP connection...')
  await transporter.verify()

  console.log('Sending test email...')
  const info = await transporter.sendMail({
    from,
    to,
    subject: 'AI CTIX SMTP Test',
    text: 'SMTP is working. AI CTIX can send real emails now.',
    html: `
      <div style="font-family: Arial, sans-serif; padding: 20px;">
        <h2>AI CTIX SMTP Test</h2>
        <p>SMTP is working. AI CTIX can send real emails now.</p>
      </div>
    `,
  })

  console.log('SMTP TEST SENT ✅')
  console.log(`Message ID: ${info.messageId}`)
}

main().catch((error) => {
  console.error('SMTP TEST FAILED ❌')
  console.error(error.message || error)
  process.exit(1)
})