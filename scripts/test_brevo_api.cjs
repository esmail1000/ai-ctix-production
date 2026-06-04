const fs = require('fs')
const path = require('path')

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

function mask(value) {
  if (!value || value.length < 12) return '***'
  return `${value.slice(0, 8)}...${value.slice(-6)}`
}

async function main() {
  loadEnvFile(path.join(process.cwd(), '.env.local'))

  const apiKey = required('BREVO_API_KEY')
  const senderEmail = required('BREVO_SENDER_EMAIL')
  const senderName = process.env.BREVO_SENDER_NAME || 'AI CTIX Security'
  const to = process.env.BREVO_TEST_TO || process.env.SMTP_TEST_TO

  if (!to || !to.trim()) {
    throw new Error('BREVO_TEST_TO is missing in .env.local')
  }

  if (!apiKey.startsWith('xkeysib-')) {
    throw new Error('BREVO_API_KEY must start with xkeysib-')
  }

  if (senderEmail.endsWith('@smtp-brevo.com')) {
    throw new Error('BREVO_SENDER_EMAIL must be your verified sender email, not the SMTP login.')
  }

  console.log('Sending Brevo API test email...')
  console.log(`API key: ${mask(apiKey)}`)
  console.log(`From: ${senderName} <${senderEmail}>`)
  console.log(`To: ${to.trim()}`)

  const response = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      accept: 'application/json',
      'api-key': apiKey,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      sender: {
        name: senderName,
        email: senderEmail,
      },
      to: [
        {
          email: to.trim(),
        },
      ],
      subject: 'AI CTIX Brevo API Test',
      htmlContent: `
        <div style="font-family: Arial, sans-serif; padding: 20px;">
          <h2>AI CTIX Brevo API Test</h2>
          <p>Brevo API email sending is working.</p>
        </div>
      `,
      textContent: 'Brevo API email sending is working.',
    }),
  })

  const text = await response.text()

  if (!response.ok) {
    throw new Error(`Brevo API failed: ${response.status} ${text}`)
  }

  console.log('BREVO API TEST SENT ✅')
  console.log(text)
}

main().catch((error) => {
  console.error('BREVO API TEST FAILED ❌')
  console.error(error.message || error)
  process.exit(1)
})