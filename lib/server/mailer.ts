function getBrevoConfig() {
  const apiKey = process.env.BREVO_API_KEY?.trim()
  const senderEmail = process.env.BREVO_SENDER_EMAIL?.trim()
  const senderName = process.env.BREVO_SENDER_NAME?.trim() || 'AI CTIX Security'

  if (!apiKey) {
    throw new Error('BREVO_API_KEY is missing.')
  }

  if (!senderEmail || !senderEmail.includes('@')) {
    throw new Error('BREVO_SENDER_EMAIL is missing or invalid.')
  }

  return { apiKey, senderEmail, senderName }
}

function escapeHtml(value: string) {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
}

async function sendBrevoEmail(input: {
  toEmail: string
  toName?: string
  subject: string
  htmlContent: string
  textContent?: string
}) {
  const { apiKey, senderEmail, senderName } = getBrevoConfig()

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
          email: input.toEmail,
          name: input.toName || input.toEmail,
        },
      ],
      subject: input.subject,
      htmlContent: input.htmlContent,
      textContent: input.textContent,
    }),
  })

  if (!response.ok) {
    const errorText = await response.text()
    throw new Error(`Brevo email failed: ${response.status} ${errorText}`)
  }

  return response.json()
}

export async function sendOtpEmail(input: {
  toEmail: string
  username: string
  otp: string
}) {
  await sendBrevoEmail({
    toEmail: input.toEmail,
    toName: input.username,
    subject: 'Your AI CTIX verification code',
    textContent: `Your AI CTIX verification code is ${input.otp}. It expires in 5 minutes.`,
    htmlContent: `
      <div style="font-family: Arial, sans-serif; max-width: 520px; margin: 0 auto; padding: 24px; border: 1px solid #cbe8d6; border-radius: 16px; background: #fcfffd;">
        <h2 style="margin: 0 0 16px; color: #15803d;">AI CTIX Account Verification</h2>
        <p style="color: #0d2217;">Hello <strong>${escapeHtml(input.username)}</strong>,</p>
        <p style="color: #4d6b5b; line-height: 1.6;">Use this one-time verification code to activate your AI CTIX account.</p>
        <div style="text-align: center; margin: 28px 0;">
          <span style="display: inline-block; padding: 14px 26px; border-radius: 12px; background: #15803d; color: #ffffff; font-size: 28px; font-weight: 700; letter-spacing: 6px; font-family: monospace;">
            ${escapeHtml(input.otp)}
          </span>
        </div>
        <p style="color: #b45309; font-size: 13px;">This code expires in 5 minutes. Do not share it with anyone.</p>
        <hr style="border: 0; border-top: 1px solid #e6f4ea; margin: 24px 0;" />
        <p style="color: #7a9284; font-size: 12px;">AI CTIX Security</p>
      </div>
    `,
  })
}

export async function sendPasswordResetEmail(input: {
  toEmail: string
  username: string
  resetLink: string
}) {
  await sendBrevoEmail({
    toEmail: input.toEmail,
    toName: input.username,
    subject: 'Reset your AI CTIX password',
    textContent: `Reset your AI CTIX password using this link: ${input.resetLink}`,
    htmlContent: `
      <div style="font-family: Arial, sans-serif; max-width: 520px; margin: 0 auto; padding: 24px; border: 1px solid #cbe8d6; border-radius: 16px; background: #fcfffd;">
        <h2 style="margin: 0 0 16px; color: #15803d;">Reset Your Password</h2>
        <p style="color: #0d2217;">Hello <strong>${escapeHtml(input.username)}</strong>,</p>
        <p style="color: #4d6b5b; line-height: 1.6;">We received a request to reset your AI CTIX password. Click the button below to set a new password.</p>
        <div style="text-align: center; margin: 28px 0;">
          <a href="${escapeHtml(input.resetLink)}" style="display: inline-block; padding: 14px 22px; border-radius: 12px; background: #15803d; color: #ffffff; text-decoration: none; font-weight: 700;">Reset Password</a>
        </div>
        <p style="color: #4d6b5b; font-size: 13px; line-height: 1.6;">
          If the button does not work, copy this link:<br />
          <span style="word-break: break-all;">${escapeHtml(input.resetLink)}</span>
        </p>
        <p style="color: #b45309; font-size: 13px;">This link expires in 15 minutes. If you did not request this, ignore this email.</p>
        <hr style="border: 0; border-top: 1px solid #e6f4ea; margin: 24px 0;" />
        <p style="color: #7a9284; font-size: 12px;">AI CTIX Security</p>
      </div>
    `,
  })
}

export async function sendPasswordChangedEmail(input: {
  toEmail: string
  username: string
}) {
  await sendBrevoEmail({
    toEmail: input.toEmail,
    toName: input.username,
    subject: 'Your AI CTIX password was changed',
    textContent:
      'Your AI CTIX password was changed successfully. If this was not you, secure your account immediately.',
    htmlContent: `
      <div style="font-family: Arial, sans-serif; max-width: 520px; margin: 0 auto; padding: 24px; border: 1px solid #cbe8d6; border-radius: 16px; background: #fcfffd;">
        <h2 style="margin: 0 0 16px; color: #15803d;">Password Changed Successfully</h2>
        <p style="color: #0d2217;">Hello <strong>${escapeHtml(input.username)}</strong>,</p>
        <p style="color: #4d6b5b; line-height: 1.6;">Your AI CTIX account password was changed successfully.</p>
        <p style="color: #b45309; font-size: 13px;">If this was not you, please reset your password immediately and review your account security.</p>
        <hr style="border: 0; border-top: 1px solid #e6f4ea; margin: 24px 0;" />
        <p style="color: #7a9284; font-size: 12px;">AI CTIX Security</p>
      </div>
    `,
  })
}
