import crypto from 'crypto'
import { prisma } from '@/lib/server/prisma'
import { sendOtpEmail } from '@/lib/server/mailer'

const PASSWORD_HASH_ALGORITHM = 'pbkdf2_sha256'
const PASSWORD_HASH_ITERATIONS = 210000
const PASSWORD_SALT_BYTES = 16
const PASSWORD_KEY_BYTES = 32

const OTP_TTL_MS = 5 * 60 * 1000
const RESET_TOKEN_TTL_MS = 15 * 60 * 1000

export interface User {
  id: string
  username: string
  email: string
  phone: string
  passwordHash: string
  emailVerified: boolean
  phoneVerified: boolean
  otpCode: string
  otpExpiry: number
  verificationChannel: 'email' | 'sms'
  createdAt: string
  passwordResetTokenHash?: string
  passwordResetExpiry?: number
}

function toAuthUser(user: any): User {
  return {
    id: user.id,
    username: user.username,
    email: user.email,
    phone: user.phone || '',
    passwordHash: user.passwordHash,
    emailVerified: Boolean(user.emailVerified),
    phoneVerified: Boolean(user.phoneVerified),
    otpCode: user.otpCode || '',
    otpExpiry: user.otpExpiry ? new Date(user.otpExpiry).getTime() : 0,
    verificationChannel: user.verificationChannel === 'sms' ? 'sms' : 'email',
    createdAt: user.createdAt ? new Date(user.createdAt).toISOString() : new Date().toISOString(),
    passwordResetTokenHash: user.passwordResetTokenHash || '',
    passwordResetExpiry: user.passwordResetExpiry
      ? new Date(user.passwordResetExpiry).getTime()
      : 0,
  }
}

function legacySha256(password: string): string {
  return crypto.createHash('sha256').update(password).digest('hex')
}

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(PASSWORD_SALT_BYTES).toString('hex')
  const derivedKey = crypto.pbkdf2Sync(
    password,
    salt,
    PASSWORD_HASH_ITERATIONS,
    PASSWORD_KEY_BYTES,
    'sha256'
  )

  return [
    PASSWORD_HASH_ALGORITHM,
    PASSWORD_HASH_ITERATIONS,
    salt,
    derivedKey.toString('hex'),
  ].join('$')
}

export function verifyPassword(password: string, storedHash: string): boolean {
  if (!storedHash) return false

  const parts = storedHash.split('$')

  if (parts.length === 4 && parts[0] === PASSWORD_HASH_ALGORITHM) {
    const iterations = Number(parts[1])
    const salt = parts[2]
    const expectedHash = parts[3]

    if (!Number.isFinite(iterations) || !salt || !expectedHash) {
      return false
    }

    const derivedKey = crypto.pbkdf2Sync(
      password,
      salt,
      iterations,
      PASSWORD_KEY_BYTES,
      'sha256'
    )

    const expectedBuffer = Buffer.from(expectedHash, 'hex')
    const actualBuffer = Buffer.from(derivedKey.toString('hex'), 'hex')

    if (expectedBuffer.length !== actualBuffer.length) {
      return false
    }

    return crypto.timingSafeEqual(expectedBuffer, actualBuffer)
  }

  return legacySha256(password) === storedHash
}

function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex')
}

function verifyHashedToken(token: string, storedHash: string): boolean {
  if (!token || !storedHash) return false

  const cleanedToken = token.trim()

  // Backward compatibility for any pre-existing unverified users that still
  // have a plaintext 6-digit OTP from older local development builds. New OTPs
  // are always stored as SHA-256 hashes.
  if (/^\d{6}$/.test(storedHash)) {
    const expectedBuffer = Buffer.from(storedHash)
    const actualBuffer = Buffer.from(cleanedToken)

    if (expectedBuffer.length !== actualBuffer.length) {
      return false
    }

    return crypto.timingSafeEqual(expectedBuffer, actualBuffer)
  }

  const actualHash = hashToken(cleanedToken)
  const expectedBuffer = Buffer.from(storedHash, 'hex')
  const actualBuffer = Buffer.from(actualHash, 'hex')

  if (expectedBuffer.length !== actualBuffer.length) {
    return false
  }

  return crypto.timingSafeEqual(expectedBuffer, actualBuffer)
}

function generateOtp(): string {
  return crypto.randomInt(100000, 1000000).toString()
}

function generateResetToken(): string {
  return crypto.randomBytes(32).toString('hex')
}

async function getAllDbUsers() {
  return prisma.user.findMany({
    orderBy: { createdAt: 'asc' },
  })
}

export async function getUsers(): Promise<User[]> {
  const users = await getAllDbUsers()
  return users.map(toAuthUser)
}

export async function getUserByUsername(username: string): Promise<User | undefined> {
  const normalized = username.trim()

  if (!normalized) return undefined

  const user = await prisma.user.findFirst({
    where: {
      username: {
        equals: normalized,
        mode: 'insensitive',
      },
    },
  })

  return user ? toAuthUser(user) : undefined
}

export async function getUserByEmail(email: string): Promise<User | undefined> {
  const normalized = email.trim()

  if (!normalized) return undefined

  const user = await prisma.user.findFirst({
    where: {
      email: {
        equals: normalized,
        mode: 'insensitive',
      },
    },
  })

  return user ? toAuthUser(user) : undefined
}

export async function getUserById(id: string): Promise<User | undefined> {
  const user = await prisma.user.findUnique({
    where: { id },
  })

  return user ? toAuthUser(user) : undefined
}

export async function registerUser(
  username: string,
  passwordPlain: string,
  email: string,
  phone: string,
  verificationChannel: 'email' | 'sms'
): Promise<{ user: User; sentRealEmail: boolean }> {
  if (verificationChannel !== 'email') {
    throw new Error('Only email verification is supported.')
  }

  const cleanUsername = username.trim()
  const cleanEmail = email.trim().toLowerCase()
  const cleanPhone = phone.trim()

  const [existingUsername, existingEmail] = await Promise.all([
    getUserByUsername(cleanUsername),
    getUserByEmail(cleanEmail),
  ])

  if (existingUsername) {
    throw new Error('Username is already taken.')
  }

  if (existingEmail) {
    throw new Error('Email is already registered.')
  }

  const otp = generateOtp()
  const otpHash = hashToken(otp)

  const dbUser = await prisma.user.create({
    data: {
      id: crypto.randomUUID(),
      username: cleanUsername,
      email: cleanEmail,
      phone: cleanPhone,
      passwordHash: hashPassword(passwordPlain),
      emailVerified: false,
      phoneVerified: false,
      otpCode: otpHash,
      otpExpiry: new Date(Date.now() + OTP_TTL_MS),
      verificationChannel: 'email',
    },
  })

  try {
    await sendOtpEmail({
      toEmail: dbUser.email,
      username: dbUser.username,
      otp,
    })
  } catch (error) {
    await prisma.user.delete({
      where: { id: dbUser.id },
    })

    throw new Error(
      error instanceof Error
        ? `Failed to send verification email: ${error.message}`
        : 'Failed to send verification email.'
    )
  }

  return {
    user: toAuthUser(dbUser),
    sentRealEmail: true,
  }
}

export async function verifyUserOtp(userId: string, otp: string): Promise<boolean> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
  })

  if (!user) return false

  const cleanedOtp = otp.trim()
  const otpExpiryTime = user.otpExpiry ? new Date(user.otpExpiry).getTime() : 0

  if (!user.otpCode || Date.now() >= otpExpiryTime) {
    return false
  }

  if (!verifyHashedToken(cleanedOtp, user.otpCode)) {
    return false
  }

  await prisma.user.update({
    where: { id: user.id },
    data: {
      emailVerified: true,
      phoneVerified: false,
      otpCode: null,
      otpExpiry: null,
    },
  })

  return true
}

export async function createPasswordResetToken(
  email: string
): Promise<{ user: User; token: string } | null> {
  const user = await getUserByEmail(email)

  if (!user) {
    return null
  }

  const token = generateResetToken()

  const updatedUser = await prisma.user.update({
    where: { id: user.id },
    data: {
      passwordResetTokenHash: hashToken(token),
      passwordResetExpiry: new Date(Date.now() + RESET_TOKEN_TTL_MS),
    },
  })

  return {
    user: toAuthUser(updatedUser),
    token,
  }
}

export async function resetPasswordWithToken(
  token: string,
  newPassword: string
): Promise<User | null> {
  const tokenHash = hashToken(token.trim())

  const user = await prisma.user.findFirst({
    where: {
      passwordResetTokenHash: tokenHash,
    },
  })

  if (!user || !user.passwordResetExpiry) {
    return null
  }

  if (Date.now() >= new Date(user.passwordResetExpiry).getTime()) {
    return null
  }

  const updatedUser = await prisma.user.update({
    where: { id: user.id },
    data: {
      passwordHash: hashPassword(newPassword),
      passwordResetTokenHash: null,
      passwordResetExpiry: null,
    },
  })

  return toAuthUser(updatedUser)
}