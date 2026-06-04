import 'dotenv/config'
import { promises as fs } from 'fs'
import path from 'path'
import { PrismaBetterSqlite3 } from '@prisma/adapter-better-sqlite3'
import { PrismaClient } from '../lib/generated/prisma/client'

const connectionString = process.env.DATABASE_URL || 'file:./dev.db'
const adapter = new PrismaBetterSqlite3({ url: connectionString })
const prisma = new PrismaClient({ adapter })

type JsonUser = {
  id?: string
  username?: string
  email?: string
  phone?: string
  passwordHash?: string
  emailVerified?: boolean
  phoneVerified?: boolean
  otpCode?: string
  otpExpiry?: number
  verificationChannel?: 'email' | 'sms'
  createdAt?: string
  passwordResetTokenHash?: string
  passwordResetExpiry?: number
}

function toDate(value: unknown): Date | null {
  if (typeof value !== 'number') return null
  if (!Number.isFinite(value) || value <= 0) return null
  return new Date(value)
}

function cleanString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : ''
}

async function main() {
  const usersJsonPath = path.join(process.cwd(), '.data', 'users.json')

  let raw = '[]'

  try {
    raw = await fs.readFile(usersJsonPath, 'utf8')
  } catch {
    console.log('No .data/users.json found. Nothing to migrate.')
    return
  }

  const parsed = JSON.parse(raw || '[]')

  if (!Array.isArray(parsed)) {
    throw new Error('.data/users.json is not an array.')
  }

  let imported = 0
  let updated = 0
  let skipped = 0

  for (const item of parsed as JsonUser[]) {
    const id = cleanString(item.id)
    const username = cleanString(item.username)
    const email = cleanString(item.email)
    const phone = cleanString(item.phone)
    const passwordHash = cleanString(item.passwordHash)

    if (!id || !username || !email || !passwordHash) {
      console.log(`SKIP invalid user: ${username || email || id || 'unknown'}`)
      skipped += 1
      continue
    }

    const existing = await prisma.user.findFirst({
      where: {
        OR: [{ id }, { username }, { email }],
      },
    })

    if (existing) {
      console.log(`SKIP existing user: ${username} <${email}>`)
      skipped += 1
      continue
    }

    await prisma.user.create({
      data: {
        id,
        username,
        email,
        phone,
        passwordHash,
        emailVerified: Boolean(item.emailVerified),
        phoneVerified: Boolean(item.phoneVerified),
        otpCode: cleanString(item.otpCode) || null,
        otpExpiry: toDate(item.otpExpiry),
        verificationChannel: item.verificationChannel || 'email',
        passwordResetTokenHash: cleanString(item.passwordResetTokenHash) || null,
        passwordResetExpiry: toDate(item.passwordResetExpiry),
        createdAt: item.createdAt ? new Date(item.createdAt) : new Date(),
      },
    })

    console.log(`IMPORTED ${username} <${email}>`)
    imported += 1
  }

  const count = await prisma.user.count()

  console.log('')
  console.log('Migration complete ✅')
  console.log(`Imported: ${imported}`)
  console.log(`Updated: ${updated}`)
  console.log(`Skipped: ${skipped}`)
  console.log(`DB users: ${count}`)
}

main()
  .catch((error) => {
    console.error('Migration failed ❌')
    console.error(error)
    process.exit(1)
  })
  .finally(async () => {
    await prisma.$disconnect()
  })