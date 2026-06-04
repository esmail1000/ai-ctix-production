import 'dotenv/config'
import { prisma } from '@/lib/server/prisma'

async function main() {
  const cutoff = new Date()

  const result = await prisma.rateLimitBucket.deleteMany({
    where: {
      resetAt: {
        lt: cutoff,
      },
    },
  })

  console.log(`Deleted expired rate limit buckets: ${result.count}`)
}

main()
  .catch((error) => {
    console.error(error)
    process.exit(1)
  })
  .finally(async () => {
    await prisma.$disconnect()
  })