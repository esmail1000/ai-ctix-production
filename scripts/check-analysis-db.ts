import 'dotenv/config'
import { PrismaBetterSqlite3 } from '@prisma/adapter-better-sqlite3'
import { PrismaClient } from '../lib/generated/prisma/client'

const connectionString = process.env.DATABASE_URL || 'file:./dev.db'
const adapter = new PrismaBetterSqlite3({ url: connectionString })
const prisma = new PrismaClient({ adapter })

async function main() {
  const reportCount = await prisma.analysisReport.count()
  const findingCount = await prisma.analysisFinding.count()
  const runCount = await prisma.analysisRun.count()
  const summaryCount = await prisma.analysisSummary.count()
  const riskCount = await prisma.analysisRiskScore.count()

  console.log('Analysis DB check ✅')
  console.log(`Reports: ${reportCount}`)
  console.log(`Findings: ${findingCount}`)
  console.log(`Runs: ${runCount}`)
  console.log(`Summaries: ${summaryCount}`)
  console.log(`Risk Scores: ${riskCount}`)
  console.log('')

  const latestReports = await prisma.analysisReport.findMany({
    take: 5,
    orderBy: { createdAt: 'desc' },
    include: {
      user: {
        select: {
          username: true,
          email: true,
        },
      },
      _count: {
        select: {
          findings: true,
          runs: true,
          summaries: true,
          riskScores: true,
        },
      },
    },
  })

  for (const report of latestReports) {
    console.log(`- ${report.id} | ${report.name}`)
    console.log(`  user: ${report.user.username} <${report.user.email}>`)
    console.log(`  findings: ${report._count.findings}`)
    console.log(`  runs: ${report._count.runs}`)
    console.log(`  summaries: ${report._count.summaries}`)
    console.log(`  riskScores: ${report._count.riskScores}`)
    console.log(`  createdAt: ${report.createdAt.toISOString()}`)
    console.log('')
  }

  const latestRisk = await prisma.analysisRiskScore.findFirst({
    orderBy: { generatedAt: 'desc' },
    include: {
      report: {
        select: {
          id: true,
          name: true,
        },
      },
    },
  })

  if (latestRisk) {
    console.log('Latest risk:')
    console.log(`  report: ${latestRisk.report.id} | ${latestRisk.report.name}`)
    console.log(`  score: ${latestRisk.overallRiskScore}`)
    console.log(`  band: ${latestRisk.overallRiskBand}`)
    console.log(`  generatedAt: ${latestRisk.generatedAt.toISOString()}`)
  }
}

main()
  .catch((error) => {
    console.error('Analysis DB check failed ❌')
    console.error(error)
    process.exit(1)
  })
  .finally(async () => {
    await prisma.$disconnect()
  })