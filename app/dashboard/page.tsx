import DashboardClient from '@/components/DashboardClient'
import { getDashboardMetrics, getFindings, getFindingsTrend, getReports } from '@/lib/data-service'

export const dynamic = 'force-dynamic'

export default async function DashboardPage() {
  const [kpis, findingsTrend, findings, reports] = await Promise.all([
    getDashboardMetrics(),
    getFindingsTrend(),
    getFindings(),
    getReports(),
  ])

  return (
    <DashboardClient
      kpis={kpis}
      findingsTrend={findingsTrend}
      findings={findings}
      reports={reports}
    />
  )
}