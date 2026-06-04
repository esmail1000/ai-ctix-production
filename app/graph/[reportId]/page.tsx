import { redirect } from 'next/navigation'

export default async function GraphReportRedirect({
  params,
}: {
  params: Promise<{ reportId: string }>
}) {
  const { reportId } = await params

  redirect(`/graph?reportId=${encodeURIComponent(reportId)}`)
}