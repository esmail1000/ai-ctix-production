import { cookies } from 'next/headers'
import { isValidWafAdminSession, WAF_ADMIN_COOKIE } from '@/app/api/admin/waf/_shared'
import WafAdminClient from './WafAdminClient'
import WafLoginClient from './WafLoginClient'

export const dynamic = 'force-dynamic'

export default async function WafAdminControlPage() {
  const cookieStore = await cookies()
  const session = cookieStore.get(WAF_ADMIN_COOKIE)?.value || ''

  if (!isValidWafAdminSession(session)) {
    return <WafLoginClient />
  }

  return <WafAdminClient />
}
