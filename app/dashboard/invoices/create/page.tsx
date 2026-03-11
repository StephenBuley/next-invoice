import type { Metadata } from 'next'
import Form from '@/app/ui/invoices/create-form'
import Breadcrumbs from '@/app/ui/invoices/breadcrumbs'
import { fetchCustomers } from '@/app/lib/data'
import { auth } from '@/auth'

export const metadata: Metadata = {
  title: 'Create Invoice',
}

export default async function Page() {
  const session = await auth()

  if (!session?.user?.id) throw new Error('Not authenticated')
  const customers = await fetchCustomers(session.user.id)

  return (
    <main>
      <Breadcrumbs
        breadcrumbs={[
          { label: 'Invoices', href: '/dashboard/invoices' },
          {
            label: 'Create Invoice',
            href: '/dashboard/invoices/create',
            active: true,
          },
        ]}
      />
      <Form customers={customers} />
    </main>
  )
}
