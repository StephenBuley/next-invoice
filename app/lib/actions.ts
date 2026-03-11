'use server'

import { z } from 'zod'
import postgres from 'postgres'
import { revalidatePath } from 'next/cache'
import { redirect } from 'next/navigation'
import { signIn } from '@/auth'
import { AuthError } from 'next-auth'
import { createUser, existsUserByEmail } from './data'
import bcrypt from 'bcrypt'

const sql = postgres(
  process.env.POSTGRES_URL!,
  // { ssl: 'require' }
)

const UserSchema = z.object({
  id: z.string().uuid(),
  name: z.string(),
  email: z.string().email({ message: 'Please enter a valid email address' }),
  password: z
    .string()
    .min(6, { message: 'Password must be at least 6 characters' }),
})

type User = z.infer<typeof UserSchema>

const UserFormSchema = UserSchema.omit({ id: true })

const FormSchema = z.object({
  id: z.string(),
  customerId: z.string({ invalid_type_error: 'Please select a customer.' }),
  amount: z.coerce
    .number()
    .gt(0, { message: 'Amount must be greater than 0.' }),
  status: z.enum(['pending', 'paid'], {
    invalid_type_error: 'Please select a status.',
  }),
  date: z.string(),
})

const CreateInvoiceSchema = FormSchema.omit({ id: true, date: true })

const UpdateInvoice = FormSchema.omit({ id: true, date: true })

type FormState<T extends z.ZodTypeAny> = {
  errors?: Partial<Record<keyof z.infer<T>, string[]>>
  message?: string | null
}

export type State = FormState<typeof CreateInvoiceSchema>

export async function createInvoice(prevState: State, formData: FormData) {
  const rawFormData = Object.fromEntries(formData)
  const validatedFields = CreateInvoiceSchema.safeParse(rawFormData)
  if (!validatedFields.success) {
    return {
      errors: validatedFields.error.flatten().fieldErrors,
      message: 'Missing fields, failed to create invoice.',
    }
  }
  const { customerId, amount, status } = validatedFields.data
  const amountInCents = amount * 100
  const date = new Date().toISOString().split('T')[0]
  try {
    await sql`
    INSERT INTO invoices (customer_id, amount, status, date)
    VALUES (${customerId}, ${amountInCents}, ${status}, ${date})
  `
  } catch (error) {
    console.error('Database Error creating invoice:', error)
    return { message: 'Database Error: Failed to create invoice.' }
  }
  revalidatePath('/dashboard/invoices')
  redirect('/dashboard/invoices')
}

export async function updateInvoice(
  id: string,
  prevState: State,
  formData: FormData,
) {
  const rawFormData = Object.fromEntries(formData)
  const validatedFields = UpdateInvoice.safeParse(rawFormData)
  if (!validatedFields.success) {
    return {
      errors: validatedFields.error.flatten().fieldErrors,
      message: 'Missing fields, failed to update invoice.',
    }
  }
  const { customerId, amount, status } = validatedFields.data
  const amountInCents = Math.round(amount * 100)
  try {
    await sql`
    UPDATE invoices
    SET customer_id = ${customerId}, amount = ${amountInCents}, status = ${status}
    WHERE id = ${id}
  `
  } catch (error) {
    console.error('Database Error updating invoice:', error)
    return { message: 'Failed to update invoice.' }
  }
  revalidatePath('/dashboard/invoices')
  redirect('/dashboard/invoices')
}

export async function deleteInvoice(id: string) {
  await sql`
    DELETE FROM invoices
    WHERE id = ${id}
  `
  revalidatePath('/dashboard/invoices')
}

export async function authenticate(
  prevState: string | undefined,
  formData: FormData,
) {
  try {
    await signIn('credentials', formData)
  } catch (error) {
    if (error instanceof AuthError) {
      switch (error.type) {
        case 'CredentialsSignin':
          return 'Invalid email or password.'
        default:
          return 'An unexpected error occurred. Please try again.'
      }
    }
    throw error
  }
}

export type UserFormState = FormState<typeof UserFormSchema>

export async function register(prevState: UserFormState, formData: FormData) {
  // validate form data
  const rawFormData = Object.fromEntries(formData)
  const validatedFields = UserFormSchema.safeParse(rawFormData)
  // if !valid, return error message to display
  if (!validatedFields.success) {
    console.log('error!')
    return {
      errors: validatedFields.error.flatten().fieldErrors,
      message: 'Invalid inputs',
    }
  }
  // we need to make sure that email doesn't already exist
  const { name, email, password } = validatedFields.data
  const exists = await existsUserByEmail(email)
  let hashedPassword = null
  try {
    hashedPassword = await bcrypt.hash(password, 10)
  } catch (error) {
    console.error('Error hashing password: ', error)
    throw new Error('Error hashing password')
  }
  if (exists) {
    return {
      message: 'Email already associated with an account.',
    }
  }
  try {
    // if it is valid, save the information to the database
    await createUser(name, email, hashedPassword)
  } catch (error) {
    // return some error message if there was a database or unexpected error
    console.error('Database error: ', error)
    throw new Error('Something went wrong creating a new user')
  }
  redirect('/dashboard')
}
