// This file contains placeholder data that you'll be replacing with real data in the Data Fetching chapter:
// https://nextjs.org/learn/dashboard-app/fetching-data
const users = [
  {
    id: '410544b2-4001-4271-9855-fec4b6a6442a',
    name: 'User',
    email: 'user@nextmail.com',
    password: '123456',
  },
  {
    id: '86547b82-8af8-48c6-a5a1-63831673d218',
    name: 'Johnny Appleseed',
    email: 'johnnya@apple.com',
    password: '123098',
  },
]

const customers = [
  {
    id: 'd6e15727-9fe1-4961-8c5b-ea44a9bd81aa',
    name: 'Evil Rabbit',
    email: 'evil@rabbit.com',
    image_url: '/customers/evil-rabbit.png',
    user_id: users[0].id,
  },
  {
    id: '3958dc9e-712f-4377-85e9-fec4b6a6442a',
    name: 'Delba de Oliveira',
    email: 'delba@oliveira.com',
    image_url: '/customers/delba-de-oliveira.png',
    user_id: users[0].id,
  },
  {
    id: '3958dc9e-742f-4377-85e9-fec4b6a6442a',
    name: 'Lee Robinson',
    email: 'lee@robinson.com',
    image_url: '/customers/lee-robinson.png',
    user_id: users[0].id,
  },
  {
    id: '76d65c26-f784-44a2-ac19-586678f7c2f2',
    name: 'Michael Novotny',
    email: 'michael@novotny.com',
    image_url: '/customers/michael-novotny.png',
    user_id: users[1].id,
  },
  {
    id: 'CC27C14A-0ACF-4F4A-A6C9-D45682C144B9',
    name: 'Amy Burns',
    email: 'amy@burns.com',
    image_url: '/customers/amy-burns.png',
    user_id: users[1].id,
  },
  {
    id: '13D07535-C59E-4157-A011-F8D2EF4E0CBB',
    name: 'Balazs Orban',
    email: 'balazs@orban.com',
    image_url: '/customers/balazs-orban.png',
    user_id: users[1].id,
  },
]

const invoices = [
  {
    customer_id: customers[0].id,
    amount: 15795,
    status: 'pending',
    date: '2022-12-06',
  },
  {
    customer_id: customers[1].id,
    amount: 20348,
    status: 'pending',
    date: '2022-11-14',
  },
  {
    customer_id: customers[4].id,
    amount: 3040,
    status: 'paid',
    date: '2022-10-29',
  },
  {
    customer_id: customers[3].id,
    amount: 44800,
    status: 'paid',
    date: '2023-09-10',
  },
  {
    customer_id: customers[5].id,
    amount: 34577,
    status: 'pending',
    date: '2023-08-05',
  },
  {
    customer_id: customers[2].id,
    amount: 54246,
    status: 'pending',
    date: '2023-07-16',
  },
  {
    customer_id: customers[0].id,
    amount: 666,
    status: 'pending',
    date: '2023-06-27',
  },
  {
    customer_id: customers[3].id,
    amount: 32545,
    status: 'paid',
    date: '2023-06-09',
  },
  {
    customer_id: customers[4].id,
    amount: 1250,
    status: 'paid',
    date: '2023-06-17',
  },
  {
    customer_id: customers[5].id,
    amount: 8546,
    status: 'paid',
    date: '2023-06-07',
  },
  {
    customer_id: customers[1].id,
    amount: 500,
    status: 'paid',
    date: '2023-08-19',
  },
  {
    customer_id: customers[5].id,
    amount: 8945,
    status: 'paid',
    date: '2023-06-03',
  },
  {
    customer_id: customers[2].id,
    amount: 1000,
    status: 'paid',
    date: '2022-06-05',
  },
]

const revenue = [
  { month: 'Jan', revenue: 2000, user_id: users[1].id },
  { month: 'Feb', revenue: 1800, user_id: users[1].id },
  { month: 'Mar', revenue: 2200, user_id: users[1].id },
  { month: 'Apr', revenue: 2500, user_id: users[1].id },
  { month: 'May', revenue: 2300, user_id: users[1].id },
  { month: 'Jun', revenue: 3200, user_id: users[1].id },
  { month: 'Jul', revenue: 3500, user_id: users[1].id },
  { month: 'Aug', revenue: 3700, user_id: users[1].id },
  { month: 'Sep', revenue: 2500, user_id: users[1].id },
  { month: 'Oct', revenue: 2800, user_id: users[1].id },
  { month: 'Nov', revenue: 3000, user_id: users[1].id },
  { month: 'Dec', revenue: 4800, user_id: users[1].id },
  { month: 'Jan', revenue: 1000, user_id: users[0].id },
  { month: 'Feb', revenue: 1000, user_id: users[0].id },
  { month: 'Mar', revenue: 2000, user_id: users[0].id },
  { month: 'Apr', revenue: 2100, user_id: users[0].id },
  { month: 'May', revenue: 2300, user_id: users[0].id },
  { month: 'Jun', revenue: 3200, user_id: users[0].id },
  { month: 'Jul', revenue: 3500, user_id: users[0].id },
  { month: 'Aug', revenue: 3700, user_id: users[0].id },
  { month: 'Sep', revenue: 3000, user_id: users[0].id },
  { month: 'Oct', revenue: 2800, user_id: users[0].id },
  { month: 'Nov', revenue: 3000, user_id: users[0].id },
  { month: 'Dec', revenue: 2800, user_id: users[0].id },
]

export { users, customers, invoices, revenue }
