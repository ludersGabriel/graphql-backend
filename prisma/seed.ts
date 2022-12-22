import { PrismaClient } from '@prisma/client'
import 'colors'
import { userSeed } from './seeders/user'

export const prisma = new PrismaClient()

async function main () {
  await userSeed()  

}

main()
  .catch(e => {
    throw e
  })
  .finally(async () => {
    await prisma.$disconnect()
  })