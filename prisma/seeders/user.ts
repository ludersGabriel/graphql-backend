import bcrypt from 'bcryptjs'
import { prisma } from '../seed'

const hash = (str: string): Promise<string> => bcrypt.hash(str, 12)

export const userSeed = async () => {
  try {
    await Promise.all([ prisma.user.create({
      data: {
        name: 'john doe admin',
        username: 'admin',
        password: await hash('1234mudar'),
        role: 'ADMIN',
        id: '21502fea-3df0-4fe5-945d-270fa7488892'
      }
    }), prisma.user.create({
      data: {
        name: 'john doe user',
        username: 'user',
        password: await hash('1234mudar'),
        role: 'USER',
        id: '4132fea-3df0-4fe5-945d-270fa7488893'
      }
    }) ])

    console.log('\t[+] users inserted'.green)
  } catch (e) {
    console.log(`\t[-] error inserting users ${e}`.red)
  }
}
