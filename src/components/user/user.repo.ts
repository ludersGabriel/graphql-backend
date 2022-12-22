import { User } from '@prisma/client'
import { prisma } from '../../context'

class UserRepo{
  private readonly prisma = prisma

  async find(id: string): Promise<User> {
    return this.prisma.user.findUniqueOrThrow({
      where: {
        id
      }
    })
  }

  async findMany(): Promise<User[]> {
    return this.prisma.user.findMany()
  }

  async findByUsername(username: string): Promise<User> {
    return this.prisma.user.findUniqueOrThrow({
      where: {
        username
      }
    })
  }

}

export const userRepo = new UserRepo()