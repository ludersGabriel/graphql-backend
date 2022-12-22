import { User } from '@prisma/client'
import { userRepo } from './user.repo'

class UserService {
  private readonly repo = userRepo

  async find(id: string): Promise<User> {
    return this.repo.find(id)
  }

  async findMany(): Promise<User[]> {
    return this.repo.findMany()
  }

  async findByUsername(username: string): Promise<User> {
    return this.repo.findByUsername(username)
  }

}

export const userService = new UserService()