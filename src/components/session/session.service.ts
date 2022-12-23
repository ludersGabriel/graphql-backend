import { SessionInput, SessionUpdateInput } from './session.dto'
import { sessionRepo } from './session.repo'


class SessionService {
  private readonly repo = sessionRepo

  async find(id: string) {
    return this.repo.find(id)
  }

  async findByUser(userId: string) {
    return this.repo.findByUser(userId)
  }

  async create(input: SessionInput) {
    return this.repo.create(input)
  }

  async delete(id: string) {
    return this.repo.delete(id)
  }

  async update(input: SessionUpdateInput) {
    return this.repo.update(input)
  }

  async findByTokenAndUser(token: string, userId: string) {
    return this.repo.findByTokenAndUser(token, userId)
  }

  async findByToken(token: string) {
    return this.repo.findByToken(token)
  }
}

export const sessionService = new SessionService()