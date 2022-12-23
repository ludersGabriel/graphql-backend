import { Session } from '@prisma/client'
import { prisma } from '../../context'
import { SessionInput, SessionUpdateInput } from './session.dto'


class SessionRepo {
  private readonly prisma = prisma

  async find(id: string): Promise<Session | null> {
    return this.prisma.session.findUnique({
      where: {
        id
      }
    })
  }

  async findByUser(
    userId: string
  ): Promise<Session[]> {
    return this.prisma.session.findMany({
      where: {
        userId
      }
    })
  }

  async findByTokenAndUser(
    token: string,
    userId: string
  ): Promise<Session> {
    return this.prisma.session.findUniqueOrThrow({
      where: {
        token_userId: {
          token,
          userId
        }
      }
    })
  }

  async findByToken(token: string): Promise<Session | null> {
    return this.prisma.session.findUnique({
      where: {
        token
      }
    })
  }

  async create(input: SessionInput): Promise<Session> {
    return this.prisma.session.create({
      data: {
        device: input.device,
        token: input.token,
        user: {
          connect: {
            id: input.userId
          }
        }
      }
    })
  }

  async delete(id: string): Promise<Session> {
    return this.prisma.session.delete({
      where: {
        id
      }
    })
  }

  async update(input: SessionUpdateInput): Promise<Session> {
    return this.prisma.session.update({
      where: {
        id: input.id
      },
      data: {
        ...input
      }
    })
  }
}

export const sessionRepo = new SessionRepo()