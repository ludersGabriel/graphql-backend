import { Role } from '@prisma/client'
import { Arg, Authorized, Ctx, Mutation, Query, Resolver } from 'type-graphql'
import { Context } from '../../context'
import { User } from './user.dto'
import { userService } from './user.service'

@Resolver(User)
export class UserResolver {
  private readonly service = userService
  
  @Authorized(Role.ADMIN)
  @Query(() => User)
  async findUser(
    @Arg('userId') userId: string,
  ): Promise<User> {
    return this.service.find(userId)
  }

  @Authorized(Role.ADMIN)
  @Query(() => [ User ])
  async findUsers(): Promise<User[]> {
    return this.service.findMany()
  }

  @Authorized()
  @Mutation(() => User)
  async me(
    @Ctx() context: Context
  ): Promise<User> {
    return this.service.find(context.user.id)
  }
}