import { Arg, Authorized, Ctx, Mutation, Resolver } from 'type-graphql'
import { Context } from '../../context'
import { LoginInput } from './auth.dto'
import { authService } from './auth.service'

@Resolver()
export class AuthResolver {
  private readonly service = authService

  @Mutation(() => String)
  async login(
    @Arg('input') input: LoginInput
  ): Promise<string> {
    return this.service.login(input)
  }

  @Authorized()
  @Mutation(() => Boolean)
  async logout(
    @Arg('token') token: string,
    @Ctx() context: Context
  ): Promise<boolean> {
    return this.service.logout(token, context.user.id)
  }

}