import { Arg, Mutation, Resolver } from 'type-graphql'
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

}