import jwt from 'jsonwebtoken'
import { AuthenticationError } from 'apollo-server'
import { checkPassword } from '../../auth'
import { userService } from '../user/user.service'
import { LoginInput } from './auth.dto'


class AuthService {
  private readonly user = userService
  private readonly secret = process.env.APP_SECRET || ''

  async login(
    input: LoginInput
  ): Promise<string> {
    const user = await this.user.findByUsername(input.username)

    const isValid = await checkPassword(input.password, user.password)
    if(!isValid) throw new AuthenticationError('Senha inválida')

    const token = jwt.sign(
      { user: { id: user.id, role: user.role, username: user.username } },
      this.secret,
      {
        expiresIn: '30m'
      }
    )

    return token
  }
}

export const authService = new AuthService()