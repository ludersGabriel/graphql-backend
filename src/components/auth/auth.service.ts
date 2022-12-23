import jwt from 'jsonwebtoken'
import { AuthenticationError } from 'apollo-server'
import { checkPassword } from '../../auth'
import { userService } from '../user/user.service'
import { LoginInput } from './auth.dto'
import { sessionService } from '../session/session.service'


class AuthService {
  private readonly user = userService
  private readonly secret = process.env.APP_SECRET || ''
  private readonly session = sessionService

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
        expiresIn: '1m'
      }
    )

    this.session.create(
      {
        token: token,
        userId: user.id,
      }
    )

    return token
  }

  async logout(token: string, userId: string): Promise<boolean> {
    const session = await this.session.findByTokenAndUser(token, userId)

    await this.session.update(
      {
        id: session.id,
        active: false
      }
    )

    return true
  }
}

export const authService = new AuthService()