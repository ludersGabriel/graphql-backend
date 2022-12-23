import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { AuthenticationError } from 'apollo-server'
import { Context, defaultUser } from './context'
import { userRepo } from './components/user/user.repo'
import { AuthChecker } from 'type-graphql'
import { sessionService } from './components/session/session.service'

export const hash = (str: string): Promise<string> => bcrypt.hash(str, 12)

export const checkPassword = (
  inputPassword: string,
  hashedPassword: string
):Promise<boolean> => bcrypt.compare(inputPassword, hashedPassword)


const getTokenPayload = async (token: string): Promise<Context> => {
  const session = sessionService
  
  try {
    return jwt.verify(token, process.env.APP_SECRET || '') as Context
  } catch (e){
    console.log({ e, token })
    const sessionData = await session.findByToken(token)

    if(sessionData){
      await session.update({
        id: sessionData.id,
        active: false
      })
    }

    return { user: defaultUser }
  }
}

export const getUser = async (token: string): Promise<Context> => {
  return getTokenPayload(token)
}

export const AuthError = () => new AuthenticationError('user not authenticaded or not found')

export const RoleError = () => new AuthenticationError('wrong permissions to use this endpoint')

export const OwnerError = () => new AuthenticationError('wrong ownership to use this endpoint')

export const authChecker: AuthChecker<Context> = async (
  { context },
  roles
) => {
  try{
    await userRepo.find(context.user.id)
  }
  catch{
    throw AuthError()
  }

  if (roles.length > 0 && !roles.includes(context.user.role)) throw RoleError()

  // if (user?.count !== context.user.count) throw AuthError()

  return true
}
