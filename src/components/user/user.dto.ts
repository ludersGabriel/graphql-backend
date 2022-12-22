import { Role } from '@prisma/client'
import { Field, ID, ObjectType, registerEnumType } from 'type-graphql'

registerEnumType(Role, { name: 'Role' })

@ObjectType()
export class User {
  @Field(() => ID)
    id: string

  @Field(() => String)
    username: string

  @Field(() => String)
    name: string

  @Field(() => Role)
    role: Role
}