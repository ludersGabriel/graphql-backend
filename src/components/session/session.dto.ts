import { Field, ID, InputType } from 'type-graphql'


@InputType()
export class SessionInput {
  @Field(() => ID)
    userId: string
  
  @Field(() => String)
    token: string

  @Field(() => String, { nullable: true })
    device?: string
}

@InputType()
export class SessionUpdateInput {
  @Field(() => ID)
    id: string

  @Field(() => String, { nullable: true })
    token?: string

  @Field(() => String, { nullable: true })
    device?: string

  @Field(() => Boolean, { nullable: true })
    active?: boolean
}