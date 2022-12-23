import 'reflect-metadata'

import { ApolloServer } from 'apollo-server'
import path from 'path'
import { buildSchema } from 'type-graphql'
import { authChecker, getUser } from './auth'

const main  = async () => {
  const schema = await buildSchema({
    resolvers: [ path.join(__dirname, '/components/**/*.resolver.{ts,js}') ],
    authChecker
  })

  const server = new ApolloServer({
    schema,
    context: async ({ req }) => {
      const token = req.headers.authorization || ''

      const { user } = await getUser(token)

      return {
        user
      }
    }
  })

  server
    .listen(process.env.PORT || 4000)
    .then(({ url }) => console.log(`Server is running, GraphQL Playground available at ${url}`))
}

main()
  .catch(e => {
    throw e
  })