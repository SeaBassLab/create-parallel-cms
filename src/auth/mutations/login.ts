import { SecurePassword } from "@blitzjs/auth"
import { resolver } from "@blitzjs/rpc"
import { AuthenticationError } from "blitz"
import db from "db"
import { Login } from "../validations"

export const authenticateUser = async (rawEmail: string, rawPassword: string) => {
  const { email, password } = Login.parse({ email: rawEmail, password: rawPassword })
  const user = await db.user.findFirst({
    where: { email },
    include: {
      memberships: true,
    },
  })
  if (!user) throw new AuthenticationError()

  const result = await SecurePassword.verify(user.hashedPassword, password)

  if (result === SecurePassword.VALID_NEEDS_REHASH) {
    // Upgrade hashed password with a more secure hash
    const improvedHash = await SecurePassword.hash(password)
    await db.user.update({ where: { id: user.id }, data: { hashedPassword: improvedHash } })
  }

  const { hashedPassword, ...rest } = user
  return rest
}

export default resolver.pipe(resolver.zod(Login), async ({ email, password }, ctx) => {
  // This throws an error if credentials are invalid
  const user = await authenticateUser(email, password)

  if (!user.memberships[0]) {
    throw new Error("No membership assosiated to this user")
  }
  if (!user.memberships[0].role) {
    throw new Error("No role assosiated to this membership")
  }
  if (!user.memberships[0].organizationId) {
    throw new Error("No organizationId assosiated to this membership")
  }
  const membershipRole = user.memberships[0].role
  const organizationId = user.memberships[0]?.organizationId

  await ctx.session.$create({
    userId: user.id,
    roles: [user.role, membershipRole],
    orgId: organizationId,
  })

  return user
})
