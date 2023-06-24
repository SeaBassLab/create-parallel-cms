import { SecurePassword } from "@blitzjs/auth"
import { resolver } from "@blitzjs/rpc"
import db from "db"
import { Signup } from "../validations"

export default resolver.pipe(
  resolver.zod(Signup),
  async ({ email, password, membershipRole, globalRole, organizationName }, ctx) => {
    const hashedPassword = await SecurePassword.hash(password.trim())
    const user = await db.user.create({
      data: {
        email: email.toLowerCase().trim(),
        hashedPassword,
        role: globalRole,
        memberships: {
          create: {
            role: membershipRole,
            organization: {
              create: {
                name: organizationName,
              },
            },
          },
        },
      },
      include: { memberships: true },
    })

    await ctx.session.$create({ userId: user.id, roles: [user.role, membershipRole] })
    return user
  }
)
