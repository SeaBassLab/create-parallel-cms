import { Suspense } from "react"
import Link from "next/link"
import Layout from "src/core/layouts/Layout"
import { useCurrentUser } from "src/users/hooks/useCurrentUser"
import logout from "src/auth/mutations/logout"
import { useMutation } from "@blitzjs/rpc"
import { Routes, BlitzPage } from "@blitzjs/next"
import styles from "src/styles/Home.module.css"
import { Button } from "parallel-ui"
/*
 * This file is just for a pleasant getting started page for your new app.
 * You can delete everything in here and start from scratch if you like.
 */

const UserInfo = () => {
  const currentUser = useCurrentUser()
  const [logoutMutation] = useMutation(logout)

  if (currentUser) {
    return (
      <>
        <Button
          label="Logout"
          className={styles.button}
          onClick={async () => {
            await logoutMutation()
          }}
        />
        <div>
          User id: <code>{currentUser.id}</code>
          <br />
          User role: <code>{currentUser.role}</code>
        </div>
      </>
    )
  } else {
    return (
      <>
        <Link href={Routes.SignupPage()}>
          <Button className={styles.button} size="large" label="Sign Up" />
        </Link>
        <Link href={Routes.LoginPage()}>
          <Button className={styles.loginButton} size="large" hierarchy="tertiary" label="Login" />
        </Link>
      </>
    )
  }
}

const Home: BlitzPage = () => {
  return (
    <Layout title="Home">
      <Suspense fallback="Loading...">
        <UserInfo />
      </Suspense>
    </Layout>
  )
}

export default Home
