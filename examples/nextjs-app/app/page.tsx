import { auth, signIn, signOut } from "../auth";

export default async function Home() {
  const session = await auth();
  return (
    <main>
      <h1>Geonosis + Next.js</h1>
      <p>
        Minimal OIDC client wired against the realm from the quickstart
        stack (<code>acme</code>, client <code>master-web</code>).
      </p>
      {session?.user ? (
        <section>
          <h2>Signed in</h2>
          <pre style={{ background: "#f4f4f4", padding: "1rem", borderRadius: 4 }}>
            {JSON.stringify(session.user, null, 2)}
          </pre>
          <p>
            Access token is on{" "}
            <code>(session as any).accessToken</code>. Use it as the{" "}
            <code>Authorization: Bearer …</code> header against the
            axum-resource-server example at{" "}
            <code>http://localhost:7000/me</code>.
          </p>
          <form
            action={async () => {
              "use server";
              await signOut();
            }}
          >
            <button type="submit">Sign out</button>
          </form>
        </section>
      ) : (
        <section>
          <h2>Not signed in</h2>
          <form
            action={async () => {
              "use server";
              await signIn("geonosis");
            }}
          >
            <button type="submit">Sign in with Geonosis</button>
          </form>
        </section>
      )}
    </main>
  );
}
