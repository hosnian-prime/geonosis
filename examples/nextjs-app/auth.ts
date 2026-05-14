// Auth.js v5 + Geonosis OIDC provider.
//
// Reads issuer / client_id / client_secret / NEXTAUTH_SECRET from env;
// the redirect URI is `${AUTH_URL}/api/auth/callback/geonosis`. The
// matching client config on the Geonosis side is `acme-web` from
// the quickstart bootstrap (see deploy/compose/quickstart.yml).

import NextAuth, { type NextAuthConfig } from "next-auth";

const issuer = process.env.GEONOSIS_ISSUER ?? "http://localhost:8080/realms/acme";
const clientId = process.env.GEONOSIS_CLIENT_ID ?? "acme-web";
const clientSecret = process.env.GEONOSIS_CLIENT_SECRET ?? "";

const config: NextAuthConfig = {
  providers: [
    {
      id: "geonosis",
      name: "Geonosis",
      type: "oidc",
      issuer,
      clientId,
      clientSecret,
      authorization: { params: { scope: "openid profile email" } },
      checks: ["pkce", "state"],
    },
  ],
  callbacks: {
    async jwt({ token, account }) {
      if (account?.access_token) {
        token.accessToken = account.access_token;
      }
      return token;
    },
    async session({ session, token }) {
      (session as any).accessToken = token.accessToken;
      return session;
    },
  },
};

export const { handlers, signIn, signOut, auth } = NextAuth(config);
