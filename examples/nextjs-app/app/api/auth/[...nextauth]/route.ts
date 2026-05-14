// Auth.js v5 catch-all route. Exposes:
//   GET /api/auth/signin
//   GET /api/auth/signout
//   GET /api/auth/callback/geonosis
//   GET /api/auth/session
//   ...
//
// All wired through the NextAuth handler from ../../../../auth.ts.

import { handlers } from "../../../../auth";

export const { GET, POST } = handlers;
