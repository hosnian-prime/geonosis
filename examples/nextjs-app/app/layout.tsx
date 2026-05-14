import type { ReactNode } from "react";

export const metadata = {
  title: "Geonosis Next.js example",
  description: "Minimal OIDC client wired against the Geonosis quickstart.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body
        style={{
          fontFamily: "system-ui, sans-serif",
          maxWidth: 720,
          margin: "3rem auto",
          padding: "0 1rem",
          lineHeight: 1.5,
        }}
      >
        {children}
      </body>
    </html>
  );
}
