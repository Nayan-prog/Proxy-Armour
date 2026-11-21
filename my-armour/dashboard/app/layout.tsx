import type { Metadata } from "next";
import "@fontsource-variable/inter";
import "@fontsource/comfortaa/latin-700.css";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: "Proxy Armour", template: "%s · Proxy Armour" },
  description: "Admin dashboard for the Proxy Armour LLM data-loss-prevention gateway",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full">{children}</body>
    </html>
  );
}
