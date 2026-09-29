import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = { title: "Optiv Nexus | Investigation Operations", description: "Environment-aware security investigation workspace" };

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
