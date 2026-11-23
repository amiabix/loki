import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { signerOrigin } from "../lib/signer-config";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Loki — Shielded Multisig",
  description: "A shielded Zcash multisig wallet.",
};

export const dynamic = "force-dynamic";

function runtimeSignerOrigin(): string | undefined {
  try { return signerOrigin(); } catch { return undefined; }
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const origin = runtimeSignerOrigin();
  return (
    <html
      lang="en"
      suppressHydrationWarning
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <head>
        {origin && <meta name="loki-signer-origin" content={origin} />}
        <script
          dangerouslySetInnerHTML={{
            __html:
              "try{var t=localStorage.getItem('loki_theme');if(t==='light'||t==='dark')document.documentElement.setAttribute('data-theme',t)}catch(e){}",
          }}
        />
      </head>
      <body>{children}</body>
    </html>
  );
}
