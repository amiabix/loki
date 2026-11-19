import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  experimental: { agentUpgrade: "security" },
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
  // Turbopack names the app chunk stably, so a code change can reuse a filename with new
  // content. Served `immutable` (the default), that leaves returning visitors on stale JS after
  // every deploy. Instead: always revalidate static chunks (ETag → 304 if unchanged, fresh JS if
  // changed), and never cache the HTML shell so it always references the current build.
  async headers() {
    return [
      {
        source: "/_next/static/:path*",
        headers: [{ key: "Cache-Control", value: "public, max-age=0, must-revalidate" }],
      },
      {
        source: "/((?!_next/static).*)",
        headers: [{ key: "Cache-Control", value: "no-store, must-revalidate" }],
      },
    ];
  },
};

export default nextConfig;
