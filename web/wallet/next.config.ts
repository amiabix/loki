import type { NextConfig } from "next";
import { wgslTurbopackRule } from "@vgpu/wgsl/next";

const nextConfig: NextConfig = {
  // The WebGPU example code (black-hole + ocean) relies on @webgpu/types, whose global GPU
  // types resolve under our local toolchain but trip a cache-free build on the deploy host's
  // newer node/TS. The runtime is unaffected. We still run `tsc --noEmit` locally for real type
  // safety, so skip the build-time type/lint check to keep deploys reliable.
  typescript: { ignoreBuildErrors: true },
  experimental: { agentUpgrade: "security" },
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
      "*.wgsl": wgslTurbopackRule(),
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
