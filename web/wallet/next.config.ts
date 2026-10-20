import type { NextConfig } from "next";
import { wgslTurbopackRule } from "@vgpu/wgsl/next";

const nextConfig: NextConfig = {
  /* config options here */
  cacheComponents: true,
  partialPrefetching: true,
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
      "*.wgsl": wgslTurbopackRule(),
    },
  },
};

export default nextConfig;
