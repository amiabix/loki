"use client";

import { useEffect, useRef, useState } from "react";
import { createRenderer } from "./black-hole/renderer";

/**
 * The vgpu "Optimized Black Hole" renderer, mounted as a fixed full-screen background.
 *
 * Adapted from the pulled example's `index.tsx`: the WebGPU pipeline, resize/visibility
 * handling, and `dispose()` cleanup are preserved verbatim — we only (1) position the
 * canvas as a fixed `-z-10` background, (2) make it `pointer-events-none` so UI on top
 * stays clickable (the renderer reads pointer parallax from `window`, so this is safe),
 * and (3) add a radial-glow fallback for browsers without WebGPU.
 */
export function BlackHoleBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [ready, setReady] = useState(false);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    let cancelled = false;
    let renderer: ReturnType<typeof createRenderer> | undefined;
    try {
      renderer = createRenderer({ canvas });
      renderer.ready
        .then(() => !cancelled && setReady(true))
        .catch(() => !cancelled && setFailed(true));
    } catch {
      setFailed(true);
    }
    return () => {
      cancelled = true;
      renderer?.dispose();
    };
  }, []);

  return (
    <div className="pointer-events-none fixed inset-0 -z-10 bg-black">
      {failed && (
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_50%_40%,rgba(62,230,160,0.1),transparent_60%)]" />
      )}
      <canvas
        ref={canvasRef}
        className={`h-full w-full transition-opacity duration-700 ${
          ready ? "opacity-100" : "opacity-0"
        }`}
      />
    </div>
  );
}
