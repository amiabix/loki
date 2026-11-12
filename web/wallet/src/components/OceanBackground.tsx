"use client";

import { useEffect, useRef, useState } from "react";
import { createRenderer } from "./ocean/renderer";

/**
 * The vgpu "FFT ocean" example (pulled via `npx vgpu examples pull fft-ocean`) as a blended
 * background layer over the Black Hole. The WebGPU renderer is preserved verbatim from the
 * example — `createRenderer({ canvas })`, its resize/visibility handling, and `dispose()`
 * resource cleanup are untouched. We only adapt the presentation:
 *   1. mount its canvas as a fixed full-screen layer above the galaxy (`-z-[9]`);
 *   2. `mix-blend-screen` + a slow opacity fade-in, so the ocean *merges into* the galaxy as a
 *      member enters a vault (the "crossing into another dimension" moment);
 *   3. a light mouse parallax (translate/scale driven by a CSS var) at a different rate from the
 *      galaxy's own parallax, giving layered depth — the sea drifts as you move the pointer.
 * It renders only while mounted (the logged-in screens), and the effect's cleanup disposes the
 * GPU graph and removes the listener, so two renderers never leak.
 */
export function OceanBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const layerRef = useRef<HTMLDivElement>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    let cancelled = false;
    let renderer: ReturnType<typeof createRenderer> | undefined;
    try {
      renderer = createRenderer({ canvas });
      renderer.ready.then(() => !cancelled && setReady(true)).catch(() => {});
    } catch {
      // No WebGPU / second context unavailable — the galaxy alone still looks right.
    }

    const onMove = (e: PointerEvent) => {
      const el = layerRef.current;
      if (!el) return;
      el.style.setProperty("--mx", String((e.clientX / window.innerWidth) * 2 - 1));
      el.style.setProperty("--my", String((e.clientY / window.innerHeight) * 2 - 1));
    };
    window.addEventListener("pointermove", onMove, { passive: true });

    return () => {
      cancelled = true;
      window.removeEventListener("pointermove", onMove);
      renderer?.dispose();
    };
  }, []);

  return (
    <div
      ref={layerRef}
      className={`pointer-events-none fixed inset-0 -z-[9] mix-blend-screen transition-opacity duration-[2200ms] ease-out ${
        ready ? "opacity-70" : "opacity-0"
      }`}
      style={{
        transform:
          "translate(calc(var(--mx, 0) * -26px), calc(var(--my, 0) * -20px)) scale(1.1)",
      }}
    >
      <canvas ref={canvasRef} className="h-full w-full" />
    </div>
  );
}
