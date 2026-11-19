"use client";

import { useEffect, useRef } from "react";
import { useIsDark } from "@/lib/theme";

// The "vault tunnel": ellipses receding to a vanishing point, radial lines through them,
// and particles rising inside the mouth. 2D canvas; colours come from globals.css tokens.
type Disc = { p: number; x: number; y: number; w: number; h: number };
type Particle = { x: number; sx: number; dx: number; y: number; vy: number; r: number; a: number };

const DISCS = 100;
const LINES = 100;
const PARTICLES = 100;
const TAU = Math.PI * 2;
const linear = (t: number) => t;
const easeInExpo = (t: number) => (t === 0 ? 0 : Math.pow(2, 10 * t - 10));
const lerp = (a: number, b: number, t: number) => a + (b - a) * t;
// Aura: emerald → gold → back, scrolled one full tile every 5 s (the reference's CSS loop).
const AURA_STOPS: [number, string][] = [
  [0, "#2fd8a8"], [0.165, "#e8b44a20"], [0.33, "#e8b44a"], [0.495, "#2fd8a820"],
  [0.66, "#2fd8a8"], [0.855, "#e8b44a60"], [1, "#2fd8a8"],
];
const AURA_PERIOD = 5000;
const AURA_SCALE = 0.5; // a soft gradient; half resolution is indistinguishable

export function LokiTunnel({ calm = false }: { calm?: boolean }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const linesRef = useRef<HTMLCanvasElement>(null);
  const auraRef = useRef<HTMLCanvasElement>(null);
  const dark = useIsDark();

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext("2d");
    const lines = linesRef.current;
    const lctx = lines?.getContext("2d");
    const aura = auraRef.current;
    const actx = aura?.getContext("2d");
    if (!canvas || !ctx || !lines || !lctx || !aura || !actx) return;
    const css = getComputedStyle(document.documentElement);
    const stroke = css.getPropertyValue("--tunnel-line").trim();
    const dot = css.getPropertyValue("--tunnel-particle").trim();
    const dotAlpha = parseFloat(css.getPropertyValue("--tunnel-particle-alpha")) || 1;
    // Calm (send/review) and reduced motion both get one static frame.
    const still = calm || window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    let w = 0, h = 0, dpr = 1;
    let start = { x: 0, y: 0, w: 0, h: 0 };
    let end = { x: 0, y: 0 };
    let clip = { x: 0, y: 0, w: 0, h: 0 };
    let clipPath = new Path2D();
    let discs: Disc[] = [];
    let particles: Particle[] = [];
    let area = { x1: 0, sw: 0, x2: 0, ew: 0, h: 0 };
    let auraTile: OffscreenCanvas | null = null;
    let now = 0;

    const tween = (d: Disc) => {
      d.x = lerp(start.x, end.x, linear(d.p));
      d.y = lerp(start.y, end.y, easeInExpo(d.p));
      d.w = lerp(start.w, 0, linear(d.p));
      d.h = lerp(start.h, 0, linear(d.p));
    };
    const inClip = (x: number, y: number) =>
      ((x - clip.x) / clip.w) ** 2 + ((y - clip.y) / clip.h) ** 2 <= 1 ||
      (y <= clip.y && Math.abs(x - clip.x) <= clip.w);
    const newParticle = (anywhere: boolean): Particle => {
      const sx = area.x1 + Math.random() * area.sw;
      const ex = area.x2 + Math.random() * area.ew;
      return {
        x: sx, sx, dx: ex - sx,
        y: anywhere ? Math.random() * area.h : area.h,
        vy: 0.5 + Math.random(),
        r: 0.5 + Math.random() * 4,
        a: 0.2 + Math.random() * 0.7,
      };
    };

    const setup = () => {
      const rect = canvas.getBoundingClientRect();
      w = rect.width; h = rect.height;
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      // The moving layer redraws 30 times a second, so it renders at 1x; the static lines stay sharp.
      canvas.width = Math.round(w);
      canvas.height = Math.round(h);
      // Shifted down from the reference (.45/.95) so the mouth sits behind the content.
      start = { x: w * 0.5, y: h * 0.58, w: w * 0.75, h: h * 0.7 };
      end = { x: w * 0.5, y: h * 1.08 };

      // The clip disc is where the discs' bottom edge stops rising and starts falling.
      discs = [];
      let prevBottom = h;
      for (let i = 0; i < DISCS; i++) {
        const d = { p: i / DISCS, x: 0, y: 0, w: 0, h: 0 };
        tween(d);
        const bottom = d.y + d.h;
        if (bottom <= prevBottom) clip = { x: d.x, y: d.y, w: d.w, h: d.h };
        prevBottom = bottom;
        discs.push(d);
      }
      clipPath = new Path2D();
      clipPath.ellipse(clip.x, clip.y, clip.w, clip.h, 0, 0, TAU);
      clipPath.rect(clip.x - clip.w, 0, clip.w * 2, clip.y);

      // Radial lines through every disc: static, so drawn once on their own canvas underneath.
      lines.width = Math.round(w * dpr);
      lines.height = Math.round(h * dpr);
      lctx.scale(dpr, dpr);
      lctx.strokeStyle = stroke;
      lctx.lineWidth = 2;
      for (let i = 0; i < LINES; i++) {
        const angle = (i / LINES) * TAU;
        const pts = discs.map((d) => ({ x: d.x + Math.cos(angle) * d.w, y: d.y + Math.sin(angle) * d.h }));
        lctx.save();
        let inside = false, clipped = false;
        for (let j = 1; j < pts.length; j++) {
          if (!inside && inClip(pts[j].x, pts[j].y)) inside = true;
          else if (inside && !clipped) { lctx.clip(clipPath); clipped = true; }
          lctx.beginPath();
          lctx.moveTo(pts[j - 1].x, pts[j - 1].y);
          lctx.lineTo(pts[j].x, pts[j].y);
          lctx.stroke();
        }
        lctx.restore();
      }

      const sw = clip.w * 0.5, ew = clip.w * 2;
      area = { sw, ew, h: h * 0.85, x1: clip.x - sw / 2, x2: clip.x - ew / 2 };
      particles = Array.from({ length: PARTICLES }, () => newParticle(true));

      // Aura tile: the 20deg gradient over twice the aura's height, painted once.
      const ar = aura.getBoundingClientRect();
      aura.width = Math.max(1, Math.round(ar.width * AURA_SCALE));
      aura.height = Math.max(1, Math.round(ar.height * AURA_SCALE));
      const tw = aura.width, th = aura.height * 2;
      auraTile = new OffscreenCanvas(tw, th);
      const tctx = auraTile.getContext("2d");
      if (tctx) {
        const a = (20 * Math.PI) / 180;
        const half = (Math.abs(tw * Math.sin(a)) + Math.abs(th * Math.cos(a))) / 2;
        const dx = Math.sin(a) * half, dy = -Math.cos(a) * half;
        const g = tctx.createLinearGradient(tw / 2 - dx, th / 2 - dy, tw / 2 + dx, th / 2 + dy);
        for (const [o, c] of AURA_STOPS) g.addColorStop(o, c);
        tctx.fillStyle = g;
        tctx.fillRect(0, 0, tw, th);
      }
    };

    const draw = () => {
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.clearRect(0, 0, w, h);
      ctx.strokeStyle = stroke;
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.ellipse(start.x, start.y, start.w, start.h, 0, 0, TAU);
      ctx.stroke();
      discs.forEach((d, i) => {
        if (i % 5) return;
        const inner = d.w < clip.w - 5;
        if (inner) { ctx.save(); ctx.clip(clipPath); }
        ctx.beginPath();
        ctx.ellipse(d.x, d.y, d.w, d.h, 0, 0, TAU);
        ctx.stroke();
        if (inner) ctx.restore();
      });
      ctx.save();
      ctx.clip(clipPath);
      for (const p of particles) {
        ctx.fillStyle = `rgba(${dot}, ${p.a * dotAlpha})`;
        ctx.fillRect(p.x, p.y, p.r, p.r);
      }
      ctx.restore();

      if (auraTile) {
        const th = auraTile.height;
        const off = ((now % AURA_PERIOD) / AURA_PERIOD) * th;
        actx.clearRect(0, 0, aura.width, aura.height);
        actx.drawImage(auraTile, 0, off - th);
        actx.drawImage(auraTile, 0, off);
      }
    };

    // Steps are per 60 Hz frame (as the reference), scaled to elapsed time. Drawn at ~30 fps
    // from a timer: the motion is slow, and a per-vsync rAF loop alone keeps the compositor busy.
    let raf = 0, timer = 0, last = 0;
    const frame = (t: number) => {
      timer = window.setTimeout(() => { raf = requestAnimationFrame(frame); }, 1000 / 30);
      const k = last ? Math.min((t - last) / (1000 / 60), 6) : 1;
      last = t;
      now = t;
      for (const d of discs) { d.p = (d.p + 0.001 * k) % 1; tween(d); }
      particles.forEach((p, i) => {
        p.y -= p.vy * k;
        if (p.y < 0) particles[i] = newParticle(false);
        else p.x = p.sx + p.dx * (1 - p.y / area.h);
      });
      draw();
    };
    const play = () => {
      cancelAnimationFrame(raf); clearTimeout(timer);
      last = 0;
      if (!still && !document.hidden) raf = requestAnimationFrame(frame);
    };

    setup();
    draw();
    play();
    const resize = new ResizeObserver(() => { setup(); draw(); });
    resize.observe(canvas);
    document.addEventListener("visibilitychange", play);
    return () => {
      cancelAnimationFrame(raf); clearTimeout(timer);
      resize.disconnect();
      document.removeEventListener("visibilitychange", play);
    };
  }, [calm, dark]);

  return (
    <div className={`loki-tunnel${calm ? " loki-tunnel-calm" : ""}`} aria-hidden="true">
      <canvas ref={linesRef} />
      <canvas ref={canvasRef} />
      <canvas ref={auraRef} className="loki-tunnel-aura" />
      <div className="loki-tunnel-scan" />
    </div>
  );
}
