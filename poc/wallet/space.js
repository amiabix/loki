'use strict';
/* A forward-flight starfield behind the app: stars stream outward from a
   vanishing point so the page feels like it is travelling into space. Pure
   canvas 2D, no dependency. The canvas is transparent, so the page background
   and theme show through; cards are opaque, so content stays readable.
   prefers-reduced-motion renders one still frame. */
(function () {
  const canvas = document.getElementById('space');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const reduce = matchMedia('(prefers-reduced-motion: reduce)');

  const COUNT = 520;      /* stars */
  const FOCAL = 300;      /* projection focal length */
  const MAXZ = 1100;      /* spawn depth */
  const SPEED = 2.4;      /* approach per frame */
  const TRAIL = 6;        /* streak length, in frames of travel */

  let w, h, cx, cy, dpr, stars, raf = 0;
  let targetX = 0, targetY = 0, panX = 0, panY = 0;

  /* stars take their colour from the live accent token, so they match either
     theme and re-tint when the theme changes */
  let rgb = [0, 224, 164];
  function readAccent() {
    const hex = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim();
    const m = /^#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex);
    if (m) rgb = [parseInt(m[1], 16), parseInt(m[2], 16), parseInt(m[3], 16)];
  }

  function resize() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    w = canvas.width = Math.floor(innerWidth * dpr);
    h = canvas.height = Math.floor(innerHeight * dpr);
    canvas.style.width = innerWidth + 'px';
    canvas.style.height = innerHeight + 'px';
    cx = w / 2;
    cy = h / 2;
  }

  function spawn(z) {
    return {x: (Math.random() - 0.5) * w * 1.6, y: (Math.random() - 0.5) * h * 1.6, z};
  }
  function build() {
    stars = [];
    for (let i = 0; i < COUNT; i++) stars.push(spawn(Math.random() * MAXZ));
  }

  function draw(moving) {
    ctx.clearRect(0, 0, w, h);
    panX += (targetX - panX) * 0.04;
    panY += (targetY - panY) * 0.04;
    const ox = cx + panX, oy = cy + panY;
    for (const s of stars) {
      if (moving) {
        s.z -= SPEED;
        if (s.z <= 1) { Object.assign(s, spawn(MAXZ)); continue; }
      }
      const k = FOCAL / s.z;
      const sx = ox + s.x * k, sy = oy + s.y * k;
      if (sx < -50 || sx > w + 50 || sy < -50 || sy > h + 50) {
        if (moving) { Object.assign(s, spawn(MAXZ)); }
        continue;
      }
      const depth = 1 - s.z / MAXZ;          /* 0 far … 1 near */
      const alpha = Math.min(0.9, 0.12 + depth * depth * 0.9);
      if (moving) {
        const k2 = FOCAL / (s.z + SPEED * TRAIL);
        ctx.strokeStyle = `rgba(${rgb[0]},${rgb[1]},${rgb[2]},${alpha})`;
        ctx.lineWidth = Math.max(1, depth * 2.4 * dpr);
        ctx.beginPath();
        ctx.moveTo(ox + s.x * k2, oy + s.y * k2);
        ctx.lineTo(sx, sy);
        ctx.stroke();
      } else {
        ctx.fillStyle = `rgba(${rgb[0]},${rgb[1]},${rgb[2]},${alpha * 0.8})`;
        const r = Math.max(1, depth * 1.8 * dpr);
        ctx.fillRect(sx - r / 2, sy - r / 2, r, r);
      }
    }
  }

  function loop() {
    draw(true);
    raf = requestAnimationFrame(loop);
  }
  function start() {
    cancelAnimationFrame(raf);
    raf = 0;
    if (reduce.matches) { draw(false); return; }
    loop();
  }

  addEventListener('resize', () => { resize(); build(); draw(!reduce.matches); });
  addEventListener('pointermove', (e) => {
    targetX = (e.clientX - innerWidth / 2) * -0.6 * (dpr || 1);
    targetY = (e.clientY - innerHeight / 2) * -0.6 * (dpr || 1);
  });
  /* save the battery when the tab is hidden */
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) { cancelAnimationFrame(raf); raf = 0; }
    else start();
  });
  reduce.addEventListener('change', start);
  /* re-tint when the theme toggle flips data-theme, or the OS scheme changes */
  new MutationObserver(readAccent).observe(document.documentElement, {attributes: true, attributeFilter: ['data-theme']});
  matchMedia('(prefers-color-scheme: light)').addEventListener('change', readAccent);

  readAccent();
  resize();
  build();
  start();
})();
