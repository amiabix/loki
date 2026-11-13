"use client";

import { useEffect, useRef, useState } from "react";
import type { Group, Vector3 } from "three";
import { useIsDark } from "@/lib/theme";

type Ball = {
  group: Group;
  velocity: Vector3;
  previous: Vector3;
  radius: number;
  mass: number;
  phase: number;
};

type Pointer = { position: Vector3; active: boolean; down: boolean; speed: number };

function resolveCollision(a: Ball, b: Ball, normal: Vector3) {
  normal.subVectors(b.group.position, a.group.position);
  const distance = normal.length();
  const overlap = a.radius + b.radius - distance;
  if (overlap <= 0) return;
  if (distance > 0) normal.divideScalar(distance);
  else normal.set(1, 0, 0);

  const totalMass = a.mass + b.mass;
  a.group.position.addScaledVector(normal, -overlap * b.mass / totalMass);
  b.group.position.addScaledVector(normal, overlap * a.mass / totalMass);
  const closingSpeed = b.velocity.dot(normal) - a.velocity.dot(normal);
  if (closingSpeed >= 0) return;
  const impulse = -(1 + 0.02) * closingSpeed / (1 / a.mass + 1 / b.mass);
  a.velocity.addScaledVector(normal, -impulse / a.mass);
  b.velocity.addScaledVector(normal, impulse / b.mass);
}

// Velocities are in world units per 1/60 second; four substeps prevent fast overlaps.
function stepPhysics(balls: Ball[], bounds: Vector3, pointer: Pointer, time: number, scratch: Vector3) {
  const dt = 1 / 4;
  const damping = Math.pow(0.9, dt);
  const repelRadius = pointer.down ? 5.6 : 4.4;
  for (const ball of balls) ball.previous.copy(ball.group.position);

  for (let step = 0; step < 4; step++) {
    for (const ball of balls) {
      const { position } = ball.group;
      const { velocity, phase } = ball;
      velocity.x += (-position.x * 0.00012 + Math.sin(time * 0.7 + phase) * 0.0009) * dt;
      velocity.y += (-position.y * 0.00025 + Math.cos(time * 0.6 + phase) * 0.0012) * dt;
      velocity.z += (-position.z * 0.0001 + Math.sin(time * 0.5 + phase) * 0.0008) * dt;

      if (pointer.active) {
        scratch.subVectors(position, pointer.position);
        const distance = scratch.length();
        if (distance < repelRadius) {
          if (distance > 0) scratch.divideScalar(distance);
          else scratch.set(Math.cos(phase), Math.sin(phase), 0);
          const falloff = 1 - distance / repelRadius;
          const smooth = falloff * falloff * (3 - 2 * falloff);
          velocity.addScaledVector(scratch, 0.05 * smooth * (1 + pointer.speed) * (pointer.down ? 1.6 : 1) * dt);
        }
      }
      velocity.multiplyScalar(damping).clampLength(0, 0.18);
      position.addScaledVector(velocity, dt);
    }

    for (let i = 0; i < balls.length; i++) {
      for (let j = i + 1; j < balls.length; j++) resolveCollision(balls[i], balls[j], scratch);
    }
    for (const ball of balls) {
      for (const axis of ["x", "y", "z"] as const) {
        const limit = Math.max(0, bounds[axis] - ball.radius);
        const position = ball.group.position[axis];
        if (Math.abs(position) > limit) {
          ball.group.position[axis] = Math.sign(position) * limit;
          if (position * ball.velocity[axis] > 0) ball.velocity[axis] *= -0.3;
        }
      }
    }
  }

  for (const ball of balls) {
    scratch.subVectors(ball.group.position, ball.previous);
    const distance = scratch.length();
    scratch.set(-scratch.y, scratch.x, 0);
    if (scratch.lengthSq() > 0) ball.group.rotateOnWorldAxis(scratch.normalize(), distance / ball.radius);
  }
}

function FloatingOrbs() {
  return (
    <>
      <span className="orb-float" style={{ width: 190, height: 190, left: "7%", top: "16%" }} />
      <span className="orb-float" style={{ width: 104, height: 104, right: "11%", top: "22%" }} />
      <span className="orb-float" style={{ width: 150, height: 150, left: "18%", bottom: "12%", opacity: 0.6 }} />
      <span className="orb-float" style={{ width: 240, height: 240, right: "-5%", bottom: "6%", opacity: 0.55 }} />
    </>
  );
}

export function OrbScene({ calm = false }: { calm?: boolean }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [animate, setAnimate] = useState(false);
  const [ready, setReady] = useState(false);
  const dark = useIsDark();

  useEffect(() => {
    const motion = window.matchMedia("(prefers-reduced-motion: reduce)");
    const update = () => {
      setAnimate(!motion.matches);
      setReady(false);
    };
    update();
    motion.addEventListener("change", update);
    return () => motion.removeEventListener("change", update);
  }, []);

  useEffect(() => {
    const container = containerRef.current;
    const canvas = canvasRef.current;
    if (calm || !animate || !container || !canvas) return;
    setReady(false);
    let cancelled = false;
    let frame = 0;
    const disposers: (() => void)[] = [];
    const dispose = () => {
      cancelAnimationFrame(frame);
      for (const release of disposers.splice(0).reverse()) release();
    };

    async function start() {
      const [THREE, { RoomEnvironment }] = await Promise.all([
        import("three"),
        import("three/examples/jsm/environments/RoomEnvironment.js"),
      ]);
      if (cancelled || !canvas || !container) return;
      const context = canvas.getContext("webgl2", { antialias: true, alpha: true, powerPreference: "high-performance" });
      if (!context || context.isContextLost()) return;
      const renderer = new THREE.WebGLRenderer({ canvas, context, antialias: true, alpha: true, powerPreference: "high-performance" });
      disposers.push(() => renderer.dispose());
      renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
      renderer.setClearColor(0x000000, 0);
      renderer.toneMapping = THREE.ACESFilmicToneMapping;
      renderer.toneMappingExposure = dark ? 0.92 : 1.15;
      renderer.shadowMap.enabled = true;
      renderer.shadowMap.type = THREE.PCFSoftShadowMap;

      const scene = new THREE.Scene();
      const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 100);
      camera.position.set(0, 0, 11);
      camera.updateMatrixWorld();
      scene.add(dark
        ? new THREE.HemisphereLight(0x8aa0e0, 0x0a1026, 0.8)
        : new THREE.HemisphereLight(0xffffff, 0x2f69ff, 1.6));
      const key = new THREE.DirectionalLight(dark ? 0xdfe8ff : 0xffffff, dark ? 0.85 : 1.4);
      key.position.set(-6, 10, 8);
      key.castShadow = true;
      key.shadow.mapSize.set(2048, 2048);
      key.shadow.bias = -0.0003;
      disposers.push(() => key.shadow.dispose());
      const rim = new THREE.DirectionalLight(dark ? 0x6f8cff : 0xffffff, dark ? 0.9 : 1.25);
      rim.position.set(8, 7, -8);
      const front = new THREE.DirectionalLight(dark ? 0xaabbff : 0xffffff, dark ? 0.25 : 0.4);
      front.position.set(0, 0, 11);
      scene.add(key, rim, front);

      // White studio reflections give the glass shape without obscuring the CSS backdrop.
      const room = new RoomEnvironment(renderer);
      const pmrem = new THREE.PMREMGenerator(renderer);
      try {
        const environment = pmrem.fromScene(room, 0.04);
        scene.environment = environment.texture;
        disposers.push(() => environment.dispose());
      } finally {
        room.dispose();
        pmrem.dispose();
      }

      const bounds = new THREE.Vector3(1, 1, 2.4);
      const resize = () => {
        const { width, height } = container.getBoundingClientRect();
        if (!width || !height) return;
        camera.aspect = width / height;
        camera.updateProjectionMatrix();
        renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
        renderer.setSize(width, height, false);
        bounds.y = Math.tan(THREE.MathUtils.degToRad(camera.fov / 2)) * camera.position.z;
        bounds.x = bounds.y * camera.aspect;
        const shadowExtent = Math.max(bounds.x, bounds.y) + bounds.z;
        Object.assign(key.shadow.camera, { left: -shadowExtent, right: shadowExtent, top: shadowExtent, bottom: -shadowExtent });
        key.shadow.camera.updateProjectionMatrix();
      };
      resize();
      const observer = new ResizeObserver(resize);
      observer.observe(container);
      disposers.push(() => observer.disconnect());

      const geometry = new THREE.SphereGeometry(1, 48, 48);
      disposers.push(() => geometry.dispose());
      const palette = dark ? [0x3a4680, 0x2b3a7a, 0x2f69ff, 0x101c52] : [0xecefff, 0xa8c1ff, 0x2f69ff, 0x0a33bf];
      const envMapIntensity = dark ? 0.4 : 1;
      const materials = palette.map(color => new THREE.MeshPhysicalMaterial({
        color, roughness: 0.44, metalness: 0, clearcoat: 0.24, emissive: color,
        emissiveIntensity: dark ? 0.05 : 0.08, envMapIntensity,
      }));
      const glass = new THREE.MeshPhysicalMaterial({
        color: dark ? 0x2b48a8 : 0x4d80ff, roughness: 0.08, metalness: 0, clearcoat: 1, clearcoatRoughness: 0.03,
        transmission: 0.95, ior: 1.485, thickness: 2.2, transparent: true, envMapIntensity,
      });
      disposers.push(() => { for (const material of [...materials, glass]) material.dispose(); });
      const balls: Ball[] = [];
      const count = window.innerWidth < 768 ? 38 : 70;
      for (let i = 0; i < count; i++) {
        const size = i / count;
        const radius = size < 0.3 ? 0.27 + Math.random() * 0.12 : size < 0.8 ? 0.42 + Math.random() * 0.18 : 0.66 + Math.random() * 0.21;
        const isGlass = i % 9 < 2;
        const mesh = new THREE.Mesh(geometry, isGlass ? glass : materials[i % materials.length]);
        mesh.scale.setScalar(radius);
        mesh.castShadow = !isGlass;
        mesh.receiveShadow = !isGlass;
        const group = new THREE.Group();
        group.add(mesh);
        // Try several positions so the first frame does not start with a pile of overlaps.
        for (let attempt = 0; attempt < 40; attempt++) {
          group.position.set(
            (Math.random() * 2 - 1) * Math.max(0, bounds.x - radius),
            (Math.random() * 2 - 1) * Math.max(0, bounds.y - radius),
            (Math.random() * 2 - 1) * (bounds.z - radius),
          );
          if (balls.every(ball => ball.group.position.distanceTo(group.position) > ball.radius + radius)) break;
        }
        scene.add(group);
        balls.push({ group, radius, mass: radius ** 3, velocity: new THREE.Vector3(), previous: group.position.clone(), phase: Math.random() * Math.PI * 2 });
      }

      const pointer: Pointer = { position: new THREE.Vector3(), active: false, down: false, speed: 0 };
      const ray = new THREE.Vector3();
      const previousPointer = new THREE.Vector3();
      let lastPointerTime = 0;
      const move = (event: PointerEvent) => {
        const rect = container.getBoundingClientRect();
        if (!rect.width || !rect.height) return;
        previousPointer.copy(pointer.position);
        ray.set((event.clientX - rect.left) / rect.width * 2 - 1, 1 - (event.clientY - rect.top) / rect.height * 2, 0.5);
        ray.unproject(camera).sub(camera.position).normalize();
        pointer.position.copy(camera.position).addScaledVector(ray, -camera.position.z / ray.z);
        pointer.speed = pointer.active ? Math.min(2, pointer.position.distanceTo(previousPointer) * 125 / Math.max(8, event.timeStamp - lastPointerTime)) : 0;
        pointer.active = true;
        lastPointerTime = event.timeStamp;
      };
      const down = (event: PointerEvent) => { move(event); pointer.down = true; };
      const up = (event: PointerEvent) => { pointer.down = false; if (event.pointerType !== "mouse") pointer.active = false; };
      const clearPointer = () => { pointer.active = false; pointer.down = false; pointer.speed = 0; };
      const leave = (event: PointerEvent) => { if (!event.relatedTarget) clearPointer(); };
      window.addEventListener("pointermove", move, { passive: true });
      window.addEventListener("pointerdown", down, { passive: true });
      window.addEventListener("pointerup", up, { passive: true });
      window.addEventListener("pointercancel", clearPointer, { passive: true });
      window.addEventListener("pointerout", leave, { passive: true });
      window.addEventListener("blur", clearPointer);
      disposers.push(() => {
        window.removeEventListener("pointermove", move);
        window.removeEventListener("pointerdown", down);
        window.removeEventListener("pointerup", up);
        window.removeEventListener("pointercancel", clearPointer);
        window.removeEventListener("pointerout", leave);
        window.removeEventListener("blur", clearPointer);
      });

      const scratch = new THREE.Vector3();
      let lastTime = 0;
      let accumulator = 0;
      let time = 0;
      let contextLost = false;
      const tick = (now: number) => {
        if (cancelled || document.hidden || contextLost) return;
        accumulator += lastTime ? Math.min((now - lastTime) / 1000, 0.05) : 0;
        lastTime = now;
        while (accumulator >= 1 / 60) {
          time += 1 / 60;
          stepPhysics(balls, bounds, pointer, time, scratch);
          pointer.speed *= 0.92;
          accumulator -= 1 / 60;
        }
        renderer.render(scene, camera);
        frame = requestAnimationFrame(tick);
      };
      const visibility = () => {
        cancelAnimationFrame(frame);
        lastTime = 0;
        accumulator = 0;
        clearPointer();
        if (!document.hidden && !contextLost) frame = requestAnimationFrame(tick);
      };
      const lost = () => {
        contextLost = true;
        cancelAnimationFrame(frame);
        setReady(false);
      };
      document.addEventListener("visibilitychange", visibility);
      canvas.addEventListener("webglcontextlost", lost);
      disposers.push(() => {
        document.removeEventListener("visibilitychange", visibility);
        canvas.removeEventListener("webglcontextlost", lost);
      });
      if (!document.hidden) {
        renderer.render(scene, camera);
        frame = requestAnimationFrame(tick);
      }
      setReady(true);
    }

    void start().catch(() => {
      dispose();
      if (!cancelled) setReady(false);
    });
    return () => { cancelled = true; dispose(); };
  }, [animate, calm, dark]);

  return (
    <div ref={containerRef} className={`orb-field ${calm ? "orb-field-calm" : ""}`} aria-hidden="true" style={{ position: "fixed", inset: 0, zIndex: -5, pointerEvents: "none" }}>
      {(calm || !animate || !ready) && <FloatingOrbs />}
      {!calm && <canvas ref={canvasRef} className="absolute inset-0 h-full w-full" style={{
        opacity: animate && ready ? (dark ? 0.8 : 0.92) : 0,
        maskImage: "radial-gradient(ellipse at 50% 45%, transparent 12%, rgba(0,0,0,0.18) 38%, #000 78%)",
      }} />}
    </div>
  );
}
