"use client";

import { useEffect, useState } from "react";

const KEY = "loki_theme";
type Theme = "light" | "dark";

function systemDark() {
  return typeof window !== "undefined" && window.matchMedia("(prefers-color-scheme: dark)").matches;
}
function stored(): Theme | null {
  try {
    const v = localStorage.getItem(KEY);
    return v === "light" || v === "dark" ? v : null;
  } catch {
    return null;
  }
}
function resolvedDark(): boolean {
  const s = stored();
  return s ? s === "dark" : systemDark();
}

export function toggleTheme() {
  const next: Theme = resolvedDark() ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  try {
    localStorage.setItem(KEY, next);
  } catch {}
  window.dispatchEvent(new Event("loki:theme"));
}

export function useIsDark(): boolean {
  const [dark, setDark] = useState(false); // SSR-safe; corrected on mount
  useEffect(() => {
    const update = () => setDark(resolvedDark());
    update();
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    mq.addEventListener("change", update);
    window.addEventListener("loki:theme", update);
    return () => {
      mq.removeEventListener("change", update);
      window.removeEventListener("loki:theme", update);
    };
  }, []);
  return dark;
}
