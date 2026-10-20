"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./api";
import type { CeremonyStatus, Payment, StatusResponse } from "./types";

/** Poll every 1.5s while `active` is true. Returns latest value + manual refresh. */
function usePoll<T>(
  fetcher: () => Promise<T>,
  active: boolean,
  initial?: T,
): { data: T | undefined; error: string | null; refresh: () => void } {
  const [data, setData] = useState<T | undefined>(initial);
  const [error, setError] = useState<string | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  const run = useCallback(async () => {
    try {
      const d = await fetcherRef.current();
      setData(d);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }, []);

  useEffect(() => {
    if (!active) return;
    let cancelled = false;
    run();
    const tick = () => {
      run().finally(() => {
        if (!cancelled) timerRef.current = setTimeout(tick, 1500);
      });
    };
    timerRef.current = setTimeout(tick, 1500);
    return () => {
      cancelled = true;
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [active, run]);

  return { data, error, refresh: run };
}

export function useStatus(member: string) {
  return usePoll<StatusResponse>(
    () => api<StatusResponse>(member, "status"),
    true,
  );
}

export function useCeremonyStatus(member: string, vault: string, active: boolean) {
  return usePoll<CeremonyStatus>(
    () => api<CeremonyStatus>(member, `status?vault=${encodeURIComponent(vault)}`),
    active,
  );
}

export function usePayments(member: string, vault: string, active: boolean) {
  return usePoll<{ payments: Payment[] }>(
    () => api<{ payments: Payment[] }>(member, `payments?vault=${encodeURIComponent(vault)}`),
    active,
  );
}
