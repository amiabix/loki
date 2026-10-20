"use client";

import { useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import { BlackHoleBackground } from "@/components/BlackHoleBackground";

/** Where `loki_serve` is listening. Everything below is real data from that wallet. */
const API = process.env.NEXT_PUBLIC_LOKI_API ?? "http://localhost:8099";

type Vault = {
  vault: string;
  network: string;
  threshold: number;
  members: number;
  policy: string;
  address: string;
  balance_zat: number;
  max_spendable_zat: number | null;
  height: number;
  chain_tip: number;
  synced: boolean;
};

const zatToZec = (zat: number) => (zat / 1e8).toLocaleString(undefined, { maximumFractionDigits: 8 });
const short = (s: string, head = 12, tail = 8) =>
  s.length > head + tail + 1 ? `${s.slice(0, head)}…${s.slice(-tail)}` : s;

export default function Home() {
  const rail = useRef<HTMLDivElement>(null);
  const [active, setActive] = useState(0);
  const [vault, setVault] = useState<Vault | null>(null);

  const screens = vault ? ["connect", "overview", "receive"] : ["connect"];

  // Vertical wheel / trackpad drives the horizontal rail (left -> right).
  useEffect(() => {
    const el = rail.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      if (Math.abs(e.deltaY) > Math.abs(e.deltaX)) {
        el.scrollLeft += e.deltaY;
        e.preventDefault();
      }
    };
    const onScroll = () => setActive(Math.round(el.scrollLeft / el.clientWidth));
    el.addEventListener("wheel", onWheel, { passive: false });
    el.addEventListener("scroll", onScroll, { passive: true });
    return () => {
      el.removeEventListener("wheel", onWheel);
      el.removeEventListener("scroll", onScroll);
    };
  }, []);

  const goTo = (i: number) =>
    rail.current?.scrollTo({ left: i * rail.current.clientWidth, behavior: "smooth" });

  return (
    <>
      <BlackHoleBackground />
      <div className="scrim pointer-events-none fixed inset-0 -z-[5]" />

      <div className="pointer-events-none fixed left-8 top-7 z-20 text-sm font-semibold tracking-[0.3em] text-white/80">
        LOKI
      </div>

      {vault && (
        <div className="fixed left-1/2 top-6 z-20 -translate-x-1/2">
          <span className="rounded-full border border-amber/40 bg-amber/10 px-3 py-1 text-[11px] font-medium uppercase tracking-wider text-amber">
            ● {vault.network} — not real funds
          </span>
        </div>
      )}

      <main
        ref={rail}
        className="no-scrollbar flex h-dvh w-screen snap-x snap-mandatory overflow-x-auto overflow-y-hidden"
      >
        <Screen>
          <Connect vault={vault} onUnlock={(v) => { setVault(v); goTo(1); }} />
        </Screen>
        {vault && (
          <>
            <Screen>
              <Overview vault={vault} onRefresh={setVault} />
            </Screen>
            <Screen>
              <Receive vault={vault} />
            </Screen>
          </>
        )}
      </main>

      {vault && (
        <div className="fixed bottom-7 left-1/2 z-20 flex -translate-x-1/2 gap-2.5">
          {screens.map((id, i) => (
            <button
              key={id}
              onClick={() => goTo(i)}
              aria-label={id}
              className={`h-2 rounded-full transition-all ${
                i === active ? "w-7 bg-mint" : "w-2 bg-white/25 hover:bg-white/50"
              }`}
            />
          ))}
        </div>
      )}
    </>
  );
}

function Screen({ children }: { children: React.ReactNode }) {
  return (
    <section className="relative flex h-dvh w-screen flex-none snap-start items-center justify-center px-6 md:px-16">
      <motion.div
        initial={{ opacity: 0, y: 24 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ amount: 0.4 }}
        transition={{ duration: 0.5, ease: "easeOut" }}
        className="w-full max-w-xl"
      >
        {children}
      </motion.div>
    </section>
  );
}

/* ---------- screens ---------- */

function Connect({ vault, onUnlock }: { vault: Vault | null; onUnlock: (v: Vault) => void }) {
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const unlock = async () => {
    setBusy(true);
    setError(null);
    try {
      const res = await fetch(`${API}/api/unlock`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ passphrase }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? `unlock failed (${res.status})`);
      setPassphrase("");
      onUnlock(data as Vault);
    } catch (e) {
      setError(
        e instanceof TypeError
          ? `Can't reach the signer at ${API}. Is loki_serve running?`
          : (e as Error).message,
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="on-shader text-center">
      <h1 className="text-6xl font-semibold tracking-tight md:text-8xl">Loki</h1>
      <p className="mx-auto mt-5 max-w-md text-balance text-lg text-white/85">
        A shielded Zcash multisig. Your key is born on your device and never
        leaves it — you approve every payment here.
      </p>

      {vault ? (
        <p className="mt-10 text-mint">✓ Unlocked — scroll right ↠</p>
      ) : (
        <div className="mx-auto mt-10 max-w-sm">
          <input
            type="password"
            autoFocus
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && passphrase && !busy && unlock()}
            placeholder="Wallet passphrase"
            className="glass w-full rounded-full px-6 py-3 text-center text-foreground outline-none placeholder:text-muted focus:border-mint/50"
          />
          <button
            onClick={unlock}
            disabled={!passphrase || busy}
            className="mt-4 w-full rounded-full bg-mint px-7 py-3 font-medium text-black transition hover:brightness-110 disabled:opacity-40"
          >
            {busy ? "Unlocking & scanning…" : "Unlock your vault →"}
          </button>
          {error && <p className="mt-4 text-sm text-danger">{error}</p>}
        </div>
      )}
    </div>
  );
}

function Overview({ vault, onRefresh }: { vault: Vault; onRefresh: (v: Vault) => void }) {
  const [syncing, setSyncing] = useState(false);
  const unit = "TAZ";

  const resync = async () => {
    setSyncing(true);
    try {
      const res = await fetch(`${API}/api/sync`, { method: "POST" });
      if (res.ok) onRefresh((await res.json()) as Vault);
    } finally {
      setSyncing(false);
    }
  };

  return (
    <div>
      <h2 className="mb-1 text-sm uppercase tracking-wider text-muted">
        Vault {short(vault.vault, 8, 6)} · {vault.policy}
      </h2>
      <div className="mb-6 font-mono text-5xl font-semibold">
        {zatToZec(vault.balance_zat)} <span className="text-2xl text-muted">{unit}</span>
      </div>
      <div className="glass rounded-2xl p-6">
        <Row label="Policy" value={`${vault.policy} · ${vault.members} members`} />
        <Row
          label="Spendable"
          value={vault.max_spendable_zat == null ? "—" : `${zatToZec(vault.max_spendable_zat)} ${unit}`}
          mono
        />
        <Row label="Network" value={vault.network} />
        <Row
          label="Synced"
          value={
            vault.synced
              ? `height ${vault.height.toLocaleString()} ✓`
              : `height ${vault.height.toLocaleString()} / tip ${vault.chain_tip.toLocaleString()}`
          }
        />
      </div>
      <button
        onClick={resync}
        disabled={syncing}
        className="mt-6 w-full rounded-full border border-white/15 py-3 font-medium transition hover:bg-white/10 disabled:opacity-40"
      >
        {syncing ? "Scanning…" : "Sync to tip"}
      </button>
    </div>
  );
}

function Receive({ vault }: { vault: Vault }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    await navigator.clipboard.writeText(vault.address);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <div className="text-center">
      <h2 className="mb-2 text-2xl font-semibold">Receive</h2>
      <p className="mb-6 text-sm text-muted">
        Your vault&apos;s shielded unified address — anyone can pay it.
      </p>
      <div className="glass rounded-2xl p-6">
        <div className="break-all font-mono text-sm leading-relaxed text-foreground">
          {vault.address}
        </div>
      </div>
      <button
        onClick={copy}
        className="mt-6 rounded-full bg-mint px-7 py-3 font-medium text-black transition hover:brightness-110"
      >
        {copied ? "Copied ✓" : "Copy address"}
      </button>
    </div>
  );
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between border-b border-white/5 py-3 last:border-0">
      <span className="text-sm text-muted">{label}</span>
      <span className={mono ? "font-mono text-sm" : "text-sm"}>{value}</span>
    </div>
  );
}
