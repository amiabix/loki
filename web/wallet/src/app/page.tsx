"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import { BlackHoleBackground } from "@/components/BlackHoleBackground";
import { api } from "@/lib/api";
import { useCeremonyStatus, usePayments, useStatus } from "@/lib/hooks";
import type {
  CeremonyStatus,
  InviteSlot,
  Payment,
  PaymentReview,
  StatusResponse,
  VaultSummary,
} from "@/lib/types";

// ─── util ────────────────────────────────────────────────────────────────────

const zatToTaz = (zat: number | string) =>
  (Number(zat) / 1e8).toLocaleString(undefined, { maximumFractionDigits: 8 });

const short = (s: string, head = 8, tail = 6) =>
  s.length > head + tail + 1 ? `${s.slice(0, head)}…${s.slice(-tail)}` : s;

// ─── navigation state ────────────────────────────────────────────────────────

type View =
  | { id: "account" }
  | { id: "home" }
  | { id: "create-vault" }
  | { id: "join-vault" }
  | { id: "ceremony"; vault: string }
  | { id: "overview"; vault: VaultSummary }
  | { id: "send"; vault: VaultSummary }
  | { id: "review"; vault: VaultSummary; attempt: string }
  | { id: "history"; vault: VaultSummary };

// ─── root ─────────────────────────────────────────────────────────────────────

export default function App() {
  // The tester's capability slug comes from the URL fragment (never sent to the server except
  // as the X-Loki-Access header by api()). It fixes which single signer this browser controls.
  const [member] = useState(() =>
    typeof window === "undefined" ? "" : window.location.hash.replace(/^#/, "").trim(),
  );
  const [view, setView] = useState<View>({ id: "account" });
  const { data: status, error: statusError, refresh: refreshStatus } = useStatus(member);

  // When status resolves, redirect to the right view if we're on "account" gating.
  useEffect(() => {
    if (!status) return;
    if (status.phase === "home" && view.id === "account") {
      setView({ id: "home" });
    }
  }, [status, view.id]);

  if (!member) {
    return (
      <>
        <BlackHoleBackground />
        <div className="scrim pointer-events-none fixed inset-0 -z-[5]" />
        <main className="flex h-dvh w-screen items-center justify-center px-6">
          <p className="max-w-md text-center text-sm text-white/70">
            Open your personal access link to sign in to your Loki signer.
          </p>
        </main>
      </>
    );
  }

  const network = status?.network ?? "testnet";
  const profile = status?.profile;

  return (
    <>
      <BlackHoleBackground />
      <div className="scrim pointer-events-none fixed inset-0 -z-[5]" />

      {/* top bar */}
      <header className="fixed inset-x-0 top-0 z-30 flex items-center justify-between px-6 py-4">
        <button
          onClick={() => view.id !== "home" && view.id !== "account" && setView({ id: "home" })}
          className="text-sm font-semibold tracking-[0.3em] text-white/80 hover:text-white transition"
        >
          LOKI
        </button>
        <div className="flex items-center gap-3">
          <span className="rounded-full border border-amber/40 bg-amber/10 px-2.5 py-0.5 text-[11px] font-medium uppercase tracking-wider text-amber">
            {network} — not real funds
          </span>
        </div>
      </header>

      {/* main view */}
      <main className="flex h-dvh w-screen items-center justify-center px-6 pt-16">
        <Screen key={`${member}-${view.id}`}>
          <ViewRouter
            view={view}
            member={member}
            status={status}
            statusError={statusError}
            profile={profile}
            onNavigate={setView}
            onStatusRefresh={refreshStatus}
          />
        </Screen>
      </main>
    </>
  );
}

// ─── screen wrapper ───────────────────────────────────────────────────────────

function Screen({ children }: { children: React.ReactNode }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: "easeOut" }}
      className="w-full max-w-xl"
    >
      {children}
    </motion.div>
  );
}

// ─── view router ──────────────────────────────────────────────────────────────

function ViewRouter({
  view,
  member,
  status,
  statusError,
  profile,
  onNavigate,
  onStatusRefresh,
}: {
  view: View;
  member: string;
  status: StatusResponse | undefined;
  statusError: string | null;
  profile: { name: string; id: string } | undefined;
  onNavigate: (v: View) => void;
  onStatusRefresh: () => void;
}) {
  if (statusError && view.id === "account") {
    return (
      <div className="on-shader text-center">
        <h1 className="text-6xl font-semibold tracking-tight">Loki</h1>
        <p className="mt-6 text-sm text-amber">{statusError}</p>
        <p className="mt-2 text-xs text-muted">Backend starting… retrying automatically.</p>
      </div>
    );
  }

  switch (view.id) {
    case "account":
      return (
        <AccountGate
          status={status}
          member={member}
          onUnlocked={() => { onNavigate({ id: "home" }); onStatusRefresh(); }}
        />
      );
    case "home":
      return (
        <Home
          member={member}
          profile={profile}
          vaults={status?.vaults ?? []}
          onNavigate={onNavigate}
          onRefresh={onStatusRefresh}
        />
      );
    case "create-vault":
      return (
        <CreateVault
          member={member}
          onBack={() => onNavigate({ id: "home" })}
          onCreated={(vault) => onNavigate({ id: "ceremony", vault })}
        />
      );
    case "join-vault":
      return (
        <JoinVault
          member={member}
          onBack={() => onNavigate({ id: "home" })}
          onJoined={(vault) => onNavigate({ id: "ceremony", vault })}
        />
      );
    case "ceremony":
      return (
        <CeremonyView
          member={member}
          vault={view.vault}
          onDone={() => { onNavigate({ id: "home" }); onStatusRefresh(); }}
        />
      );
    case "overview":
      return (
        <VaultOverview
          member={member}
          vault={view.vault}
          onSend={() => onNavigate({ id: "send", vault: view.vault })}
          onHistory={() => onNavigate({ id: "history", vault: view.vault })}
          onBack={() => onNavigate({ id: "home" })}
        />
      );
    case "send":
      return (
        <Send
          member={member}
          vault={view.vault}
          onBack={() => onNavigate({ id: "overview", vault: view.vault })}
          onDraft={(attempt) => onNavigate({ id: "review", vault: view.vault, attempt })}
        />
      );
    case "review":
      return (
        <ReviewApprove
          member={member}
          vault={view.vault}
          attempt={view.attempt}
          onBack={() => onNavigate({ id: "history", vault: view.vault })}
        />
      );
    case "history":
      return (
        <History
          member={member}
          vault={view.vault}
          onReview={(attempt) => onNavigate({ id: "review", vault: view.vault, attempt })}
          onBack={() => onNavigate({ id: "overview", vault: view.vault })}
        />
      );
  }
}

// ─── shared primitives ────────────────────────────────────────────────────────

function Row({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-white/5 py-3 last:border-0">
      <span className="shrink-0 text-sm text-muted">{label}</span>
      <span className={`text-right text-sm ${mono ? "font-mono break-all" : ""}`}>{value}</span>
    </div>
  );
}

function Btn({
  children,
  onClick,
  disabled,
  variant = "mint",
  className = "",
}: {
  children: React.ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  variant?: "mint" | "amber" | "danger" | "ghost";
  className?: string;
}) {
  const base = "w-full rounded-full px-7 py-3 font-medium transition disabled:opacity-40";
  const styles: Record<string, string> = {
    mint: "bg-mint text-black hover:brightness-110",
    amber: "bg-amber/20 text-amber border border-amber/40 hover:bg-amber/30",
    danger: "bg-danger/20 text-danger border border-danger/40 hover:bg-danger/30",
    ghost: "border border-white/15 text-foreground hover:bg-white/10",
  };
  return (
    <button onClick={onClick} disabled={disabled} className={`${base} ${styles[variant]} ${className}`}>
      {children}
    </button>
  );
}

function GlassCard({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return <div className={`glass rounded-2xl p-6 ${className}`}>{children}</div>;
}

function BackLink({ onClick, label = "← Back" }: { onClick: () => void; label?: string }) {
  return (
    <button onClick={onClick} className="mb-4 text-sm text-muted hover:text-white transition">
      {label}
    </button>
  );
}

function ErrMsg({ msg }: { msg: string | null }) {
  if (!msg) return null;
  return <p className="mt-3 text-sm text-danger">{msg}</p>;
}

// ─── account gate ─────────────────────────────────────────────────────────────

function AccountGate({
  status,
  member,
  onUnlocked,
}: {
  status: StatusResponse | undefined;
  member: string;
  onUnlocked: () => void;
}) {
  if (!status) {
    return (
      <div className="on-shader text-center">
        <h1 className="text-6xl font-semibold tracking-tight">Loki</h1>
        <p className="mt-6 text-sm text-muted animate-pulse">Connecting…</p>
      </div>
    );
  }
  if (status.phase === "new_profile") return <CreateProfile member={member} onCreated={onUnlocked} />;
  if (status.phase === "locked") return <UnlockProfile member={member} onUnlocked={onUnlocked} />;
  // phase === "home" — already handled by useEffect redirect
  return null;
}

function CreateProfile({ member, onCreated }: { member: string; onCreated: () => void }) {
  const [name, setName] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const submit = async () => {
    setBusy(true); setErr(null);
    try {
      await api(member, "profile-create", { name, passphrase });
      onCreated();
    } catch (e) { setErr((e as Error).message); }
    finally { setBusy(false); }
  };

  return (
    <div className="on-shader text-center">
      <h1 className="text-6xl font-semibold tracking-tight">Loki</h1>
      <p className="mt-3 text-muted">Create your profile</p>
      <div className="mx-auto mt-8 max-w-sm space-y-3">
        <input
          autoFocus
          placeholder="Profile name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          className="glass w-full rounded-full px-6 py-3 text-center outline-none placeholder:text-muted focus:border-mint/50"
        />
        <input
          type="password"
          placeholder="Passphrase"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && name && passphrase && !busy && submit()}
          className="glass w-full rounded-full px-6 py-3 text-center outline-none placeholder:text-muted focus:border-mint/50"
        />
        <Btn onClick={submit} disabled={!name || !passphrase || busy}>
          {busy ? "Creating…" : "Create profile →"}
        </Btn>
        <ErrMsg msg={err} />
      </div>
    </div>
  );
}

function UnlockProfile({ member, onUnlocked }: { member: string; onUnlocked: () => void }) {
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const submit = async () => {
    setBusy(true); setErr(null);
    try {
      await api(member, "unlock", { passphrase });
      onUnlocked();
    } catch (e) { setErr((e as Error).message); }
    finally { setBusy(false); }
  };

  return (
    <div className="on-shader text-center">
      <h1 className="text-6xl font-semibold tracking-tight">Loki</h1>
      <p className="mt-3 text-muted">Unlock your wallet</p>
      <div className="mx-auto mt-8 max-w-sm space-y-3">
        <input
          type="password"
          autoFocus
          placeholder="Wallet passphrase"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && passphrase && !busy && submit()}
          className="glass w-full rounded-full px-6 py-3 text-center outline-none placeholder:text-muted focus:border-mint/50"
        />
        <Btn onClick={submit} disabled={!passphrase || busy}>
          {busy ? "Unlocking…" : "Unlock →"}
        </Btn>
        <ErrMsg msg={err} />
      </div>
    </div>
  );
}

// ─── home ─────────────────────────────────────────────────────────────────────

function Home({
  member,
  profile,
  vaults,
  onNavigate,
  onRefresh,
}: {
  member: string;
  profile: { name: string; id: string } | undefined;
  vaults: VaultSummary[];
  onNavigate: (v: View) => void;
  onRefresh: () => void;
}) {
  const [locking, setLocking] = useState(false);

  const lock = async () => {
    setLocking(true);
    try {
      await api(member, "lock", {});
      onNavigate({ id: "account" });
    } finally { setLocking(false); }
  };

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-semibold">{profile?.name ?? "Wallet"}</h2>
        </div>
        <button onClick={lock} disabled={locking} className="text-xs text-muted hover:text-danger transition">
          {locking ? "Locking…" : "Lock"}
        </button>
      </div>

      {vaults.length > 0 ? (
        <div className="space-y-2 mb-6">
          {vaults.map((v) => (
            <button
              key={v.vault}
              onClick={() => onNavigate({ id: "overview", vault: v })}
              className="glass w-full rounded-2xl p-4 text-left hover:border-mint/30 transition"
            >
              <div className="flex items-center justify-between">
                <span className="font-medium">{v.name}</span>
                <span className="text-xs text-muted">{v.threshold}/{v.members}</span>
              </div>
              <span className="font-mono text-xs text-muted">{short(v.vault)}</span>
            </button>
          ))}
        </div>
      ) : (
        <GlassCard className="mb-6 text-center text-muted text-sm py-10">
          No vaults yet. Create one or join with an invite code.
        </GlassCard>
      )}

      <div className="grid grid-cols-2 gap-3">
        <Btn variant="mint" onClick={() => onNavigate({ id: "create-vault" })}>
          Create vault
        </Btn>
        <Btn variant="ghost" onClick={() => onNavigate({ id: "join-vault" })}>
          Join vault
        </Btn>
      </div>
    </div>
  );
}

// ─── create vault ─────────────────────────────────────────────────────────────

function CreateVault({
  member,
  onBack,
  onCreated,
}: {
  member: string;
  onBack: () => void;
  onCreated: (vault: string) => void;
}) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const submit = async () => {
    setBusy(true); setErr(null);
    try {
      const res = await api<{ vault: string }>(member, "create", { name, members: 3 });
      onCreated(res.vault);
    } catch (e) { setErr((e as Error).message); }
    finally { setBusy(false); }
  };

  return (
    <div>
      <BackLink onClick={onBack} />
      <h2 className="mb-6 text-2xl font-semibold">Create vault</h2>
      <GlassCard>
        <p className="mb-4 text-sm text-muted">
          This starts a 3-member ceremony. Share the invite codes with the other members.
        </p>
        <input
          autoFocus
          placeholder="Vault name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && name && !busy && submit()}
          className="glass w-full rounded-full px-6 py-3 outline-none placeholder:text-muted"
        />
      </GlassCard>
      <div className="mt-4">
        <Btn onClick={submit} disabled={!name || busy}>
          {busy ? "Starting…" : "Start ceremony →"}
        </Btn>
      </div>
      <ErrMsg msg={err} />
    </div>
  );
}

// ─── join vault ───────────────────────────────────────────────────────────────

function JoinVault({
  member,
  onBack,
  onJoined,
}: {
  member: string;
  onBack: () => void;
  onJoined: (vault: string) => void;
}) {
  const [invite, setInvite] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const submit = async () => {
    setBusy(true); setErr(null);
    try {
      const res = await api<{ vault: string }>(member, "join", { invite });
      onJoined(res.vault);
    } catch (e) { setErr((e as Error).message); }
    finally { setBusy(false); }
  };

  return (
    <div>
      <BackLink onClick={onBack} />
      <h2 className="mb-6 text-2xl font-semibold">Join vault</h2>
      <GlassCard>
        <input
          autoFocus
          placeholder="Invite code"
          value={invite}
          onChange={(e) => setInvite(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && invite && !busy && submit()}
          className="glass w-full rounded-full px-6 py-3 outline-none placeholder:text-muted font-mono text-sm"
        />
      </GlassCard>
      <div className="mt-4">
        <Btn onClick={submit} disabled={!invite || busy}>
          {busy ? "Joining…" : "Join →"}
        </Btn>
      </div>
      <ErrMsg msg={err} />
    </div>
  );
}

// ─── ceremony ─────────────────────────────────────────────────────────────────

const CEREMONY_PHASES: CeremonyStatus["phase"][] = [
  "waiting_for_members",
  "compare_roster",
  "creating_keys",
  "back_up",
  "waiting_for_backups",
  "final_backup",
  "connecting_relays",
  "active",
];

const PHASE_LABEL: Record<CeremonyStatus["phase"], string> = {
  waiting_for_members: "Waiting for members",
  compare_roster: "Compare roster",
  creating_keys: "Creating keys",
  back_up: "Back up",
  waiting_for_backups: "Waiting for backups",
  final_backup: "Final backup",
  connecting_relays: "Connecting relays",
  active: "Active",
};

function CeremonyView({
  member,
  vault,
  onDone,
}: {
  member: string;
  vault: string;
  onDone: () => void;
}) {
  const { data: cs, error } = useCeremonyStatus(member, vault, true);

  if (error) {
    return (
      <div>
        <p className="text-sm text-amber">{error}</p>
        <p className="mt-1 text-xs text-muted">Backend starting… polling.</p>
      </div>
    );
  }

  if (!cs) {
    return <p className="text-sm text-muted animate-pulse">Loading ceremony…</p>;
  }

  if (cs.phase === "active") {
    return (
      <div className="text-center on-shader">
        <div className="text-5xl mb-4">✓</div>
        <h2 className="text-2xl font-semibold text-mint mb-2">Vault ready</h2>
        <p className="text-muted text-sm mb-8">The ceremony is complete and the vault is active.</p>
        <Btn onClick={onDone}>Go to vault →</Btn>
      </div>
    );
  }

  return (
    <div>
      <h2 className="mb-4 text-xl font-semibold">Ceremony</h2>
      <PhaseLadder current={cs.phase} />

      <div className="mt-6">
        {cs.phase === "waiting_for_members" && (
          <WaitingForMembers invites={cs.invites ?? []} />
        )}
        {cs.phase === "compare_roster" && (
          <CompareRoster
            member={member}
            vault={vault}
            fingerprint={cs.fingerprint}
            confirmations={cs.confirmations ?? []}
          />
        )}
        {(cs.phase === "creating_keys" || cs.phase === "waiting_for_backups" || cs.phase === "connecting_relays") && (
          <div className="text-sm text-muted text-center animate-pulse">
            {PHASE_LABEL[cs.phase]}… please wait.
          </div>
        )}
        {cs.phase === "back_up" && (
          <BackupPhase member={member} vault={vault} finalStep={false} />
        )}
        {cs.phase === "final_backup" && (
          <BackupPhase member={member} vault={vault} finalStep={true} />
        )}
      </div>
    </div>
  );
}

function PhaseLadder({ current }: { current: CeremonyStatus["phase"] }) {
  const currentIdx = CEREMONY_PHASES.indexOf(current);
  return (
    <div className="flex flex-wrap gap-1.5">
      {CEREMONY_PHASES.map((p, i) => (
        <span
          key={p}
          className={`rounded-full px-2.5 py-0.5 text-[11px] font-medium transition ${
            i < currentIdx
              ? "bg-mint/15 text-mint"
              : i === currentIdx
              ? "bg-mint text-black"
              : "border border-white/10 text-muted"
          }`}
        >
          {PHASE_LABEL[p]}
        </span>
      ))}
    </div>
  );
}

function WaitingForMembers({ invites }: { invites: InviteSlot[] }) {
  const [copied, setCopied] = useState<number | null>(null);
  const copy = async (slot: number, code: string) => {
    await navigator.clipboard.writeText(code);
    setCopied(slot);
    setTimeout(() => setCopied(null), 1500);
  };
  return (
    <div className="space-y-3">
      <p className="text-sm text-muted mb-4">Share each invite code with the corresponding member.</p>
      {invites.map((inv) => (
        <div key={inv.slot} className="glass rounded-xl p-3 flex items-center justify-between gap-3">
          <div className="min-w-0">
            <p className="text-xs text-muted mb-1">Slot {inv.slot + 1}</p>
            <p className="font-mono text-xs break-all">{inv.code}</p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {inv.joined && <span className="text-mint text-xs">✓ joined</span>}
            <button
              onClick={() => copy(inv.slot, inv.code)}
              className="rounded-full border border-white/15 px-3 py-1 text-xs hover:bg-white/10 transition"
            >
              {copied === inv.slot ? "✓" : "Copy"}
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}

function CompareRoster({
  member,
  vault,
  fingerprint,
  confirmations,
}: {
  member: string;
  vault: string;
  fingerprint: string | undefined;
  confirmations: { slot: number; confirmed: boolean; matches: boolean }[];
}) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const agree = async () => {
    setBusy(true); setErr(null);
    try {
      await api(member, "agree", { vault, fingerprint });
    } catch (e) { setErr((e as Error).message); }
    finally { setBusy(false); }
  };

  const mySlot = confirmations.find((c) => !c.confirmed);
  const alreadyConfirmed = confirmations.every((c) => c.confirmed);

  return (
    <div>
      <p className="text-sm text-muted mb-4">
        Every member must verify this fingerprint matches on all devices before confirming.
      </p>
      {fingerprint && (
        <GlassCard className="mb-4 text-center">
          <p className="text-xs text-muted mb-2 uppercase tracking-wider">Roster fingerprint</p>
          <p className="font-mono text-lg break-all text-amber">{fingerprint}</p>
        </GlassCard>
      )}
      <div className="space-y-1 mb-4">
        {confirmations.map((c) => (
          <div key={c.slot} className="flex justify-between text-sm">
            <span className="text-muted">Slot {c.slot + 1}</span>
            <span className={c.confirmed ? (c.matches ? "text-mint" : "text-danger") : "text-muted"}>
              {c.confirmed ? (c.matches ? "✓ matches" : "✗ mismatch") : "pending"}
            </span>
          </div>
        ))}
      </div>
      {!alreadyConfirmed && mySlot !== undefined && (
        <Btn variant="amber" onClick={agree} disabled={busy}>
          {busy ? "Confirming…" : "Confirm roster"}
        </Btn>
      )}
      {alreadyConfirmed && (
        <p className="text-sm text-mint text-center">All members confirmed — advancing…</p>
      )}
      <ErrMsg msg={err} />
    </div>
  );
}

function BackupPhase({
  member,
  vault,
  finalStep,
}: {
  member: string;
  vault: string;
  finalStep: boolean;
}) {
  const [words, setWords] = useState<string[] | null>(null);
  const [entry, setEntry] = useState("");
  const [card, setCard] = useState<string | null>(null);
  const [cardEntry, setCardEntry] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const fetchWords = async () => {
    setBusy(true); setErr(null);
    try {
      const res = await api<{ words: string[] }>(member, "backup", { vault });
      setWords(res.words);
    } catch (e) { setErr((e as Error).message); }
    finally { setBusy(false); }
  };

  const fetchFinalCard = async () => {
    setBusy(true); setErr(null);
    try {
      const res = await api<{ card: string }>(member, `final-card?vault=${encodeURIComponent(vault)}`);
      setCard(res.card);
    } catch (e) { setErr((e as Error).message); }
    finally { setBusy(false); }
  };

  const verifyWords = async () => {
    setBusy(true); setErr(null);
    try {
      const enteredWords = entry.trim().split(/\s+/);
      if (finalStep) {
        await api(member, "verify-final-backup", { vault, words: enteredWords, card: cardEntry.trim() });
      } else {
        await api(member, "verify", { vault, words: enteredWords });
        // then finalize-backup
        await api(member, "finalize-backup", { vault, words: enteredWords });
      }
      setDone(true);
    } catch (e) { setErr((e as Error).message); }
    finally { setBusy(false); }
  };

  if (done) {
    return <p className="text-sm text-mint text-center">Backup complete — waiting for others…</p>;
  }

  if (!words) {
    return (
      <div className="text-center">
        <p className="text-sm text-muted mb-4">
          {finalStep ? "Final backup verification required." : "Write down your 24-word recovery phrase. Never share it."}
        </p>
        <Btn variant="amber" onClick={finalStep ? fetchFinalCard : fetchWords} disabled={busy}>
          {busy ? "Loading…" : finalStep ? "Show final backup" : "Show recovery phrase"}
        </Btn>
      </div>
    );
  }

  return (
    <div>
      <p className="text-xs text-amber uppercase tracking-wider mb-3">
        {finalStep ? "Final backup words" : "Recovery phrase — write these down"}
      </p>
      <GlassCard className="mb-4">
        <div className="grid grid-cols-3 gap-2">
          {words.map((w, i) => (
            <div key={i} className="flex gap-1.5 items-baseline">
              <span className="text-[10px] text-muted w-5 text-right">{i + 1}.</span>
              <span className="font-mono text-sm">{w}</span>
            </div>
          ))}
        </div>
      </GlassCard>

      {finalStep && card && (
        <div className="mb-3">
          <p className="text-xs text-muted mb-1">Recovery card code</p>
          <GlassCard>
            <p className="font-mono text-sm break-all text-amber">{card}</p>
          </GlassCard>
          <input
            placeholder="Re-enter card code"
            value={cardEntry}
            onChange={(e) => setCardEntry(e.target.value)}
            className="glass mt-2 w-full rounded-full px-6 py-3 font-mono text-sm outline-none placeholder:text-muted"
          />
        </div>
      )}

      <p className="text-xs text-muted mb-2">Re-enter all 24 words to confirm</p>
      <textarea
        rows={3}
        placeholder="word1 word2 word3 …"
        value={entry}
        onChange={(e) => setEntry(e.target.value)}
        className="glass w-full rounded-2xl px-4 py-3 font-mono text-sm outline-none placeholder:text-muted resize-none mb-3"
      />
      <Btn
        variant="amber"
        onClick={verifyWords}
        disabled={busy || !entry.trim() || (finalStep && !cardEntry.trim())}
      >
        {busy ? "Verifying…" : "Verify & continue"}
      </Btn>
      <ErrMsg msg={err} />
    </div>
  );
}

// ─── vault overview ───────────────────────────────────────────────────────────

function VaultOverview({
  member,
  vault,
  onSend,
  onHistory,
  onBack,
}: {
  member: string;
  vault: VaultSummary;
  onSend: () => void;
  onHistory: () => void;
  onBack: () => void;
}) {
  const [address, setAddress] = useState<string | null>(null);
  const [balance, setBalance] = useState<{ balance_zat: number } | null>(null);
  const [copied, setCopied] = useState(false);
  const [loadErr, setLoadErr] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    // Load independently: a hosted vault's balance can be unavailable (needs a scan /
    // roster the signer can't open), but the address must still render.
    api<{ address: string }>(member, "address", { vault: vault.vault })
      .then((r) => active && setAddress(r.address))
      .catch((e) => active && setLoadErr((e as Error).message));
    api<{ balance_zat: number }>(member, "balance", { vault: vault.vault })
      .then((r) => active && setBalance(r))
      .catch(() => {});
    return () => {
      active = false;
    };
  }, [member, vault.vault]);

  const copy = async () => {
    if (!address) return;
    await navigator.clipboard.writeText(address);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div>
      <BackLink onClick={onBack} />
      <div className="mb-1 flex items-center justify-between">
        <h2 className="text-2xl font-semibold">{vault.name}</h2>
        <span className="text-xs text-muted">{vault.threshold}/{vault.members}</span>
      </div>
      <div className="mb-6 font-mono text-4xl font-semibold">
        {balance ? zatToTaz(balance.balance_zat) : "—"}
        <span className="ml-2 text-xl text-muted">TAZ</span>
      </div>

      {loadErr && <p className="mb-3 text-sm text-amber">{loadErr}</p>}

      <GlassCard className="mb-4">
        <Row label="Policy" value={`${vault.threshold} of ${vault.members}`} />
        <Row label="Vault ID" value={short(vault.vault)} mono />
        {address && (
          <Row
            label="Address"
            value={
              <span className="font-mono text-xs break-all">{short(address, 16, 10)}</span>
            }
          />
        )}
      </GlassCard>

      {address && (
        <button
          onClick={copy}
          className="mb-3 w-full rounded-full border border-white/15 py-2 text-sm hover:bg-white/10 transition"
        >
          {copied ? "✓ Address copied" : "Copy receive address"}
        </button>
      )}

      <div className="grid grid-cols-2 gap-3">
        <Btn variant="mint" onClick={onSend}>Send</Btn>
        <Btn variant="ghost" onClick={onHistory}>History</Btn>
      </div>
    </div>
  );
}

// ─── send ─────────────────────────────────────────────────────────────────────

function Send({
  member,
  vault,
  onBack,
  onDraft,
}: {
  member: string;
  vault: VaultSummary;
  onBack: () => void;
  onDraft: (attempt: string) => void;
}) {
  const [recipient, setRecipient] = useState("");
  const [amountTaz, setAmountTaz] = useState("");
  const [memo, setMemo] = useState("");
  const [draft, setDraft] = useState<{ attempt: string; fee_zat: string; change_zat: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const prepareDraft = async () => {
    setBusy(true); setErr(null);
    try {
      const amount_zat = String(Math.round(parseFloat(amountTaz) * 1e8));
      const res = await api<{ attempt: string; fee_zat: string; change_zat: string }>(
        member, "payment-draft", { vault: vault.vault, recipient, amount_zat, memo }
      );
      setDraft(res);
    } catch (e) { setErr((e as Error).message); }
    finally { setBusy(false); }
  };

  const publish = async () => {
    if (!draft) return;
    setBusy(true); setErr(null);
    try {
      await api(member, "payment-publish", { vault: vault.vault, attempt: draft.attempt });
      onDraft(draft.attempt);
    } catch (e) { setErr((e as Error).message); }
    finally { setBusy(false); }
  };

  return (
    <div>
      <BackLink onClick={onBack} />
      <h2 className="mb-6 text-2xl font-semibold">Send from {vault.name}</h2>
      <GlassCard className="mb-4 space-y-3">
        <input
          placeholder="Recipient address"
          value={recipient}
          onChange={(e) => setRecipient(e.target.value)}
          className="glass w-full rounded-full px-5 py-2.5 font-mono text-sm outline-none placeholder:text-muted"
        />
        <input
          placeholder="Amount (TAZ)"
          type="number"
          step="0.00000001"
          min="0"
          value={amountTaz}
          onChange={(e) => setAmountTaz(e.target.value)}
          className="glass w-full rounded-full px-5 py-2.5 text-sm outline-none placeholder:text-muted"
        />
        <input
          placeholder="Memo (optional)"
          value={memo}
          onChange={(e) => setMemo(e.target.value)}
          className="glass w-full rounded-full px-5 py-2.5 text-sm outline-none placeholder:text-muted"
        />
      </GlassCard>

      {draft && (
        <GlassCard className="mb-4">
          <p className="text-xs text-muted mb-3 uppercase tracking-wider">Transaction summary</p>
          <Row label="Attempt" value={short(draft.attempt, 10, 6)} mono />
          <Row label="Fee" value={`${zatToTaz(draft.fee_zat)} TAZ`} />
          <Row label="Change" value={`${zatToTaz(draft.change_zat)} TAZ`} />
        </GlassCard>
      )}

      {!draft ? (
        <Btn onClick={prepareDraft} disabled={!recipient || !amountTaz || busy}>
          {busy ? "Preparing…" : "Prepare →"}
        </Btn>
      ) : (
        <Btn variant="amber" onClick={publish} disabled={busy}>
          {busy ? "Publishing…" : "Publish payment"}
        </Btn>
      )}
      <ErrMsg msg={err} />
    </div>
  );
}

// ─── review / approve ─────────────────────────────────────────────────────────

function ReviewApprove({
  member,
  vault,
  attempt,
  onBack,
}: {
  member: string;
  vault: VaultSummary;
  attempt: string;
  onBack: () => void;
}) {
  const [review, setReview] = useState<PaymentReview | null>(null);
  const [approved, setApproved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const fetchReview = useCallback(async () => {
    try {
      const r = await api<PaymentReview>(member, "payment-review", { vault: vault.vault, attempt });
      setReview(r);
    } catch {
      // not ready yet — poll
    }
  }, [member, vault.vault, attempt]);

  useEffect(() => {
    if (approved) return;
    fetchReview();
    const tick = () => {
      fetchReview().finally(() => {
        timerRef.current = setTimeout(tick, 1500);
      });
    };
    timerRef.current = setTimeout(tick, 1500);
    return () => { if (timerRef.current) clearTimeout(timerRef.current); };
  }, [approved, fetchReview]);

  const approve = async () => {
    if (!review) return;
    setBusy(true); setErr(null);
    try {
      await api(member, "payment-approve", { vault: vault.vault, attempt, review_token: review.review_token });
      setApproved(true);
    } catch (e) { setErr((e as Error).message); }
    finally { setBusy(false); }
  };

  if (approved) {
    return (
      <div className="text-center on-shader">
        <div className="text-5xl mb-4">✓</div>
        <p className="text-mint font-semibold mb-2">Approved</p>
        <p className="text-sm text-muted mb-8">Switch members and approve with the others, then send from History.</p>
        <Btn variant="ghost" onClick={onBack}>Back to history</Btn>
      </div>
    );
  }

  if (!review) {
    return (
      <div>
        <BackLink onClick={onBack} />
        <p className="text-sm text-muted animate-pulse">Loading payment review…</p>
      </div>
    );
  }

  return (
    <div>
      <BackLink onClick={onBack} />
      <h2 className="mb-2 text-2xl font-semibold">Review payment</h2>
      <p className="text-xs text-amber mb-4 uppercase tracking-wider">Sign this payment</p>
      <GlassCard className="mb-4">
        <Row label="To" value={<span className="font-mono text-xs break-all">{review.recipient}</span>} />
        <Row label="Amount" value={`${zatToTaz(review.amount_zat)} TAZ`} />
        <Row label="Fee" value={`${zatToTaz(review.fee_zat)} TAZ`} />
        {review.memo && <Row label="Memo" value={review.memo} />}
      </GlassCard>
      <Btn variant="amber" onClick={approve} disabled={busy}>
        {busy ? "Approving…" : "Approve payment"}
      </Btn>
      <ErrMsg msg={err} />
    </div>
  );
}

// ─── history ──────────────────────────────────────────────────────────────────

const PHASE_PILL: Record<string, string> = {
  preparing: "border border-white/15 text-muted",
  approved: "bg-amber/15 text-amber",
  broadcast: "bg-mint/15 text-mint",
  confirmed: "bg-mint text-black",
};

function History({
  member,
  vault,
  onReview,
  onBack,
}: {
  member: string;
  vault: VaultSummary;
  onReview: (attempt: string) => void;
  onBack: () => void;
}) {
  const { data, error } = usePayments(member, vault.vault, true);
  const [finishing, setFinishing] = useState<string | null>(null);
  const [verifying, setVerifying] = useState<string | null>(null);
  const [txids, setTxids] = useState<Record<string, string>>({});
  const [verified, setVerified] = useState<Record<string, boolean>>({});
  const [err, setErr] = useState<string | null>(null);

  const finish = async (attempt: string) => {
    setFinishing(attempt); setErr(null);
    try {
      const res = await api<{ phase: string; txid: string }>(member, "payment-finish", { vault: vault.vault, attempt });
      setTxids((p) => ({ ...p, [attempt]: res.txid }));
      // start polling verify
      setVerifying(attempt);
    } catch (e) { setErr((e as Error).message); }
    finally { setFinishing(null); }
  };

  useEffect(() => {
    if (!verifying) return;
    const attempt = verifying;
    const txid = txids[attempt];
    if (!txid) return;
    const tick = async () => {
      try {
        const res = await api<{ phase: string }>(member, "payment-verify", { vault: vault.vault, attempt, txid });
        if (res.phase === "confirmed") {
          setVerified((p) => ({ ...p, [attempt]: true }));
          setVerifying(null);
          return;
        }
      } catch {}
      setTimeout(tick, 1500);
    };
    setTimeout(tick, 1500);
  }, [verifying, txids, member, vault.vault]);

  const payments = data?.payments ?? [];

  return (
    <div>
      <BackLink onClick={onBack} />
      <h2 className="mb-4 text-2xl font-semibold">History</h2>

      {error && <p className="mb-3 text-sm text-amber">{error}</p>}

      {payments.length === 0 ? (
        <GlassCard className="text-center text-sm text-muted py-10">No payments yet.</GlassCard>
      ) : (
        <div className="space-y-3">
          {payments.map((p) => (
            <GlassCard key={p.attempt}>
              <div className="flex items-start justify-between gap-3 mb-2">
                <div className="min-w-0">
                  <p className="font-mono text-xs text-muted break-all">{short(p.recipient, 14, 8)}</p>
                  <p className="font-mono text-sm mt-0.5">{zatToTaz(p.amount_zat)} TAZ</p>
                </div>
                <span className={`rounded-full px-2.5 py-0.5 text-[11px] font-medium shrink-0 ${PHASE_PILL[p.phase] ?? "border border-white/15 text-muted"}`}>
                  {verified[p.attempt] ? "confirmed" : p.phase}
                </span>
              </div>
              <div className="flex gap-2 mt-3">
                <button
                  onClick={() => onReview(p.attempt)}
                  className="flex-1 rounded-full border border-white/15 py-1.5 text-xs hover:bg-white/10 transition"
                >
                  Review / approve
                </button>
                {p.ready_to_send && !txids[p.attempt] && (
                  <button
                    onClick={() => finish(p.attempt)}
                    disabled={finishing === p.attempt}
                    className="flex-1 rounded-full bg-mint/20 border border-mint/40 text-mint py-1.5 text-xs hover:bg-mint/30 transition disabled:opacity-40"
                  >
                    {finishing === p.attempt ? "Sending…" : "Send →"}
                  </button>
                )}
                {txids[p.attempt] && (
                  <span className="flex-1 text-center text-xs text-mint py-1.5">
                    {verified[p.attempt] ? "✓ Confirmed" : `txid: ${short(txids[p.attempt], 8, 6)}`}
                  </span>
                )}
              </div>
            </GlassCard>
          ))}
        </div>
      )}
      <ErrMsg msg={err} />
    </div>
  );
}
