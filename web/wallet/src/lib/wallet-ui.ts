/** Invite metadata is a preview only; the existing join endpoint validates the invite. */
export function invitePreview(code: string): { vault: string; name: string; members: number; threshold: number; slot: number } | null {
  try {
    const raw = atob(code.replace(/-/g, "+").replace(/_/g, "/"));
    const value = JSON.parse(new TextDecoder().decode(Uint8Array.from(raw, (c) => c.charCodeAt(0))));
    if (typeof value.name !== "string" || !value.name.trim() || value.name.length > 80
      || typeof value.vault !== "string" || !/^[a-f0-9]{64}$/i.test(value.vault)
      || !Number.isInteger(value.members) || value.members < 2 || value.members > 16
      || !Number.isInteger(value.threshold) || value.threshold < 2 || value.threshold > value.members
      || !Number.isInteger(value.slot) || value.slot < 2 || value.slot > value.members) return null;
    return value;
  } catch { return null; }
}

export function paymentLabel(phase: string, ready: boolean, sending: boolean): string {
  if (phase === "confirmed") return "Confirmed";
  if (phase === "broadcast") return "Awaiting confirmation";
  if (phase === "expired") return "Expired";
  if (sending) return "Sending";
  if (ready) return "Ready to send";
  const labels: Record<string, string> = {
    draft: "Draft", preparing: "Preparing payment", signing: "Collecting approvals",
    approved: "Approved · awaiting proposer", not_selected: "Other members are signing",
  };
  return labels[phase] ?? "Status unavailable";
}

// shortcut: status omits the viewer's slot; retain successful joins until the API exposes it.
export function rememberVaultSlot(profile: string | undefined, vault: string, slot: number) {
  if (!profile) return;
  try { localStorage.setItem(`loki_slot:${profile}:${vault}`, String(slot)); } catch {}
}

export function rememberedVaultSlot(profile: string | undefined, vault: string): number | null {
  if (!profile) return null;
  try {
    const slot = Number(localStorage.getItem(`loki_slot:${profile}:${vault}`));
    return Number.isInteger(slot) && slot >= 1 && slot <= 16 ? slot : null;
  } catch { return null; }
}
