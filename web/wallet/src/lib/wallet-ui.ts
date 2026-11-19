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
  if (phase === "replaced") return "Replaced · will never be sent";
  if (phase === "broadcast") return "Awaiting confirmation";
  if (phase === "expired") return "Expired";
  if (phase === "failed") return "Failed · not sent";
  if (phase === "discarding") return "Releasing reserved input";
  if (phase === "cancelled") return "Cancelled";
  if (sending) return "Sending";
  if (ready) return "Ready to send";
  const labels: Record<string, string> = {
    draft: "Draft", preparing: "Preparing payment", signing: "Collecting approvals",
    approved: "Approved · awaiting the signed transaction", not_selected: "Other members are signing",
    ready: "Signed · building the transaction", signed: "Signed · not sent yet",
  };
  return labels[phase] ?? "Status unavailable";
}

// A short, human-comparable rendering of the roster fingerprint, so members can read it aloud on a
// call or eyeball it on another phone instead of trusting a coordinator-shown hex string. Pure and
// deterministic; the fingerprint itself is untouched. Every byte folds into every slot (XOR), so a
// swapped roster cannot collide by matching a shared prefix.
const VERIFY_WORDS = [
  "anchor", "apple", "arrow", "bacon", "badge", "beach", "bird", "blade",
  "bloom", "bolt", "brick", "cabin", "cable", "camel", "candle", "cargo",
  "cedar", "cliff", "cloud", "clover", "coral", "crane", "crown", "daisy",
  "delta", "dragon", "eagle", "ember", "falcon", "fern", "flame", "forest",
  "frost", "garden", "ginger", "globe", "grape", "harbor", "hawk", "honey",
  "island", "jaguar", "jungle", "kettle", "lagoon", "lantern", "lemon", "lotus",
  "maple", "marble", "meadow", "meteor", "mint", "moon", "nebula", "ocean",
  "olive", "orbit", "otter", "panda", "parrot", "pearl", "pepper", "planet",
  "pond", "prism", "quartz", "quill", "rabbit", "raven", "reef", "river",
  "rocket", "ruby", "saddle", "sage", "salmon", "shadow", "shark", "shell",
  "silver", "sloth", "spark", "sphinx", "spruce", "star", "storm", "summit",
  "swan", "tiger", "timber", "topaz", "torch", "trail", "tulip", "turtle",
  "velvet", "violet", "walnut", "whale", "willow", "wolf", "zebra", "zephyr",
];
const VERIFY_EMOJI = ["🦊", "🐻", "🦉", "🐢", "🐙", "🦋", "🌵", "🍀", "🔥", "❄️", "🌙", "⚡", "🌊", "🍎", "🚀", "💎"];

export function verifyPhrase(fingerprint: string | undefined): { words: string[]; emoji: string[] } | null {
  const hex = fingerprint?.trim().toLowerCase();
  if (!hex || hex.length % 2 !== 0 || !/^[0-9a-f]+$/.test(hex)) return null;
  const bytes = Uint8Array.from(hex.match(/../g)!, (b) => parseInt(b, 16));
  const fold = (slots: number) => {
    const acc = new Uint8Array(slots);
    bytes.forEach((b, i) => { acc[i % slots] ^= b; });
    return acc;
  };
  return {
    words: Array.from(fold(5), (b) => VERIFY_WORDS[b % VERIFY_WORDS.length]),
    emoji: Array.from(fold(4), (b) => VERIFY_EMOJI[b % VERIFY_EMOJI.length]),
  };
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

/** Whole seconds before a pairing link lapses, rounded up; 0 once expired. The coordinator
 *  keeps a reservation while `expires > now`, so the link is gone at `now === expires`. */
export function pairingSecondsLeft(expires: number, now: number): number {
  return expires > now ? Math.ceil((expires - now) / 1000) : 0;
}

/** What a native member reads when LokiSigner recorded no agreement to a roster. `answered` is
 *  false when the request lost its connection before LokiSigner replied. The member's own error
 *  prefixes come from `agree` in poc/src/host/ceremony.rs. */
export function nativeRosterRefusal(message: string, answered: boolean): string {
  if (!answered) return "This page lost its connection to LokiSigner. If its dialog is still open, answer it there; this page moves on once you choose Codes match.";
  if (message.startsWith("roster codes differ")) return "You chose Codes differ in LokiSigner, so it will not agree to this vault. Tell the creator and the other members: someone may have been swapped in. If you chose it by mistake, quit and reopen LokiSigner, pair this tab again, and compare once more.";
  if (message.startsWith("roster code not confirmed")) return "LokiSigner's dialog closed or timed out before you answered, so nothing was recorded. Choose Compare in LokiSigner again when every member is ready to compare.";
  if (message.startsWith("LokiSigner is already asking")) return "LokiSigner is already showing a roster code. Answer that dialog first.";
  if (message.startsWith("the vault setup changed while LokiSigner was asking")) return "The vault's members changed while LokiSigner was asking, so nothing was recorded. Choose Compare in LokiSigner again to see the new code, and compare it with every member again.";
  if (message === "roster code mismatch" || message === "roster fingerprint mismatch") return "The vault's members changed since this page loaded. Choose Compare in LokiSigner again to see the current code.";
  return `LokiSigner recorded no agreement: ${message}`;
}
