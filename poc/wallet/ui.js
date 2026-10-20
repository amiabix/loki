/* Loki wired UI — the redesign prototype's look over REAL member_app routes.
 *
 * Reuses design/tokens.css + design/app.css. Unlike proto.js (pure nav
 * toggles, no network) every screen here calls the same /api/* commands the
 * shipping app.js uses. The signer token lives in the URL hash, exactly as
 * app.js:2 reads it, so the server-printed link opens this UI too:
 *   http://127.0.0.1:<port>/ui#<token>
 */
"use strict";

const token = location.hash.slice(1);
const ZAT = 100000000n;

const screens = [
  ["connect", "Connect"],
  ["vaults", "Vaults"],
  ["create", "Create vault"],
  ["setup", "Setup & backup"],
  ["overview", "Vault overview"],
  ["propose", "Propose payment"],
  ["approve", "Signer approval"],
  ["history", "History"],
];

let selectedVault = null;      // vault id the propose/approve screens act on
let reviewToken = null;        // WYSIWYS review_token for the approval screen
let reviewAttempt = null;
let setupViewVersion = 0;

async function api(path, body) {
  if (!token) throw new Error("Open the private local app link printed by the server (ends in /ui#…).");
  const response = await fetch(`/api/${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: {
      "X-Loki-Token": token,
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    cache: "no-store",
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "Request failed");
  return result;
}

const zecFromZat = (amount) => {
  const zat = BigInt(amount);
  return `${zat / ZAT}.${(zat % ZAT).toString().padStart(8, "0")}`;
};

function zatFromZec(text) {
  const value = String(text ?? "").trim();
  if (!/^[0-9]+(\.[0-9]{1,8})?$/.test(value)) throw new Error("Enter ZEC — digits, at most 8 decimals.");
  const [whole, fraction = ""] = value.split(".");
  const zat = BigInt(whole) * ZAT + BigInt((fraction + "00000000").slice(0, 8));
  if (zat <= 0n) throw new Error("Enter an amount greater than zero.");
  return zat.toString();
}

function $(id) { return document.getElementById(id); }

function flash(el, text, kind = "info") {
  if (!el) return;
  el.textContent = text;
  el.className = "callout callout-" + kind;
  el.classList.remove("hidden");
}

function clearSetupInputs() {
  $("setup-words").textContent = "";
  for (const id of ["setup-fingerprint", "setup-verify-words", "setup-final-create-words", "setup-final-words", "setup-final-card"]) {
    $(id).value = "";
  }
}

function show(id) {
  setupViewVersion++;
  if (id !== "setup") clearSetupInputs();
  document.querySelectorAll("[data-screen]").forEach((s) => {
    s.classList.toggle("hidden", s.dataset.screen !== id);
  });
  document.querySelectorAll(".nav button").forEach((b) => {
    b.setAttribute("aria-current", String(b.dataset.go === id));
  });
  const hero = id === "approve";
  document.querySelector(".rail").classList.toggle("hidden", hero);
  document.querySelector(".topbar").classList.toggle("hidden", hero);
  if (location.hash.slice(1) !== token) { /* keep token in hash */ }
  window.scrollTo(0, 0);
  if (id === "vaults") loadVaults();
  if (id === "propose") loadVaultOptions();
  if (id === "setup") loadSetup();
  if (id === "overview") loadOverview();
  if (id === "history") loadHistory();
}

/* Fill a <select> with this signer's vaults; keeps selectedVault in sync. */
async function fillVaultSelect(sel, after) {
  const home = await api("status");
  const vaults = home.vaults || [];
  sel.replaceChildren();
  if (!vaults.length) { sel.appendChild(new Option("No vaults yet", "")); return []; }
  for (const v of vaults) sel.appendChild(new Option(v.name || v.vault, v.vault));
  if (selectedVault && vaults.some((v) => v.vault === selectedVault)) sel.value = selectedVault;
  else selectedVault = sel.value;
  sel.onchange = () => { setupViewVersion++; selectedVault = sel.value; if (after) after(); };
  return vaults;
}

function buildNav() {
  const nav = document.querySelector(".nav");
  screens.forEach(([id, label], i) => {
    const b = document.createElement("button");
    b.dataset.go = id;
    b.innerHTML = `<span class="idx">${String(i + 1).padStart(2, "0")}</span><span>${label}</span>`;
    b.addEventListener("click", () => show(id));
    nav.appendChild(b);
  });
}

/* ── 01 Connect: a real /api/status call proves the token works ─────────── */
async function connect() {
  const out = $("connect-out");
  try {
    const home = await api("status");
    flash(out, `Connected. Profile “${home.profile?.name || home.profile || "?"}” · network ${home.network}.`, "accent");
    setTimeout(() => show("vaults"), 500);
  } catch (error) {
    flash(out, error.message, "danger");
  }
}

/* ── 02 Vaults: real vault list for this signer ─────────────────────────── */
/* /api/status (home) returns membership fields: {vault, name, slot, threshold,
 * members}. Per-vault phase comes from /api/status?vault=<id>, exactly as the
 * shipping app resolves it when a vault is opened. */
function policyText(v, phase) {
  const bits = [];
  if (v.threshold && v.members) bits.push(`${v.threshold}-of-${v.members}`);
  if (v.members) bits.push(`${v.members} members`);
  if (phase) bits.push(phase.replaceAll("_", " "));
  return bits.join(" · ");
}

async function vaultPhase(id) {
  try { return (await api(`status?vault=${encodeURIComponent(id)}`)).phase; }
  catch { return "unavailable"; }
}

async function loadVaults() {
  const list = $("vault-list");
  list.textContent = "Loading…";
  try {
    const home = await api("status");
    const vaults = home.vaults || [];
    if (!vaults.length) { list.textContent = "No vaults yet. Create one to begin."; return; }
    list.replaceChildren();
    for (const v of vaults) {
      const phase = await vaultPhase(v.vault);
      const row = document.createElement("div");
      row.className = "vault-item";
      const ok = phase === "active";
      row.innerHTML =
        `<div class="vault-avatar">${(v.name || "V").slice(0, 2).toUpperCase()}</div>` +
        `<div class="meta"><div class="name"></div><p class="muted"></p></div>` +
        `<span class="pill ${ok ? "pill-ok" : "pill-warn"}"><span class="dot"></span> ${phase.replaceAll("_", " ")}</span>`;
      row.querySelector(".name").textContent = v.name || v.vault;
      row.querySelector(".muted").textContent = policyText(v, phase);
      row.addEventListener("click", () => { selectedVault = v.vault; show("propose"); });
      list.appendChild(row);
    }
  } catch (error) {
    list.textContent = error.message;
  }
}

/* ── 03 Create vault: general t-of-n via real /api/create ───────────────── */
function wireTofN() {
  const tSel = $("t-sel"), nSel = $("n-sel"), preview = $("ton-preview");
  for (const n of [3, 4]) nSel.appendChild(new Option(String(n), n, false, n === 3));
  const fillT = (n) => {
    const want = parseInt(tSel.value || "2", 10);
    tSel.innerHTML = "";
    for (const t of n === 3 ? [2] : [2, 3]) tSel.appendChild(new Option(String(t), t));
    tSel.value = String(n === 3 ? 2 : Math.min(want, 3));
  };
  const render = () => {
    const n = parseInt(nSel.value, 10), t = parseInt(tSel.value, 10);
    preview.innerHTML = `This vault needs <strong>${t} of ${n}</strong> members to approve any payment.`;
  };
  nSel.addEventListener("change", () => { fillT(parseInt(nSel.value, 10)); render(); });
  tSel.addEventListener("change", render);
  fillT(3); render();
}

async function createVault() {
  const out = $("create-out");
  const name = $("create-name").value.trim();
  const threshold = parseInt($("t-sel").value, 10);
  const members = parseInt($("n-sel").value, 10);
  try {
    const value = await api("create", { name, members, threshold });
    selectedVault = value.vault;
    flash(out, `Vault draft created (${threshold}-of-${members}). Invite the other ${members - 1} members from the shipping app.`, "accent");
    setTimeout(() => show("vaults"), 900);
  } catch (error) {
    flash(out, error.message, "danger");
  }
}

/* ── 04 Propose payment: real draft + publish ───────────────────────────── */
async function loadVaultOptions() {
  const sel = $("propose-vault");
  try {
    const home = await api("status");
    const active = [];
    for (const v of home.vaults || []) {
      if ((await vaultPhase(v.vault)) === "active") active.push(v);
    }
    sel.replaceChildren();
    if (!active.length) {
      sel.appendChild(new Option("No active vault — finish setup first", ""));
      selectedVault = null;
      return;
    }
    for (const v of active) sel.appendChild(new Option(`${v.name || v.vault} · ${policyText(v, "active")}`, v.vault));
    if (selectedVault && active.some((v) => v.vault === selectedVault)) sel.value = selectedVault;
    else selectedVault = sel.value;
  } catch (error) {
    flash($("propose-out"), error.message, "danger");
  }
}

async function proposePayment() {
  const out = $("propose-out");
  const vault = $("propose-vault").value || selectedVault;
  if (!vault) { flash(out, "No active vault to pay from.", "warn"); return; }
  selectedVault = vault;
  try {
    const amount_zat = zatFromZec($("propose-amount").value);
    const recipient = $("propose-recipient").value.trim();
    const memo = $("propose-memo").value;
    const draft = await api("payment-draft", { vault, recipient, amount_zat, memo });
    await api("payment-publish", { vault, attempt: draft.attempt });
    flash(out, `Proposal published. Payment ${draft.payment}, signers ${draft.signers.join(", ")}. Open the approval screen once the exact transaction is readable.`, "accent");
  } catch (error) {
    flash(out, error.message, "danger");
  }
}

/* ── 05 Signer approval (WYSIWYS): real review then approve ─────────────── */
async function loadApproval() {
  const out = $("approve-out");
  const body = $("approve-body");
  reviewToken = null; reviewAttempt = null;
  body.classList.add("hidden");
  out.classList.add("hidden");
  const vault = selectedVault;
  if (!vault) { flash(out, "Select a vault and propose a payment first.", "warn"); return; }
  try {
    const payments = await api(`payments?vault=${encodeURIComponent(vault)}`);
    const rows = payments.payments || [];
    const pending = rows.find((p) => ["commitments", "package"].includes(p.phase));
    if (!pending) { flash(out, "No payment is waiting for your approval on this vault.", "info"); return; }
    const review = await api("payment-review", { vault, attempt: pending.attempt });
    reviewToken = review.review_token;
    reviewAttempt = pending.attempt;
    $("sign-amount").textContent = zecFromZat(review.amount_zat);
    $("sign-to").textContent = review.recipient;
    $("sign-fee").textContent = `${zecFromZat(review.fee_zat)} ZEC`;
    $("sign-change").textContent = `${zecFromZat(review.change_zat)} ZEC → vault`;
    $("sign-memo").textContent = review.memo_utf8 || "(no memo)";
    $("sign-expiry").textContent = `height ${review.expiry_height}`;
    body.classList.remove("hidden");
  } catch (error) {
    flash(out, `Transaction not readable yet: ${error.message}`, "warn");
  }
}

async function approve() {
  const out = $("approve-out");
  if (!reviewToken) { flash(out, "Nothing reviewed to approve.", "warn"); return; }
  try {
    await api("payment-approve", { vault: selectedVault, attempt: reviewAttempt, review_token: reviewToken });
    flash(out, "Share released for this exact package.", "accent");
  } catch (error) {
    flash(out, error.message, "danger");
  }
}

function refuse() {
  flash($("approve-out"), "Refused. No share released. A refusal is your decision, not a veto on the group.", "danger");
  reviewToken = null;
}

/* ── 06 Setup & backup: real /api/status drives steps + confirmations ───── */
/* The ceremony phase vocabulary comes straight from member_app.status():
 * waiting_for_members → compare_roster → creating_keys → back_up/
 * waiting_for_backups → final_backup → active. Each later phase implies the
 * earlier steps are done, so one ordered list of phase sets maps cleanly. */
const SETUP_STEPS = [
  ["Members joined", ["compare_roster", "creating_keys", "back_up", "waiting_for_backups", "final_backup", "active"]],
  ["Roster verified", ["creating_keys", "back_up", "waiting_for_backups", "final_backup", "active"]],
  ["Creating keys (DKG)", ["back_up", "waiting_for_backups", "final_backup", "active"]],
  ["Back up & prove restore", ["active"]],
  ["Active · address revealed", []],
];

function renderSteps(phase) {
  const el = $("setup-steps");
  el.replaceChildren();
  SETUP_STEPS.forEach(([label, doneWhen], i) => {
    const active = phase === "creating_keys" && i === 2;
    const state = doneWhen.includes(phase) || (i === 4 && phase === "active") ? "done"
      : active ? "active" : "pending";
    const step = document.createElement("div");
    step.className = "step " + state;
    step.innerHTML = `<span class="marker">${state === "done" ? "✓" : i + 1}</span>` +
      `<div class="body"><h4></h4></div>`;
    step.querySelector("h4").textContent = label;
    el.appendChild(step);
  });
}

async function loadSetup() {
  if (!selectedVault) await fillVaultSelect($("setup-vault"), loadSetup).catch(() => {});
  else { const s = $("setup-vault"); if (s.value !== selectedVault) await fillVaultSelect(s, loadSetup).catch(() => {}); }
  const vault = selectedVault;
  clearSetupInputs();
  if (!vault) { $("setup-steps").textContent = "No vault to set up."; return; }
  try {
    const state = await api(`status?vault=${encodeURIComponent(vault)}`);
    if (vault !== selectedVault) return;
    renderSteps(state.phase);
    $("setup-final-section").classList.toggle("hidden", !["final_backup", "connecting_relays", "active"].includes(state.phase));
    $("setup-final-create-label").classList.toggle("hidden", !state.final_card_needs_words);
    $("setup-finalize").disabled = !!state.final_card_created;
    $("setup-download-final").disabled = !state.final_card_created;
    $("setup-verify-final").disabled = !state.final_card_created;
    const code = $("setup-code");
    code.replaceChildren();
    const fp = state.fingerprint || "";
    (fp ? fp.match(/.{1,4}/g) : ["—"]).forEach((chunk) => {
      const b = document.createElement("span"); b.className = "codeblock";
      b.textContent = chunk.toUpperCase(); code.appendChild(b);
    });
    const conf = $("setup-confirms");
    conf.replaceChildren();
    for (const c of state.confirmations || []) {
      const row = document.createElement("div");
      row.className = "kv-row";
      const ok = c.matches, pill = ok ? "pill-ok" : c.confirmed ? "pill-danger" : "pill-warn";
      const word = ok ? "matches" : c.confirmed ? "DIFFERS" : "waiting";
      row.innerHTML = `<span>Member ${c.slot}</span><span class="pill ${pill}"><span class="dot"></span> ${word}</span>`;
      conf.appendChild(row);
    }
    $("setup-agree").disabled = !fp;
  } catch (error) {
    $("setup-steps").textContent = error.message;
  }
}

async function setupAgree() {
  const out = $("setup-agree-out");
  try {
    const vault = selectedVault;
    const entered = $("setup-fingerprint").value.trim().toLowerCase();
    const state = await api(`status?vault=${encodeURIComponent(vault)}`);
    if (vault !== selectedVault) throw new Error("Vault changed. Compare its fingerprint before confirming.");
    if (!state.fingerprint) throw new Error("Wait for all members to publish their roster answer.");
    if (entered !== state.fingerprint) throw new Error("Type the full fingerprint after comparing it with every member outside this app.");
    await api("agree", { vault, fingerprint: entered });
    flash(out, "Roster confirmed. Key creation started — this screen resumes if the app restarts.", "accent");
    setTimeout(loadSetup, 800);
  } catch (error) { flash(out, error.message, "danger"); }
}

async function setupBackup() {
  const out = $("setup-backup-out");
  const vault = selectedVault, view = setupViewVersion;
  try {
    const result = await api("backup", { vault });
    if (vault !== selectedVault || view !== setupViewVersion) return;
    $("setup-words").textContent = result.words;
    flash(out, "Words revealed. Write them down, then prove restore to confirm your backup.", "info");
  } catch (error) { if (vault === selectedVault && view === setupViewVersion) flash(out, error.message, "danger"); }
}

async function setupVerify() {
  const out = $("setup-backup-out");
  const vault = selectedVault, view = setupViewVersion;
  try {
    await api("verify", { vault, words: $("setup-verify-words").value.trim() });
    if (vault !== selectedVault || view !== setupViewVersion) return;
    $("setup-words").textContent = "";
    $("setup-verify-words").value = "";
    await api("activate", { vault });
    if (vault !== selectedVault || view !== setupViewVersion) return;
    flash(out, "Restore proven. Backup confirmed; the vault activates when every member confirms.", "accent");
    setTimeout(loadSetup, 800);
  } catch (error) { if (vault === selectedVault && view === setupViewVersion) flash(out, error.message, "danger"); }
}

async function setupFinalize() {
  const out = $("setup-final-out");
  try {
    const vault = selectedVault;
    const words = $("setup-final-create-words").value.trim();
    if (!$("setup-final-create-label").classList.contains("hidden") && !words) {
      throw new Error("Enter your 24 words to create the final card.");
    }
    await api("finalize-backup", { vault, ...(words ? { words } : {}) });
    if (vault !== selectedVault) return;
    $("setup-final-create-words").value = "";
    $("setup-download-final").disabled = false;
    $("setup-verify-final").disabled = false;
    flash(out, "Final card created. Download it, then load that saved file to check it.", "accent");
  } catch (error) { flash(out, error.message, "danger"); }
}

async function setupDownloadFinal() {
  const out = $("setup-final-out");
  try {
    const vault = selectedVault;
    const result = await api(`final-card?vault=${encodeURIComponent(vault)}`);
    if (vault !== selectedVault) return;
    const bytes = Uint8Array.from(atob(result.card), c => c.charCodeAt(0));
    const url = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = "loki-vault.card";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) { flash(out, error.message, "danger"); }
}

async function setupVerifyFinal() {
  const out = $("setup-final-out");
  try {
    const vault = selectedVault;
    const words = $("setup-final-words").value.trim();
    const file = $("setup-final-card").files[0];
    if (!words || !file || !file.size || file.size > 64 * 1024) {
      throw new Error("Enter your 24 words and load the final card you saved.");
    }
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (vault !== selectedVault) throw new Error("Vault changed. Load the saved card for the selected vault.");
    let raw = "";
    for (const byte of bytes) raw += String.fromCharCode(byte);
    await api("verify-final-backup", { vault, words, card: btoa(raw) });
    $("setup-final-words").value = "";
    $("setup-final-card").value = "";
    flash(out, "Final recovery card checked. Ask every member to do the same before depositing.", "accent");
    await loadSetup();
  } catch (error) { flash(out, error.message, "danger"); }
}

/* ── 07 Vault overview: status + balance + address + roster + payments ──── */
async function loadOverview() {
  if (!selectedVault) await fillVaultSelect($("overview-vault"), loadOverview).catch(() => {});
  else { const s = $("overview-vault"); if (s.value !== selectedVault) await fillVaultSelect(s, loadOverview).catch(() => {}); }
  const vault = selectedVault;
  $("ov-addr-shown").classList.add("hidden");
  $("ov-reveal").classList.remove("hidden");
  if (!vault) { $("ov-name").textContent = "No vault"; return; }
  try {
    const state = await api(`status?vault=${encodeURIComponent(vault)}`);
    $("ov-name").textContent = state.name || vault;
    $("ov-policy").textContent = `${state.threshold}-of-${state.total_members} · phase ${state.phase.replaceAll("_", " ")}`;
    $("ov-members").textContent = state.total_members ?? "—";
    $("ov-threshold").textContent = `threshold ${state.threshold}`;
    const roster = $("ov-roster");
    roster.replaceChildren();
    const reports = Object.fromEntries((state.backups || []).map((r) => [r.slot, r.reported]));
    for (let slot = 1; slot <= (state.total_members || 0); slot++) {
      const row = document.createElement("div");
      row.className = "member";
      const you = slot === state.slot ? " · you" : "";
      const up = reports[slot];
      row.innerHTML = `<span class="dot-avatar">${slot}</span>` +
        `<div style="flex:1"><strong>slot ${slot}</strong> <span class="muted">${you}</span></div>` +
        `<span class="pill ${up ? "pill-ok" : "pill-warn"}"><span class="dot"></span> ${up ? "backed up" : "pending"}</span>`;
      roster.appendChild(row);
    }
    $("ov-addr-hidden").classList.toggle("hidden", state.phase === "active");
    $("ov-reveal").classList.toggle("hidden", state.phase !== "active");
    await loadOverviewPayments(vault);
    await loadBalance(vault, state);
  } catch (error) {
    $("ov-name").textContent = error.message;
  }
}

async function loadBalance(vault, state) {
  if (state.network === "testnet" && state.synced_balance) {
    const b = state.synced_balance;
    $("ov-height").textContent = `Balance · height ${b.height}`;
    $("ov-balance").textContent = `${zecFromZat(b.balance_zat)} TAZ`;
    $("ov-synced").textContent = b.scan_ready ? "scan at chain tip" : "scanning…";
    return;
  }
  if (state.phase !== "active") { $("ov-balance").textContent = "—"; return; }
  try {
    const b = await api("balance", { vault });
    $("ov-height").textContent = b.height != null ? `Balance · height ${b.height}` : "Balance";
    $("ov-balance").textContent = `${zecFromZat(b.balance_zat ?? b.balance ?? 0)} ZEC`;
    $("ov-synced").textContent = "from this device's scan";
  } catch (error) { $("ov-synced").textContent = error.message; }
}

async function loadOverviewPayments(vault) {
  const el = $("ov-payments");
  try {
    const data = await api(`payments?vault=${encodeURIComponent(vault)}`);
    const rows = data.payments || [];
    $("ov-pending").textContent = rows.filter((p) => !PAYMENT_DONE.includes(p.phase)).length;
    el.replaceChildren();
    if (!rows.length) { el.textContent = "No payments yet."; return; }
    for (const p of rows) el.appendChild(paymentRow(p));
  } catch (error) { el.textContent = error.message; $("ov-pending").textContent = "—"; }
}

/* ── 08 History: the same /api/payments feed, every payment and its status ─ */
const PAYMENT_DONE = ["confirmed"];
const PHASE_LABEL = {
  draft: ["Preparing", "pill-warn"], commitments: ["Preparing", "pill-warn"],
  package: ["Awaiting approvals", "pill-warn"], approved: ["Approved", "pill-warn"],
  approval_pending_delivery: ["Approved", "pill-warn"], queued_for_delivery: ["Approved", "pill-warn"],
  approval_interrupted: ["Approved", "pill-warn"], broadcast: ["Broadcast", "pill-warn"],
  confirmation_needs_recheck: ["Reorg — rechecking", "pill-danger"],
  confirmed: ["Confirmed", "pill-ok"], failed: ["Failed", "pill-danger"],
};

function paymentRow(p) {
  const [label, pill] = PHASE_LABEL[p.phase] || [p.phase.replaceAll("_", " "), "pill-warn"];
  const row = document.createElement("div");
  row.className = "kv-row";
  const signers = (p.signers || []).join(", ");
  row.innerHTML = `<span><span class="mono">${p.payment || p.attempt.slice(0, 8)}</span>` +
    ` <span class="muted">signers ${signers}</span></span>` +
    `<span class="pill ${pill}"><span class="dot"></span> ${label}` +
    `${p.txid ? ` · ${p.txid.slice(0, 10)}…` : ""}</span>`;
  return row;
}

async function loadHistory() {
  if (!selectedVault) await fillVaultSelect($("history-vault"), loadHistory).catch(() => {});
  else { const s = $("history-vault"); if (s.value !== selectedVault) await fillVaultSelect(s, loadHistory).catch(() => {}); }
  const vault = selectedVault, el = $("history-list");
  if (!vault) { el.textContent = "No vault selected."; return; }
  el.textContent = "Loading…";
  try {
    const data = await api(`payments?vault=${encodeURIComponent(vault)}`);
    const rows = data.payments || [];
    el.replaceChildren();
    if (!rows.length) { el.textContent = "No payments yet."; return; }
    for (const p of rows) el.appendChild(paymentRow(p));
  } catch (error) { flash($("history-out"), error.message, "danger"); el.textContent = ""; }
}

document.addEventListener("DOMContentLoaded", () => {
  buildNav();
  wireTofN();
  $("connect-go").addEventListener("click", connect);
  $("create-go").addEventListener("click", createVault);
  $("propose-go").addEventListener("click", proposePayment);
  $("approve-load").addEventListener("click", loadApproval);
  $("do-approve").addEventListener("click", approve);
  $("do-refuse").addEventListener("click", refuse);
  $("setup-agree").addEventListener("click", setupAgree);
  $("setup-backup").addEventListener("click", setupBackup);
  $("setup-verify").addEventListener("click", setupVerify);
  $("setup-finalize").addEventListener("click", setupFinalize);
  $("setup-download-final").addEventListener("click", setupDownloadFinal);
  $("setup-verify-final").addEventListener("click", setupVerifyFinal);
  $("ov-reveal").addEventListener("click", async () => {
    try {
      const r = await api("address", { vault: selectedVault });
      $("ov-addr").textContent = r.address || r;
      $("ov-addr-shown").classList.remove("hidden");
      $("ov-reveal").classList.add("hidden");
    } catch (error) { $("ov-addr-hidden").textContent = error.message; $("ov-addr-hidden").classList.remove("hidden"); }
  });
  document.body.addEventListener("click", (e) => {
    const go = e.target.closest("[data-go-screen]");
    if (go) { e.preventDefault(); show(go.dataset.goScreen); }
  });
  show("connect");
});
