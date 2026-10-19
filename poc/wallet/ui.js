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
  ["propose", "Propose payment"],
  ["approve", "Signer approval"],
];

let selectedVault = null;      // vault id the propose/approve screens act on
let reviewToken = null;        // WYSIWYS review_token for the approval screen
let reviewAttempt = null;

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

function show(id) {
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
  const MIN = 2, MAX = 9;
  for (let v = MIN; v <= MAX; v++) nSel.appendChild(new Option(String(v), v, false, v === 3));
  const fillT = (n, keep) => {
    const want = keep != null ? keep : Math.min(parseInt(tSel.value || "2", 10), n);
    tSel.innerHTML = "";
    for (let v = MIN; v <= n; v++) tSel.appendChild(new Option(String(v), v));
    tSel.value = String(Math.min(Math.max(want, MIN), n));
  };
  const render = () => {
    const n = parseInt(nSel.value, 10), t = parseInt(tSel.value, 10);
    preview.innerHTML = `This vault needs <strong>${t} of ${n}</strong> members to approve any payment.`;
  };
  nSel.addEventListener("change", () => { fillT(parseInt(nSel.value, 10)); render(); });
  tSel.addEventListener("change", render);
  fillT(3, 2); render();
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

document.addEventListener("DOMContentLoaded", () => {
  buildNav();
  wireTofN();
  $("connect-go").addEventListener("click", connect);
  $("create-go").addEventListener("click", createVault);
  $("propose-go").addEventListener("click", proposePayment);
  $("approve-load").addEventListener("click", loadApproval);
  $("do-approve").addEventListener("click", approve);
  $("do-refuse").addEventListener("click", refuse);
  document.body.addEventListener("click", (e) => {
    const go = e.target.closest("[data-go-screen]");
    if (go) { e.preventDefault(); show(go.dataset.goScreen); }
  });
  show("connect");
});
