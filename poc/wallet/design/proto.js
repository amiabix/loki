/* Loki redesign prototype — nav + state toggles only. No crypto, no network. */
"use strict";

const screens = [
  ["connect",  "Connect signer"],
  ["vaults",   "Vaults"],
  ["create",   "Create vault"],
  ["join",     "Join vault"],
  ["setup",    "Setup & backup"],
  ["overview", "Vault overview"],
  ["propose",  "Propose payment"],
  ["approve",  "Signer approval"],
  ["send",     "Send & confirm"],
  ["recover",  "Recover / leave"],
];

function show(id) {
  document.querySelectorAll("[data-screen]").forEach((s) => {
    s.classList.toggle("hidden", s.dataset.screen !== id);
  });
  document.querySelectorAll(".nav button").forEach((b) => {
    b.setAttribute("aria-current", String(b.dataset.go === id));
  });
  // the signer-approval hero takes over the whole frame
  const hero = id === "approve";
  document.querySelector(".rail").classList.toggle("hidden", hero);
  document.querySelector(".topbar").classList.toggle("hidden", hero);
  document.getElementById("app").style.gridTemplateColumns = hero ? "1fr" : "";
  if (location.hash !== "#" + id) history.replaceState(null, "", "#" + id);
  window.scrollTo(0, 0);
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

function theme(mode) {
  const root = document.documentElement;
  if (mode === "system" || mode == null) {
    root.removeAttribute("data-theme");
    try { localStorage.removeItem("loki-theme"); } catch (e) {}
  } else {
    root.setAttribute("data-theme", mode);
    try { localStorage.setItem("loki-theme", mode); } catch (e) {}
  }
  const cur = root.getAttribute("data-theme") || "system";
  document.querySelectorAll(".seg [data-theme-btn]").forEach((b) => {
    b.setAttribute("aria-pressed", String(b.dataset.themeBtn === cur));
  });
}

/* General t-of-n picker: live preview + one invite row per non-creator slot. */
function wireTofN() {
  const tSel = document.getElementById("t-sel");
  const nSel = document.getElementById("n-sel");
  const preview = document.getElementById("ton-preview");
  const invites = document.getElementById("invite-list");
  if (!tSel || !nSel || !preview || !invites) return;

  const MIN = 2, MAX = 9;
  const codes = ["bd71…9f02", "4a0c…7731", "e22d…1c48", "90fa…55ab", "1c7e…a3d5",
                 "77b0…e14f", "3ad9…0c82", "c5f1…6b90"];

  for (let v = MIN; v <= MAX; v++) {
    nSel.appendChild(new Option(String(v), v, false, v === 5));
  }

  function fillT(n, keep) {
    const want = keep != null ? keep : Math.min(parseInt(tSel.value || "3", 10), n);
    tSel.innerHTML = "";
    for (let v = MIN; v <= n; v++) tSel.appendChild(new Option(String(v), v));
    tSel.value = String(Math.min(Math.max(want, MIN), n));
  }

  function render() {
    const n = parseInt(nSel.value, 10);
    const t = parseInt(tSel.value, 10);
    preview.innerHTML =
      `This vault needs <strong>${t} of ${n}</strong> members to approve any payment. ` +
      `Any ${t} eligible members can complete a proposal.`;
    invites.innerHTML =
      `<div class="row-between card" style="background:var(--surface-2);padding:var(--sp-3)">` +
      `<span class="mono">You · slot 1</span><span class="pill pill-ok"><span class="dot"></span> You</span></div>`;
    for (let slot = 2; slot <= n; slot++) {
      invites.insertAdjacentHTML("beforeend",
        `<div class="row-between card" style="background:var(--surface-2);padding:var(--sp-3)">` +
        `<span class="mono">loki/invite · ${codes[slot - 2]}</span>` +
        `<button class="btn btn-quiet" data-copy="loki/invite:${codes[slot - 2]}">Copy</button></div>`);
    }
  }

  nSel.addEventListener("change", () => { fillT(parseInt(nSel.value, 10)); render(); });
  tSel.addEventListener("change", render);
  fillT(5, 3);
  render();
}

/* tiny demo interactions, each guarded so a missing element is a no-op */
function wireDemos() {
  // DKG progress simulation on the setup screen
  const bar = document.getElementById("dkg-bar");
  const run = document.getElementById("dkg-run");
  if (run && bar) {
    run.addEventListener("click", () => {
      let p = parseInt(bar.dataset.p || "40", 10);
      const tick = () => {
        p = Math.min(100, p + 15);
        bar.style.width = p + "%";
        bar.dataset.p = p;
        const label = document.getElementById("dkg-label");
        if (label) label.textContent = p < 100 ? `Creating keys… ${p}%` : "Keys created. Back up to activate.";
        if (p < 100) setTimeout(tick, 420);
      };
      tick();
    });
  }

  // Send & confirm: step through payment states
  const states = ["preparing", "collecting", "ready", "broadcast", "confirmed"];
  const advance = document.getElementById("send-advance");
  const rollback = document.getElementById("send-rollback");
  const setState = (name) => {
    document.querySelectorAll("[data-sendstate]").forEach((el) => {
      const i = states.indexOf(el.dataset.sendstate);
      const cur = states.indexOf(name);
      el.classList.toggle("done", i < cur);
      el.classList.toggle("active", i === cur);
      el.classList.toggle("pending", i > cur);
    });
    const cap = document.getElementById("send-caption");
    if (cap) cap.textContent = {
      preparing: "Fresh signing commitments are being sealed in each signer. Nothing is approved yet.",
      collecting: "Commitments are in. A candidate is being built for each eligible pair.",
      ready: "Two valid shares collected. Any synced member can finish and broadcast.",
      broadcast: "Transaction broadcast. Waiting for a block to mine it.",
      confirmed: "Confirmed by this device's own chain scan. A reorg can roll this back.",
    }[name];
    const badge = document.getElementById("send-badge");
    if (badge) {
      badge.textContent = name.toUpperCase();
      badge.className = "pill " + (name === "confirmed" ? "pill-ok" : name === "broadcast" ? "pill-info" : "pill-warn");
    }
  };
  if (advance) {
    advance.addEventListener("click", () => {
      const active = document.querySelector("[data-sendstate].active");
      const i = active ? states.indexOf(active.dataset.sendstate) : -1;
      setState(states[Math.min(states.length - 1, i + 1)]);
    });
  }
  if (rollback) rollback.addEventListener("click", () => setState("broadcast"));

  // Approve / refuse on the hero
  const outcome = document.getElementById("sign-outcome");
  document.getElementById("do-approve")?.addEventListener("click", () => {
    if (outcome) { outcome.textContent = "Share released for this exact package. Returning to the payment."; outcome.className = "callout callout-accent"; outcome.classList.remove("hidden"); }
    setTimeout(() => show("send"), 900);
  });
  document.getElementById("do-refuse")?.addEventListener("click", () => {
    if (outcome) { outcome.textContent = "Refused. No share released. A refusal is your decision, not a veto on the group."; outcome.className = "callout callout-danger"; outcome.classList.remove("hidden"); }
  });

  // address reveal on overview
  document.getElementById("reveal-addr")?.addEventListener("click", (e) => {
    document.getElementById("addr-hidden")?.classList.add("hidden");
    document.getElementById("addr-shown")?.classList.remove("hidden");
    e.target.classList.add("hidden");
  });
}

document.addEventListener("DOMContentLoaded", () => {
  // restore a saved theme before first paint of the toggle state
  let saved = null;
  try { saved = localStorage.getItem("loki-theme"); } catch (e) {}
  if (saved) document.documentElement.setAttribute("data-theme", saved);

  buildNav();
  wireDemos();
  wireTofN();

  document.querySelectorAll("[data-theme-btn]").forEach((b) =>
    b.addEventListener("click", () => theme(b.dataset.themeBtn)));

  // cross-screen links + copy buttons (clipboard degrades to a label flash on file://)
  document.body.addEventListener("click", (e) => {
    const go = e.target.closest("[data-nav]");
    if (go) { e.preventDefault(); show(go.dataset.nav); return; }
    const cp = e.target.closest("[data-copy]");
    if (cp) {
      const prev = cp.textContent;
      navigator.clipboard?.writeText(cp.dataset.copy).catch(() => {});
      cp.textContent = "Copied";
      setTimeout(() => { cp.textContent = prev; }, 1100);
    }
  });

  theme(saved || "system");
  const start = location.hash.slice(1);
  show(screens.some(([id]) => id === start) ? start : "connect");
});

// deep-link: respond to back/forward and manual hash edits
window.addEventListener("hashchange", () => {
  const id = location.hash.slice(1);
  if (screens.some(([s]) => s === id)) show(id);
});
