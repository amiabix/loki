"""Background payment progress while the profile is unlocked.

The worker runs the payment steps that need no human judgement, the same ones the
signer page used to run on a poll: deliver queued proposals and saved signing
messages, receive and import, commit nonces, build the package, resend saved
approvals, and check readiness and the chain. It never reviews, approves or sends:
those stay signer-window actions. The rule is enforced by `check`, which every
native command consults, not only by which methods the worker calls.
"""
import collections
import contextlib
import threading
import time

# (binary, command) pairs the worker thread may run. Frozen: review,
# approve-reviewed and finish are absent and stay so.
ALLOWED = frozenset({
    ("loki_relay_member", "payment-sync"),
    ("loki_relay_member", "features"),
    ("loki_member_payment", "local-wires"),
    ("loki_member_payment", "resend"),
    ("loki_member_payment", "commit"),
    ("loki_member_payment", "package"),
    ("loki_member_payment", "finish-check"),
    ("loki_member_payment", "find-mined"),
    ("loki_member_payment", "verify"),
    ("loki_member_payment", "tip"),
    ("loki_member_payment", "chain-check"),
    ("loki_member_payment", "features"),
})
NEVER = frozenset({"review", "approve-reviewed", "finish"})
# Payment phases in which a payment still needs work from some member.
SETTLED = frozenset({"confirmed", "draft"})
MID_FLIGHT_SECONDS = 2
IDLE_SECONDS = 3
CONFIRMED_RECHECK_SECONDS = 10
STOP_SECONDS = 5


class PaymentWorker:
    def __init__(self, wallet):
        self.wallet = wallet
        self.local = threading.local()
        self.stop_event = threading.Event()
        self.wake = threading.Event()
        self.thread = None
        self.meta_lock = threading.Lock()
        self.vault_locks = {}
        self.user_waiting = collections.Counter()
        self.due = {}
        self.errors = {}
        self.backoff = {}
        self.burst = {}
        self.ready = {}
        self.checked = {}
        self.passes = collections.Counter()
        self.pass_done = threading.Condition(self.meta_lock)
        self.processes = set()
        self.process_lock = threading.Lock()

    # ── the rule ──────────────────────────────────────────────────────────────
    def on_worker(self):
        return getattr(self.local, "worker", False)

    def check(self, binary_name, action):
        if self.on_worker() and (action in NEVER or (binary_name, action) not in ALLOWED):
            raise PermissionError(f"The payment worker may not run {binary_name} {action}")

    # ── locks: one per vault, user actions first ─────────────────────────────
    def _lock(self, vault):
        with self.meta_lock:
            return self.vault_locks.setdefault(vault, threading.RLock())

    @contextlib.contextmanager
    def user_action(self, vault, poke=True):
        """Run a signer-window payment action on `vault` between worker steps.
        Read-only actions pass poke=False so they do not start a worker pass."""
        with self.meta_lock:
            self.user_waiting[vault] += 1
        try:
            with self._lock(vault):
                yield
        finally:
            with self.meta_lock:
                self.user_waiting[vault] -= 1
                if not self.user_waiting[vault]:
                    del self.user_waiting[vault]
            if poke:
                self.poke(vault)

    def user_pending(self, vault):
        with self.meta_lock:
            return self.user_waiting.get(vault, 0) > 0

    def yield_to_user(self, vault, limit=STOP_SECONDS):
        """Between two worker steps: let pending signer-window actions on `vault` run
        first, then continue the pass."""
        if not self.user_pending(vault):
            return
        lock = self._lock(vault)
        lock.release()
        try:
            end = time.monotonic() + limit
            while self.user_pending(vault) and time.monotonic() < end and not self.stop_event.is_set():
                time.sleep(0.02)
        finally:
            lock.acquire()

    # ── lifecycle ─────────────────────────────────────────────────────────────
    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self.run, daemon=True, name="payment-worker")
        self.thread.start()

    def stop(self):
        """Lock: stop within STOP_SECONDS, killing a native command still running."""
        self.stop_event.set()
        self.wake.set()
        with self.process_lock:
            for process in self.processes:
                if process.poll() is None:
                    process.terminate()
        if self.thread and self.thread is not threading.current_thread():
            self.thread.join(timeout=STOP_SECONDS - 1)
        with self.process_lock:
            for process in self.processes:
                if process.poll() is None:
                    process.kill()
        with self.meta_lock:
            self.ready.clear()
            self.checked.clear()
            self.errors.clear()
            self.due.clear()
            self.pass_done.notify_all()

    def running(self):
        return bool(self.thread and self.thread.is_alive() and not self.stop_event.is_set())

    def track(self, process):
        """Register a native child started on the worker thread, so Lock can stop it."""
        if not self.on_worker():
            return False
        with self.process_lock:
            stopped = self.stop_event.is_set()
            if not stopped:
                self.processes.add(process)
        if stopped:
            if process.poll() is None:
                process.kill()
            process.communicate()
            raise ValueError("Signer is locked")
        return True

    def untrack(self, process):
        with self.process_lock:
            self.processes.discard(process)

    def poke(self, vault=None):
        with self.meta_lock:
            for name in ([vault] if vault else list(self.due)):
                self.due[name] = 0.0
        self.wake.set()

    def sync_now(self, vault, timeout=60):
        """Run one pass for `vault` now and wait for it ("Check for updates")."""
        if not self.running():
            raise ValueError("Unlock your profile first")
        if vault not in self.wallet.payment_vaults():
            raise ValueError("Relay payments are not available for this vault yet")
        with self.meta_lock:
            seen = self.passes[vault]
            self.errors.pop(vault, None)
            self.backoff.pop(vault, None)
            self.due[vault] = 0.0
        self.wake.set()
        end = time.monotonic() + timeout
        with self.meta_lock:
            while self.passes[vault] == seen and not self.stop_event.is_set():
                left = end - time.monotonic()
                if left <= 0:
                    raise ValueError("Payment updates are still running; try again shortly")
                self.pass_done.wait(left)
            if vault in self.errors:
                raise ValueError(self.errors[vault])

    # ── the loop ──────────────────────────────────────────────────────────────
    def run(self):
        self.local.worker = True
        while not self.stop_event.is_set():
            try:
                vaults = self.wallet.payment_vaults()
            except (ValueError, OSError):
                vaults = []
            now = time.monotonic()
            for vault in vaults:
                if self.stop_event.is_set():
                    break
                with self.meta_lock:
                    due = self.due.setdefault(vault, 0.0)
                if due > now or self.user_pending(vault):
                    continue
                self._pass(vault)
            with self.meta_lock:
                waits = [max(0.0, self.due.get(vault, 0.0) - time.monotonic()) for vault in vaults]
            self.wake.wait(min([1.0, *waits]) if waits else 1.0)
            self.wake.clear()

    def _pass(self, vault):
        lock = self._lock(vault)
        if not lock.acquire(timeout=0.05):
            return
        progressed = False
        try:
            progressed = self.wallet.payment_pass(vault, self)
            error = None
        except Exception as caught:  # noqa: BLE001 - surfaced to the page, then retried
            error = str(caught) or type(caught).__name__
        finally:
            lock.release()
        with self.meta_lock:
            now = time.monotonic()
            if error:
                self.errors[vault] = error
                self.backoff[vault] = min(30.0, self.backoff.get(vault, 1.0) * 2)
                self.due[vault] = now + self.backoff[vault]
            else:
                self.errors.pop(vault, None)
                self.backoff.pop(vault, None)
                busy = self.wallet.payments_mid_flight(vault)
                # Straight on after progress (at most 20 passes in a row), then the cadence.
                self.burst[vault] = self.burst.get(vault, 0) + 1 if progressed else 0
                if progressed and self.burst[vault] <= 20:
                    self.due[vault] = now
                else:
                    self.due[vault] = now + (MID_FLIGHT_SECONDS if busy else IDLE_SECONDS)
            self.passes[vault] += 1
            self.pass_done.notify_all()

    # ── cached results for the pure-read payment list ─────────────────────────
    def set_ready(self, vault, attempt, ready):
        with self.meta_lock:
            self.ready[(vault, attempt)] = ready

    def is_ready(self, vault, attempt):
        with self.meta_lock:
            return self.ready.get((vault, attempt), False)

    def recheck_due(self, vault, attempt):
        with self.meta_lock:
            last = self.checked.get((vault, attempt))
            return last is None or time.monotonic() - last >= CONFIRMED_RECHECK_SECONDS

    def rechecked(self, vault, attempt):
        with self.meta_lock:
            self.checked[(vault, attempt)] = time.monotonic()

    def error(self, vault):
        with self.meta_lock:
            return self.errors.get(vault)
