import AppKit

typealias ConnectCancellation = @convention(c) (UnsafeRawPointer?) -> Int32
typealias ConnectDecision = @convention(c) (UnsafePointer<CChar>?, UnsafePointer<CChar>?,
    UnsafeRawPointer?, ConnectCancellation) -> Int32

@_silgen_name("loki_member_app_pair")
func loki_member_app_pair(_ launch: UnsafePointer<CChar>, _ pass: UnsafeMutablePointer<CChar>,
    _ notify: @convention(c) (UnsafePointer<CChar>?, UnsafePointer<CChar>?) -> Void,
    _ approve: @convention(c) (UnsafePointer<CChar>?) -> Int32,
    _ confirmRoster: @convention(c) (UnsafePointer<CChar>?) -> Int32,
    _ connect: ConnectDecision) -> Int32

@_silgen_name("loki_member_app_disconnect_wallet_tabs")
func loki_member_app_disconnect_wallet_tabs()

@_silgen_name("loki_member_app_pairing_target")
func loki_member_app_pairing_target(_ launch: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?

@_silgen_name("loki_member_app_pairing_link")
private func loki_member_app_pairing_link(_ launch: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?

@_silgen_name("loki_member_app_configuration")
func loki_member_app_configuration(_ launch: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?

@_silgen_name("loki_member_app_profile")
func loki_member_app_profile(_ launch: UnsafePointer<CChar>, _ action: UInt32) -> UnsafeMutablePointer<CChar>?

@_silgen_name("loki_member_app_stop")
func loki_member_app_stop() -> Int32

@_silgen_name("loki_member_app_free")
func loki_member_app_free(_ value: UnsafeMutablePointer<CChar>?)

/// One Rust query on this launch: `{"<answer>": ...}` or `{"error": ...}`. Every value shown
/// to the member comes from Rust, which checked it; nothing is parsed from the link here.
private func nativeQuery(_ query: (UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?, _ launch: [String: Any]) -> [String: Any] {
    guard let json = try? JSONSerialization.data(withJSONObject: launch), let request = String(data: json, encoding: .utf8) else {
        return ["error": "invalid launch"]
    }
    let reply = request.withCString { query($0) }
    return nativeReply(reply)
}

func nativeReply(_ reply: UnsafeMutablePointer<CChar>?) -> [String: Any] {
    defer { loki_member_app_free(reply) }
    guard let reply = reply,
          let parsed = try? JSONSerialization.jsonObject(with: Data(String(cString: reply).utf8)) as? [String: Any]
    else { return ["error": "invalid reply"] }
    return parsed
}

func retryAlert(_ failure: SignerStartFailure, profile: String?) -> NSAlert {
    let alert = NSAlert()
    alert.messageText = failure == .cancelled ? "LokiSigner paused" : "LokiSigner couldn’t continue"
    alert.informativeText = profile == "vault" && failure == .notFresh
        ? SignerStartFailure.protectedProfile.message : failure.message
    if profile == "vault", [.differentPairing, .wrongProfile, .registrationRefused].contains(failure) {
        alert.informativeText += "\n\n" + SignerStartFailure.protectedProfile.message
    }
    alert.addButton(withTitle: "Try again")
    alert.addButton(withTitle: "Quit")
    if profile == "profile" || (profile == "vault" && failure.keyIsGone) {
        alert.addButton(withTitle: failure.keyIsGone ? "Set aside profile…" : "Start over…")
    }
    return alert
}

func setAsideAlert(recover: Bool = false) -> NSAlert {
    let alert = NSAlert()
    alert.messageText = "Set aside this LokiSigner profile?"
    alert.informativeText = recover
        ? "LokiSigner will rename the entire local data folder, including any vault data. Nothing will be deleted. To restore your vault in the original location, choose “Restore from recovery words”. You’ll need your recovery words and downloaded backup file."
        : "LokiSigner will rename the entire local data folder, including this profile’s identity and pairing settings. Nothing will be deleted. You can then pair a new signer or choose “Restore from recovery words”. To restore, you’ll need your recovery words and downloaded backup file."
    alert.addButton(withTitle: "Cancel")
    alert.addButton(withTitle: "Set aside and start over")
    return alert
}

func registrationWarningAlert(_ message: String, key: Bool = false, recover: Bool = false) -> NSAlert {
    let alert = NSAlert()
    alert.messageText = key ? "LokiSigner is still running" : "LokiSigner is running"
    alert.informativeText = message
    alert.addButton(withTitle: "OK")
    if recover { alert.addButton(withTitle: "Set aside profile…") }
    return alert
}

@_silgen_name("loki_signer_approval_selftest")
func loki_signer_approval_selftest(_ approve: @convention(c) (UnsafePointer<CChar>?) -> Int32) -> Int32

/// Presents a decision requested by the wallet, without accepting input carried over from
/// another window. Keep native buttons so assistive technology can still press them.
func runDecisionAlert(_ alert: NSAlert, timeout: TimeInterval? = nil,
                      escape: NSApplication.ModalResponse,
                      field: NSTextField? = nil) -> NSApplication.ModalResponse {
    alert.layout()
    let window = alert.window
    let buttons = alert.buttons
    var controls: [NSView] = buttons
    if let field { controls.append(field) }
    for button in buttons {
        button.keyEquivalent = ""
        button.isEnabled = false
    }
    window.defaultButtonCell = nil
    window.initialFirstResponder = field

    var acceptsInputSince = TimeInterval.infinity
    var enable: Timer?
    let center = NotificationCenter.default
    let becameKey = center.addObserver(forName: NSWindow.didBecomeKeyNotification,
                                       object: window, queue: nil) { _ in
        window.makeFirstResponder(field)
        let deadline = ProcessInfo.processInfo.systemUptime + 1
        let timer = Timer(timeInterval: 1, repeats: false) { _ in
            guard window.isKeyWindow, window.isVisible else { return }
            acceptsInputSince = deadline
            for button in buttons { button.isEnabled = true }
        }
        enable = timer
        RunLoop.main.add(timer, forMode: .modalPanel)
    }
    let resignedKey = center.addObserver(forName: NSWindow.didResignKeyNotification,
                                         object: window, queue: nil) { _ in
        enable?.invalidate()
        acceptsInputSince = .infinity
        for button in buttons { button.isEnabled = false }
    }

    let input = NSEvent.addLocalMonitorForEvents(matching: [.keyDown, .leftMouseDown, .leftMouseUp]) { event in
        guard event.window === window else { return event }
        guard event.timestamp >= acceptsInputSince else { return nil }
        guard event.type == .keyDown else { return event }

        let focused = window.firstResponder
        let editing = field.map { $0 === focused || $0.currentEditor() === focused } ?? false
        switch event.keyCode {
        case 36, 76: // Return, keypad Enter
            return nil
        case 48: // Tab / Shift-Tab
            // Keep the field reachable even when macOS Keyboard Navigation is off.
            guard !event.isARepeat else { return nil }
            let reverse = event.modifierFlags.contains(.shift)
            let current = editing ? controls.count - 1 : controls.firstIndex { $0 === focused }
            let next = current.map { ($0 + (reverse ? controls.count - 1 : 1)) % controls.count }
                ?? (reverse ? controls.count - 1 : 0)
            window.makeFirstResponder(controls[next])
            return nil
        case 49: // Space
            if editing { return event }
            if !event.isARepeat { buttons.first { $0 === focused }?.performClick(nil) }
            return nil
        case 53: // Escape
            if !event.isARepeat { NSApp.stopModal(withCode: escape) }
            return nil
        default:
            return event
        }
    }

    NSApp.activate(ignoringOtherApps: true)
    let expiry = timeout.map { seconds in
        let timer = Timer(timeInterval: seconds, repeats: false) { _ in NSApp.abortModal() }
        RunLoop.main.add(timer, forMode: .modalPanel)
        return timer
    }
    defer {
        expiry?.invalidate()
        enable?.invalidate()
        center.removeObserver(becameKey)
        center.removeObserver(resignedKey)
        if let input = input { NSEvent.removeMonitor(input) }
    }
    return alert.runModal()
}

/// An unanswered payment request is refused after this long.
private let approvalTimeout: TimeInterval = 120

private func zec(_ value: Any?) -> String {
    let zat = (value as? NSNumber)?.uint64Value ?? 0
    return String(format: "%llu.%08llu ZEC", zat / 100_000_000, zat % 100_000_000)
}

/// The member's decision on one payment, called by the signer from a worker thread just
/// before it would release its signature share. Every detail shown is what the signer
/// derived from the transaction bytes itself. Returns 1 only for an explicit approval;
/// Refuse, closing the dialog, a malformed request or the timeout all refuse.
private func nativeApprove(_ summary: UnsafePointer<CChar>?) -> Int32 {
    guard let summary = summary,
          let request = try? JSONSerialization.jsonObject(with: Data(String(cString: summary).utf8)) as? [String: Any]
    else { return 0 }
    var approved = false
    DispatchQueue.main.sync {
        guard NativeSigner.walletDecisionAllowed else { return }
        defer { NativeSigner.embeddedSigner?.resumeWalletWarnings() }
        let text = { (key: String) in request[key] as? String ?? "?" }
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Approve this payment?"
        let memo = text("memo").isEmpty ? "" : "\nMemo: \(text("memo"))"
        let fee = (request["fee_verified"] as? Bool) == true ? zec(request["fee_zat"]) : "\(zec(request["fee_zat"])) (NOT VERIFIED)"
        let member = (request["member"] as? NSNumber)?.stringValue ?? "?"
        alert.informativeText = """
            Recipient: \(text("recipient"))
            Amount: \(zec(request["amount_zat"]))
            Fee: \(fee)
            Change back to the vault: \(zec(request["change_zat"]))
            Network: \(text("network")) (branch \(text("branch_id")))\(memo)

            Member \(member) — Vault: \(text("vault"))
            Payment: \(text("payment"))
            Attempt: \(text("attempt"))
            Signs: \(text("sighash"))

            LokiSigner read these details from the transaction itself, not from the wallet page. \
            Approve only if they match the payment you intend. Unanswered requests are refused after \(Int(approvalTimeout / 60)) minutes.
            """
        alert.addButton(withTitle: "Refuse")
        alert.addButton(withTitle: "Approve and sign")
        approved = runDecisionAlert(alert, timeout: approvalTimeout, escape: .alertFirstButtonReturn)
            == .alertSecondButtonReturn
    }
    return approved ? 1 : 0
}

/// An unanswered roster comparison is refused after this long; members compare by phone.
private let rosterTimeout: TimeInterval = 600

/// The most combining marks shown in a row; the rest are dropped so text stays in its line.
private let combiningMarksShown = 3

/// Another party's text, such as a vault name from the creator, as one plain line. Rust already
/// hides a name with control, format, default-ignorable or line-breaking characters or with a
/// long run of combining marks (`vault_label`). This is the second layer: any such character
/// that still arrives becomes U+FFFD, and a run of combining marks is cut to three.
func untrustedText(_ text: String) -> String {
    let replaced: Set<Unicode.GeneralCategory> = [.control, .format, .lineSeparator, .paragraphSeparator]
    let marks: Set<Unicode.GeneralCategory> = [.nonspacingMark, .enclosingMark]
    var scalars = String.UnicodeScalarView()
    var run = 0
    for scalar in text.unicodeScalars {
        let category = scalar.properties.generalCategory
        if replaced.contains(category) || scalar.properties.isDefaultIgnorableCodePoint {
            scalars.append("\u{FFFD}")
            run = 0
        } else if marks.contains(category) {
            run += 1
            if run <= combiningMarksShown { scalars.append(scalar) }
        } else {
            scalars.append(scalar)
            run = 0
        }
    }
    return String(scalars)
}

/// A bordered one-line box holding another party's text, apart from the app's own wording.
/// The text is truncated at the box's edge and its drawing is clipped to the box.
func untrustedLine(_ text: String) -> NSTextField {
    let field = NSTextField(labelWithString: untrustedText(text))
    field.isBordered = true
    field.drawsBackground = true
    field.backgroundColor = .textBackgroundColor
    field.usesSingleLineMode = true
    field.maximumNumberOfLines = 1
    field.cell?.wraps = false
    field.lineBreakMode = .byTruncatingTail
    field.isSelectable = true
    if #available(macOS 14, *) { field.clipsToBounds = true }
    return field
}

/// The member's comparison of a vault's roster code, called by the member from a worker thread
/// when the wallet asks to agree to a roster. The code is the one Rust derived from the setup
/// document key generation will use. Returns 1 for an explicit "Codes match" and 2 for
/// "Codes differ"; closing the dialog, a malformed request or the timeout return 0.
private func nativeConfirmRoster(_ summary: UnsafePointer<CChar>?) -> Int32 {
    guard let summary = summary,
          let request = try? JSONSerialization.jsonObject(with: Data(String(cString: summary).utf8)) as? [String: Any],
          let code = request["roster_code"] as? String,
          code.range(of: "^[0-9]{4}( [0-9]{4}){5}$", options: .regularExpression) != nil,
          let name = request["vault_name"] as? String,
          let threshold = (request["threshold"] as? NSNumber)?.intValue,
          let members = (request["members"] as? NSNumber)?.intValue,
          let member = (request["member"] as? NSNumber)?.intValue,
          let network = request["network"] as? String, ["regtest", "testnet"].contains(network)
    else { return 0 }
    var answer: Int32 = 0
    DispatchQueue.main.sync {
        guard NativeSigner.walletDecisionAllowed else { return }
        defer { NativeSigner.embeddedSigner?.resumeWalletWarnings() }
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Do the roster codes match?"
        alert.informativeText = """
            A vault needs \(threshold) of \(members) members to approve. You are member \(member). Network: \(network).

            Compare the code below with every other member over a channel you already trust, \
            such as a phone call or in person. Choose Codes match only if every member sees \
            the same code. If any code differs, someone may have been swapped into this vault: \
            choose Codes differ.

            Unanswered requests are refused after \(Int(rosterTimeout / 60)) minutes.
            """
        let codeLabel = NSTextField(labelWithString: "Roster code")
        codeLabel.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        let codeField = NSTextField(labelWithString: code)
        codeField.font = .monospacedDigitSystemFont(ofSize: 20, weight: .semibold)
        codeField.isSelectable = true
        let nameLabel = NSTextField(labelWithString: "Vault name (set by creator):")
        nameLabel.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        let nameField = untrustedLine(name)
        let stack = NSStackView(views: [codeLabel, codeField, nameLabel, nameField])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 4
        stack.setCustomSpacing(12, after: codeField)
        stack.frame = NSRect(x: 0, y: 0, width: 420, height: 96)
        nameField.widthAnchor.constraint(equalToConstant: 420).isActive = true
        alert.accessoryView = stack
        alert.addButton(withTitle: "Codes differ")
        alert.addButton(withTitle: "Codes match")
        switch runDecisionAlert(alert, timeout: rosterTimeout, escape: .abort) {
        case .alertSecondButtonReturn: answer = 1
        case .alertFirstButtonReturn: answer = 2
        default: answer = 0
        }
    }
    return answer
}

private func nativeConnect(_ origin: UnsafePointer<CChar>?, _ code: UnsafePointer<CChar>?,
                           _ context: UnsafeRawPointer?, _ cancelled: ConnectCancellation) -> Int32 {
    guard let origin, let code, let context else { return 0 }
    let coordinator = String(cString: origin), comparison = String(cString: code)
    return DispatchQueue.main.sync {
        showConnectDialog(origin: coordinator, code: comparison, cancelled: { cancelled(context) != 0 }) ? 1 : 0
    }
}

/// Only answer the request whose code matches the wallet tab. The borrowed cancellation
/// check is used only while the C callback is live, including during the modal run loop.
func showConnectDialog(origin: String, code: String, cancelled: @escaping () -> Bool) -> Bool {
    guard !cancelled(), NSApp.modalWindow == nil else { return false }
    let alert = NSAlert()
    alert.messageText = "Connect this wallet tab?"
    alert.informativeText = """
        Wallet: \(origin)

        Choose Allow only if you clicked Connect LokiSigner and the code below matches the one in that tab.
        Unanswered requests are refused in under two minutes.
        """
    let comparison = NSTextField(labelWithString: code)
    comparison.font = .monospacedDigitSystemFont(ofSize: 24, weight: .semibold)
    comparison.frame = NSRect(x: 0, y: 0, width: 230, height: 30)
    alert.accessoryView = comparison
    alert.addButton(withTitle: "Refuse")
    alert.addButton(withTitle: "Allow")
    let window = alert.window
    let timer = Timer(timeInterval: 0.1, repeats: true) { _ in
        if cancelled() && NSApp.modalWindow === window { NSApp.abortModal() }
    }
    RunLoop.main.add(timer, forMode: .modalPanel)
    defer { timer.invalidate() }
    return runDecisionAlert(alert, escape: .alertFirstButtonReturn) == .alertSecondButtonReturn && !cancelled()
}

private func nativeNotice(_ kind: UnsafePointer<CChar>?, _ message: UnsafePointer<CChar>?) {
    guard let kind = kind, let message = message else { return }
    let event = String(cString: kind), text = String(cString: message)
    if event == "registration-warning" || event == "registration-key" || event == "registration-key-gone" {
        // Rust supplies fixed copy here. Don't block its retry loop on an open dialog.
        DispatchQueue.main.async { NativeSigner.current?.warnRegistration(event, message: text) }
        return
    }
    if event == "startup-key" || event == "startup-key-gone" {
        DispatchQueue.main.async { NativeSigner.current?.startupKeyFailure = event == "startup-key-gone" ? .keyGone(text) : .key(text) }
        return
    }
    // Synchronous delivery keeps recovery words on screen before registration continues.
    DispatchQueue.main.sync {
        let alert = NSAlert()
        if event == "ready" || event == "restore-ready" || event == "restore-pending" {
            if let signer = NativeSigner.embeddedSigner, event == "ready" {
                signer.didStart()
                return
            }
            alert.messageText = event == "ready" ? "LokiSigner is running" : "Vault restored"
            let connect = NativeSigner.embeddedSigner != nil ? "Keep LokiSigner running to approve and sign."
                : "On this Mac, choose Connect LokiSigner in the wallet. If the wallet only offers to paste a link, ask the coordinator to update it. Keep LokiSigner running to approve and sign."
            alert.informativeText = event == "restore-pending"
                ? "Your vault is saved on this Mac. LokiSigner will keep trying to reconnect, without your recovery words.\n\n\(connect)"
                : connect
            alert.addButton(withTitle: "Done")
            alert.runModal()
            NativeSigner.current?.didStart()
        } else if event == "recovery" {
            alert.messageText = "Save your recovery words privately"
            alert.informativeText = text
            alert.addButton(withTitle: "I saved these words")
            alert.runModal()
        }
    }
}

final class NativeSigner: NSObject, NSApplicationDelegate {
    private static var embeddedMode = false
    fileprivate static weak var embeddedSigner: NativeSigner?
    fileprivate static var current: NativeSigner? { embeddedSigner ?? (NSApp.delegate as? NativeSigner) }
    fileprivate static var walletDecisionAllowed: Bool { !embeddedMode || embeddedSigner?.canShowWalletDecision == true }
    private let embedded: Bool
    private var ready = false
    private var stopping = false
    private var walletCompletion: ((SignerStartFailure?) -> Void)?
    private var lockCompletions: [() -> Void] = []
    private let walletWork = DispatchGroup()
    private var running = false
    private var prompting = false {
        didSet {
            if !prompting && !registrationWarnings.isEmpty { DispatchQueue.main.async { self.showNextRegistrationWarning() } }
        }
    }
    private var registrationWarnings: [(event: String, message: String)] = []
    fileprivate var startupKeyFailure: SignerStartFailure?
    private var opened = false
    private var cleanupNeeded = true
    private var retryLink: String?
    private var queuedLink: String?
    private var startingOver = false
    private var recoveringKey = false
    private let args: [String]
    private let initialLink: String?

    init(args: [String], link: String?, embedded: Bool = false) {
        self.args = args
        self.initialLink = link
        self.embedded = embedded
        super.init()
        if embedded { Self.embeddedMode = true; Self.embeddedSigner = self }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.activate(ignoringOtherApps: true)
        DispatchQueue.main.async {
            if !self.opened { self.opened = true; self.start(self.initialLink) }
        }
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        opened = true
        guard let url = urls.first else { return }
        if prompting { queuedLink = url.absoluteString }
        else { start(url.absoluteString) }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if opened && !running && !prompting { start(queuedLink ?? retryLink) }
        return true
    }

    private func profile(_ action: UInt32 = 0) -> [String: Any] {
        nativeQuery({ loki_member_app_profile($0, action) }, ["args": args])
    }

    private func startupProfile() -> [String: Any] {
        let location = profile(cleanupNeeded ? 1 : 0)
        if location["profile"] != nil { cleanupNeeded = false }
        return location
    }

    var walletReady: Bool { ready && !stopping && !startingOver }
    fileprivate var canShowWalletDecision: Bool { walletReady && !prompting && NSApp.modalWindow == nil }

    func walletProfile() -> [String: Any] {
        var value = profile()
        value["running"] = walletReady
        return value
    }

    func beginWalletOperation(_ completion: @escaping (SignerStartFailure?) -> Void) -> Bool {
        guard !prompting, !stopping, !running || walletReady,
              walletCompletion == nil, NSApp.modalWindow == nil else { return false }
        walletCompletion = completion
        return true
    }

    private func finishWalletOperation(_ failure: SignerStartFailure? = nil) {
        prompting = false
        retryLink = nil
        let completion = walletCompletion
        walletCompletion = nil
        completion?(failure)
    }

    func unlockWallet() {
        if walletReady { finishWalletOperation(); return }
        start(nil)
    }

    func pairWallet(origin: String) {
        guard !running else { finishWalletOperation(.differentPairing); return }
        prompting = true
        let state = startupProfile()
        guard let profile = state["profile"] as? String else { retry(.dataFolderUnavailable, link: nil); return }
        if profile == "fresh", !canSetUpWithTouchID() { finishWalletOperation(.cancelled); return }
        let launch: [String: Any] = ["args": args, "restore_origin": origin]
        let reply = nativeQuery(loki_member_app_pairing_target, launch)
        guard let target = reply["target"] as? [String: Any], let coordinator = target["coordinator"] as? String,
              coordinator.hasPrefix("https://") else { finishWalletOperation(.coordinatorOrigin); return }
        let alert = NSAlert()
        alert.messageText = "Contact this coordinator?"
        alert.informativeText = """
            Coordinator: \(coordinator)

            Compare this address with the one your vault organizer gave you. No request has been sent yet. Continuing asks this coordinator to reserve a member slot.

            Adding or removing a Touch ID fingerprint makes this Mac’s signer keys unusable. Save your recovery words and encrypted vault backups privately.
            """
        alert.addButton(withTitle: "Continue")
        alert.addButton(withTitle: "Cancel")
        guard runDecisionAlert(alert, escape: .alertSecondButtonReturn) == .alertFirstButtonReturn else {
            finishWalletOperation(.cancelled); return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let reply = nativeQuery(loki_member_app_pairing_link, launch)
            DispatchQueue.main.async {
                guard let link = reply["link"] as? String else { self.finishWalletOperation(.registrationRefused); return }
                self.loadConfiguration(link: link, approvedOrigin: coordinator)
            }
        }
    }

    func restoreWallet() {
        if walletReady { restoreVault(nil); return }
        prompting = true
        switch startupProfile()["profile"] as? String {
        case "fresh":
            if canSetUpWithTouchID() { beginRecovery() } else { finishWalletOperation(.cancelled) }
        case "profile":
            if !confirmSetAside() { finishWalletOperation(.cancelled) }
        case "vault":
            finishWalletOperation(.unlockToRestore)
        default:
            finishWalletOperation(.dataFolderUnavailable)
        }
    }

    func lockWallet(_ completion: @escaping () -> Void) -> Bool {
        if stopping { lockCompletions.append(completion); return true }
        guard !prompting, !startingOver, NSApp.modalWindow == nil else { return false }
        guard running else { completion(); return true }
        stopping = true
        lockCompletions.append(completion)
        // If Rust already exited, its queued stopped() callback still drains and completes lock.
        _ = loki_member_app_stop()
        return true
    }

    func performWalletWork(_ work: @escaping () -> [String: Any],
                           complete: @escaping ([String: Any]?) -> Void) -> Bool {
        guard walletReady else { return false }
        walletWork.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            let value = work()
            DispatchQueue.main.async {
                complete(self.walletReady ? value : nil)
                self.walletWork.leave()
                self.resumeWalletWarnings()
            }
        }
        return true
    }

    private func retry(_ failure: SignerStartFailure, link: String?) {
        if embedded {
            if failure.keyIsGone, let state = profile()["profile"] as? String, ["profile", "vault"].contains(state) {
                prompting = true
                let alert = NSAlert()
                alert.messageText = "LokiSigner couldn’t use the local key"
                alert.informativeText = failure.message
                alert.addButton(withTitle: "OK")
                alert.addButton(withTitle: "Set aside profile…")
                if alert.runModal() == .alertSecondButtonReturn, confirmSetAside(recover: true) { return }
            }
            finishWalletOperation(failure)
            return
        }
        prompting = true
        retryLink = link
        let alert = retryAlert(failure, profile: profile()["profile"] as? String)
        NSApp.activate(ignoringOtherApps: true)
        switch alert.runModal() {
        case .alertSecondButtonReturn:
            NSApp.terminate(nil)
        case .alertThirdButtonReturn:
            if confirmSetAside(recover: failure.keyIsGone) { return }
        default: break
        }
        // Don't nest modal panels or keep a previous passphrase field alive on retry.
        DispatchQueue.main.async {
            self.prompting = false
            self.start(self.queuedLink ?? (failure == .differentPairing ? nil : self.retryLink))
        }
    }

    private func confirmSetAside(recover: Bool = false) -> Bool {
        if embedded, !canSetUpWithTouchID() { finishWalletOperation(.cancelled); return true }
        guard setAsideAlert(recover: recover).runModal() == .alertSecondButtonReturn else { return false }
        recoveringKey = recover
        if running {
            startingOver = loki_member_app_stop() != 0
            if !startingOver {
                DispatchQueue.main.async {
                    if self.running { self.retry(.setAsideFailed, link: self.retryLink) }
                }
            }
        } else {
            finishSetAside()
        }
        return true
    }

    private func finishSetAside() {
        let recover = recoveringKey
        recoveringKey = false
        let reply = profile(recover ? 3 : 2)
        if reply["profile"] as? String != "fresh" {
            retry(reply["error"] as? String == "vault" ? .protectedProfile : .setAsideFailed, link: retryLink)
        } else {
            let link = recover ? nil : queuedLink ?? retryLink
            DispatchQueue.main.async {
                if self.embedded {
                    if canSetUpWithTouchID() { self.beginRecovery() } else { self.finishWalletOperation(.cancelled) }
                } else {
                    self.prompting = false
                    self.start(link)
                }
            }
        }
    }

    fileprivate func didStart() {
        ready = true
        prompting = false
        queuedLink = nil
        if embedded { finishWalletOperation() }
    }

    fileprivate func warnRegistration(_ event: String, message: String) {
        guard running, !startingOver, !stopping else { return }
        registrationWarnings.append((event, message))
        showNextRegistrationWarning()
    }

    fileprivate func resumeWalletWarnings() {
        DispatchQueue.main.async { self.showNextRegistrationWarning() }
    }

    private func showNextRegistrationWarning() {
        guard running, !startingOver, !stopping, !prompting, !registrationWarnings.isEmpty else { return }
        if embedded, NSApp.modalWindow != nil { return }
        prompting = true
        let warning = registrationWarnings.removeFirst()
        let recover = warning.event == "registration-key-gone"
        let alert = registrationWarningAlert(warning.message, key: warning.event != "registration-warning", recover: recover)
        if alert.runModal() == .alertSecondButtonReturn, recover, confirmSetAside(recover: true) { return }
        prompting = false
    }

    private func stopped(_ failure: SignerStartFailure, link: String?) {
        ready = false
        if embedded {
            walletWork.notify(queue: .main) { self.finishStopped(failure, link: link) }
        } else {
            finishStopped(failure, link: link)
        }
    }

    private func finishStopped(_ failure: SignerStartFailure, link: String?) {
        running = false
        registrationWarnings.removeAll()
        if stopping {
            stopping = false
            prompting = false
            let completions = lockCompletions
            lockCompletions.removeAll()
            completions.forEach { $0() }
        } else if startingOver {
            startingOver = false
            finishSetAside()
        } else {
            retry(failure, link: link)
        }
    }

    func start(_ link: String?) {
        guard !prompting else { return }
        prompting = true
        queuedLink = nil
        retryLink = link
        NSApp.activate(ignoringOtherApps: true)
        if running {
            let alert = NSAlert()
            alert.messageText = "This signer is already running"
            let state = profile()["profile"] as? String
            alert.informativeText = state == "vault" ? SignerStartFailure.protectedProfile.message
                : "This profile is unlocked. Quit to lock it, or start over if you intended to use a different profile."
            alert.addButton(withTitle: "OK")
            if state == "profile" { alert.addButton(withTitle: "Start over…") }
            if alert.runModal() == .alertSecondButtonReturn, confirmSetAside() { return }
            prompting = false
            return
        }
        let location = startupProfile()
        guard let state = location["profile"] as? String else {
            retry(location["error"] as? String == "data-folder-unavailable" ? .dataFolderUnavailable : .unexpected, link: link)
            return
        }
        if state == "fresh" {
            if embedded { finishWalletOperation(.pairingLinkNeeded); return }
            guard canSetUpWithTouchID() else { prompting = false; return }
            switch firstRunChoice() {
            case .alertSecondButtonReturn:
                beginRecovery()
                return
            case .alertFirstButtonReturn:
                if link == nil { retry(.pairingLinkNeeded, link: nil); return }
            default:
                retry(.cancelled, link: link)
                return
            }
        }
        loadConfiguration(link: link)
    }

    private func loadConfiguration(link: String?, approvedOrigin: String? = nil) {
        var launch: [String: Any] = ["args": args]
        if let link = link {
            launch["pairing_url"] = link
            // Validate the link locally before asking the member to fetch configuration.
            let reply = nativeQuery(loki_member_app_pairing_target, launch)
            guard let target = reply["target"] as? [String: Any], let origin = target["coordinator"] as? String,
                  let slot = (target["slot"] as? NSNumber)?.stringValue else {
                let different = (reply["error"] as? String)?.hasPrefix("this profile is already paired with ") == true
                retry(different ? .differentPairing : .invalidLink, link: link)
                return
            }
            if let approvedOrigin, origin != approvedOrigin { retry(.invalidLink, link: link); return }
            guard confirmCoordinator(origin, title: "Pair this device with slot \(slot)?") else {
                retry(.cancelled, link: link)
                return
            }
        }
        // A pairing link, or an unlock with nothing saved, asks the coordinator; keep the UI live.
        DispatchQueue.global(qos: .userInitiated).async {
            let reply = nativeQuery(loki_member_app_configuration, launch)
            DispatchQueue.main.async { self.confirm(link: link, launch: launch, reply: reply) }
        }
    }

    private func confirmCoordinator(_ origin: String, title: String) -> Bool {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = "Coordinator: \(origin)\n\nOnly continue if this is the coordinator you intended. LokiSigner then asks it for the signer configuration and shows it to you before anything is saved."
        alert.addButton(withTitle: "Continue")
        alert.addButton(withTitle: "Cancel")
        return runDecisionAlert(alert, escape: .alertSecondButtonReturn) == .alertFirstButtonReturn
    }

    private func configurationText(_ config: [String: Any]) -> String {
        let text = { (key: String) in config[key] as? String ?? "none" }
        let witnesses = (config["nonce_witnesses"] as? [String])?.joined(separator: "\n  ") ?? "none"
        return """
            Coordinator: \(text("coordinator"))
            Network: \(text("network"))
            frostd: \(text("frostd_url"))
            lightwalletd: \(text("lightwalletd_url"))
            Nonce witnesses:
              \(witnesses)

            The coordinator above chose these endpoints, except any you set with launch flags \
            (those apply to this launch only, and then nothing is saved).
            """
    }

    /// Shows the configuration before anything is saved; the member continues with exactly it.
    private func confirm(link: String?, launch: [String: Any], reply: [String: Any]) {
        guard let config = reply["config"] as? [String: Any] else {
            retry(.configuration, link: link)
            return
        }
        if embedded, config["network"] as? String != "testnet" { retry(.testnetOnly, link: link); return }
        let alert = NSAlert()
        let slot = (config["slot"] as? NSNumber)?.stringValue ?? "?"
        let endpoints = configurationText(config)
        if embedded, link != nil {
            alert.messageText = "Review signer configuration"
            alert.informativeText = "Check the network and endpoints before saving them to your local profile.\n\nMember slot: \(slot)\n\(endpoints)\nYour passphrase stays on this Mac."
        } else if link != nil {
            alert.messageText = "Pair this device with slot \(slot)?"
            alert.informativeText = "\(endpoints)\nCreate or unlock your local profile below. These values are saved once it unlocks."
        } else {
            alert.messageText = "Unlock your paired signer"
            alert.informativeText = embedded ? "\(endpoints)\nYour passphrase stays on this Mac."
                : "\(endpoints)\nFor a new device, cancel and open a pairing link from the wallet. Your passphrase stays in this app."
        }
        let password = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 420, height: 26))
        password.placeholderString = "Local profile passphrase"
        alert.accessoryView = password
        alert.addButton(withTitle: link == nil ? "Unlock" : "Pair")
        alert.addButton(withTitle: "Cancel")
        let answer: NSApplication.ModalResponse
        if link != nil {
            answer = runDecisionAlert(alert, escape: .alertSecondButtonReturn, field: password)
        } else {
            alert.window.initialFirstResponder = password
            NSApp.activate(ignoringOtherApps: true)
            answer = alert.runModal()
        }
        alert.window.endEditing(for: password)
        guard answer == .alertFirstButtonReturn else {
            password.stringValue = ""
            retry(.cancelled, link: link)
            return
        }
        guard !password.stringValue.isEmpty, !password.stringValue.contains("\0") else {
            password.stringValue = ""
            retry(.emptyPassphrase, link: link)
            return
        }
        var confirmed = launch
        confirmed["config"] = config
        if embedded { confirmed["embedded"] = true }
        guard let json = try? JSONSerialization.data(withJSONObject: confirmed), let request = String(data: json, encoding: .utf8) else {
            password.stringValue = ""
            retry(.unexpected, link: link)
            return
        }
        var secret = Array(password.stringValue.utf8CString)
        password.stringValue = ""
        running = true
        DispatchQueue.global(qos: .userInitiated).async {
            defer { _ = secret.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
            let code = request.withCString { request in
                secret.withUnsafeMutableBufferPointer { pass in loki_member_app_pair(request, pass.baseAddress!, nativeNotice, nativeApprove, nativeConfirmRoster, nativeConnect) }
            }
            DispatchQueue.main.async {
                let failure: SignerStartFailure
                switch code {
                case 3: failure = .unlock
                case 4: failure = .deviceKey
                case 5: failure = .registrationRefused
                case 6: failure = .registrationFailed
                case 7: failure = self.startupKeyFailure ?? .deviceKey
                case 8: failure = .registrationRosterUnavailable
                default: failure = .unexpected
                }
                self.startupKeyFailure = nil
                // A consumed pairing link cannot unlock again. Resume from the saved pin instead.
                self.stopped(failure, link: [3, 4, 7, 8].contains(code) ? link : nil)
            }
        }
    }

    private func beginRecovery() {
        let alert = NSAlert()
        alert.messageText = "Enter your original coordinator"
        alert.informativeText = "Use the HTTPS origin of the wallet that your old Mac was paired with."
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 420, height: 26))
        field.placeholderString = "https://wallet.example"
        alert.accessoryView = field
        alert.addButton(withTitle: "Continue")
        alert.addButton(withTitle: "Cancel")
        alert.window.initialFirstResponder = field
        guard alert.runModal() == .alertFirstButtonReturn else { retry(.cancelled, link: retryLink); return }
        let launch: [String: Any] = ["args": args, "restore_origin": field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)]
        let reply = nativeQuery(loki_member_app_pairing_target, launch)
        guard let target = reply["target"] as? [String: Any], let origin = target["coordinator"] as? String else {
            retry(.coordinatorOrigin, link: retryLink)
            return
        }
        guard confirmCoordinator(origin, title: "Restore with this coordinator?") else {
            retry(.cancelled, link: retryLink)
            return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let reply = nativeQuery(loki_member_app_configuration, launch)
            DispatchQueue.main.async { self.confirmRecovery(launch: launch, reply: reply) }
        }
    }

    private func confirmRecovery(launch: [String: Any], reply: [String: Any]) {
        guard let config = reply["config"] as? [String: Any] else {
            retry(.configuration, link: retryLink)
            return
        }
        if embedded, config["network"] as? String != "testnet" { retry(.testnetOnly, link: retryLink); return }
        let alert = NSAlert()
        alert.messageText = "Review the signer configuration"
        alert.informativeText = configurationText(config)
        alert.addButton(withTitle: "Continue")
        alert.addButton(withTitle: "Cancel")
        var confirmed = launch
        confirmed["config"] = config
        if embedded { confirmed["embedded"] = true }
        guard alert.runModal() == .alertFirstButtonReturn else { retry(.cancelled, link: retryLink); return }
        guard let json = try? JSONSerialization.data(withJSONObject: confirmed), let request = String(data: json, encoding: .utf8) else {
            retry(.unexpected, link: retryLink)
            return
        }
        let input: RecoveryInput
        switch restoreInput(newProfile: true) {
        case .failure(let failure): retry(failure, link: retryLink); return
        case .success(let value): input = value
        }
        running = true
        DispatchQueue.global(qos: .userInitiated).async {
            let error = request.withCString { request in
                input.file.withCString { file in
                    input.words.withUnsafeMutableBufferPointer { words in
                        input.pass.withUnsafeMutableBufferPointer { pass in
                            recoveryError(loki_member_app_restore_profile(request, words.baseAddress, words.count,
                                pass.baseAddress, pass.count, file, nativeNotice, nativeApprove, nativeConfirmRoster, nativeConnect))
                        }
                    }
                }
            }
            DispatchQueue.main.async {
                self.stopped(error ?? .unexpected, link: error == .restoredButStopped ? nil : self.retryLink)
            }
        }
    }

    @objc func restoreVault(_ sender: Any?) {
        guard !prompting else { return }
        guard running else {
            if profile()["profile"] as? String == "fresh" { start(queuedLink ?? retryLink) }
            else { retry(.unlockToRestore, link: nil) }
            return
        }
        prompting = true
        let input: RecoveryInput
        switch restoreInput(newProfile: false) {
        case .failure(let failure):
            if failure != .cancelled { showRecoveryResult(error: failure) }
            if embedded { finishWalletOperation(failure) } else { prompting = false }
            return
        case .success(let value): input = value
        }
        if embedded { walletWork.enter() }
        DispatchQueue.global(qos: .userInitiated).async {
            let error = input.file.withCString { file in
                input.words.withUnsafeMutableBufferPointer { words in
                    recoveryError(loki_member_app_restore_vault(words.baseAddress, words.count, file))
                }
            }
            DispatchQueue.main.async {
                defer { if self.embedded { self.walletWork.leave() } }
                if error == .wrongProfile {
                    let state = self.profile()["profile"] as? String
                    let alert = NSAlert()
                    alert.messageText = "Could not restore vault"
                    alert.informativeText = SignerStartFailure.wrongProfile.message
                    if state == "vault" { alert.informativeText += "\n\n" + SignerStartFailure.protectedProfile.message }
                    alert.addButton(withTitle: "OK")
                    if state == "profile" { alert.addButton(withTitle: "Start over…") }
                    self.retryLink = nil
                    if alert.runModal() == .alertSecondButtonReturn, self.confirmSetAside() { return }
                } else {
                    showRecoveryResult(error: error)
                }
                if self.embedded { self.finishWalletOperation(error) } else { self.prompting = false }
            }
        }
    }

    @objc func disconnectWalletTabs(_ sender: Any?) {
        loki_member_app_disconnect_wallet_tabs()
    }
}

func nativeSignerArguments(_ arguments: [String]) -> [String] {
    var args = arguments
    if !args.contains("--data") {
        let root = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("LokiSigner")
        args += ["--data", root.path]
    }
    if !args.contains("--port") { args += ["--port", "0"] }
    return args
}

func runNativeSigner(arguments: [String], link: String?) -> Never {
    let app = NSApplication.shared
    app.setActivationPolicy(.regular)
    let menu = NSMenu()
    let item = NSMenuItem()
    let actions = NSMenu()
    let delegate = NativeSigner(args: nativeSignerArguments(arguments), link: link)
    let vaultAddresses = VaultAddressesWindow()
    let showAddresses = actions.addItem(withTitle: "Vault addresses…", action: #selector(VaultAddressesWindow.show(_:)), keyEquivalent: "")
    showAddresses.target = vaultAddresses
    let restore = actions.addItem(withTitle: "Restore a vault…", action: #selector(NativeSigner.restoreVault(_:)), keyEquivalent: "")
    restore.target = delegate
    actions.addItem(.separator())
    let disconnect = actions.addItem(withTitle: "Disconnect all wallet tabs", action: #selector(NativeSigner.disconnectWalletTabs(_:)), keyEquivalent: "")
    disconnect.target = delegate
    actions.addItem(withTitle: "Quit and lock LokiSigner", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
    item.submenu = actions
    menu.addItem(item)
    app.mainMenu = menu
    app.delegate = delegate
    withExtendedLifetime((delegate, vaultAddresses)) { app.run() }
    exit(0)
}

/// `LokiSigner approve`: a real 2-of-3 DKG and payment whose quorum members each ask the
/// payment dialog above before signing. Exit 0 = signed after approval, 3 = refused.
final class ApprovalSelftest: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.activate(ignoringOtherApps: true)
        DispatchQueue.global(qos: .userInitiated).async {
            let rc = loki_signer_approval_selftest(nativeApprove)
            print(rc == 0 ? "APPROVAL SELFTEST PASS: payment signed only after native approval"
                : rc == 3 ? "APPROVAL SELFTEST REFUSED: the member refused; no signature share was released"
                : "APPROVAL SELFTEST FAILED (code \(rc))")
            fflush(stdout)
            exit(rc)
        }
    }
}

func runApprovalSelftest() -> Never {
    let app = NSApplication.shared
    app.setActivationPolicy(.regular)
    let delegate = ApprovalSelftest()
    app.delegate = delegate
    withExtendedLifetime(delegate) { app.run() }
    exit(0)
}
