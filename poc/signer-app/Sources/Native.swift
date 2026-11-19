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
    defer { loki_member_app_free(reply) }
    guard let reply = reply,
          let parsed = try? JSONSerialization.jsonObject(with: Data(String(cString: reply).utf8)) as? [String: Any]
    else { return ["error": "invalid reply"] }
    return parsed
}

func retryAlert(_ failure: SignerStartFailure, profile: String?) -> NSAlert {
    let alert = NSAlert()
    alert.messageText = failure == .cancelled ? "LokiSigner paused" : "LokiSigner couldn’t continue"
    alert.informativeText = failure.message
    if profile == "vault", [.differentPairing, .notFresh, .wrongProfile, .registrationRefused].contains(failure) {
        alert.informativeText += "\n\n" + SignerStartFailure.protectedProfile.message
    }
    alert.addButton(withTitle: "Try again")
    alert.addButton(withTitle: "Quit")
    if profile == "profile" { alert.addButton(withTitle: "Start over…") }
    return alert
}

func setAsideAlert() -> NSAlert {
    let alert = NSAlert()
    alert.messageText = "Set aside this LokiSigner profile?"
    alert.informativeText = "LokiSigner will move the entire local data folder, including this profile’s identity and pairing settings, to a dated folder beside it. Nothing will be deleted. You can then pair a new signer or restore from recovery words."
    alert.addButton(withTitle: "Cancel")
    alert.addButton(withTitle: "Set aside and start over")
    return alert
}

func registrationWarningAlert(_ message: String) -> NSAlert {
    let alert = NSAlert()
    alert.messageText = "LokiSigner is running"
    alert.informativeText = message
    alert.addButton(withTitle: "OK")
    return alert
}

@_silgen_name("loki_signer_approval_selftest")
func loki_signer_approval_selftest(_ approve: @convention(c) (UnsafePointer<CChar>?) -> Int32) -> Int32

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
        alert.buttons[1].keyEquivalent = ""
        NSApp.activate(ignoringOtherApps: true)
        let timeout = Timer(timeInterval: approvalTimeout, repeats: false) { _ in NSApp.abortModal() }
        RunLoop.main.add(timeout, forMode: .modalPanel)
        approved = alert.runModal() == .alertSecondButtonReturn
        timeout.invalidate()
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
        // The dialog takes focus while the member may be typing elsewhere: Return, Space or any
        // other key answers nothing, and the member must click. Lay out first, because
        // NSAlert assigns its default button there.
        alert.layout()
        for button in alert.buttons {
            button.keyEquivalent = ""
            button.refusesFirstResponder = true
        }
        alert.window.defaultButtonCell = nil
        NSApp.activate(ignoringOtherApps: true)
        let timeout = Timer(timeInterval: rosterTimeout, repeats: false) { _ in NSApp.abortModal() }
        RunLoop.main.add(timeout, forMode: .modalPanel)
        switch alert.runModal() {
        case .alertSecondButtonReturn: answer = 1
        case .alertFirstButtonReturn: answer = 2
        default: answer = 0
        }
        timeout.invalidate()
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
    alert.layout()
    for button in alert.buttons {
        button.keyEquivalent = ""
        button.refusesFirstResponder = true
    }
    let window = alert.window
    window.defaultButtonCell = nil
    NSApp.activate(ignoringOtherApps: true)
    let timer = Timer(timeInterval: 0.1, repeats: true) { _ in
        if cancelled() && NSApp.modalWindow === window { NSApp.abortModal() }
    }
    RunLoop.main.add(timer, forMode: .modalPanel)
    defer { timer.invalidate() }
    return alert.runModal() == .alertSecondButtonReturn && !cancelled()
}

private func nativeNotice(_ kind: UnsafePointer<CChar>?, _ message: UnsafePointer<CChar>?) {
    guard let kind = kind, let message = message else { return }
    let event = String(cString: kind), text = String(cString: message)
    if event == "registration-warning" {
        // Rust supplies fixed copy here. Don't block its retry loop on an open dialog.
        DispatchQueue.main.async { (NSApp.delegate as? NativeSigner)?.warnRegistration(text) }
        return
    }
    // Synchronous delivery keeps recovery words on screen before registration continues.
    DispatchQueue.main.sync {
        let alert = NSAlert()
        if event == "ready" || event == "restore-ready" || event == "restore-pending" {
            alert.messageText = event == "ready" ? "LokiSigner is running" : "Vault restored"
            let connect = "On this Mac, choose Connect LokiSigner in the wallet. If the wallet only offers to paste a link, ask the coordinator to update it. Keep LokiSigner running to approve and sign."
            alert.informativeText = event == "restore-pending"
                ? "Your vault is saved on this Mac. LokiSigner will keep trying to reconnect, without your recovery words.\n\n\(connect)"
                : connect
            alert.addButton(withTitle: "Done")
            alert.runModal()
            (NSApp.delegate as? NativeSigner)?.didStart()
        } else if event == "recovery" {
            alert.messageText = "Save your recovery words privately"
            alert.informativeText = text
            alert.addButton(withTitle: "I saved these words")
            alert.runModal()
        }
    }
}

final class NativeSigner: NSObject, NSApplicationDelegate {
    private var running = false
    private var prompting = false {
        didSet {
            if !prompting, let message = registrationWarning {
                registrationWarning = nil
                DispatchQueue.main.async { self.warnRegistration(message) }
            }
        }
    }
    private var registrationWarning: String?
    private var opened = false
    private var cleanupNeeded = true
    private var retryLink: String?
    private var queuedLink: String?
    private var startingOver = false
    private let args: [String]
    private let initialLink: String?

    init(args: [String], link: String?) {
        self.args = args
        self.initialLink = link
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

    private func retry(_ failure: SignerStartFailure, link: String?) {
        prompting = true
        retryLink = link
        let alert = retryAlert(failure, profile: profile()["profile"] as? String)
        NSApp.activate(ignoringOtherApps: true)
        switch alert.runModal() {
        case .alertSecondButtonReturn:
            NSApp.terminate(nil)
        case .alertThirdButtonReturn:
            if confirmSetAside() { return }
        default: break
        }
        // Don't nest modal panels or keep a previous passphrase field alive on retry.
        DispatchQueue.main.async {
            self.prompting = false
            self.start(self.queuedLink ?? (failure == .differentPairing ? nil : self.retryLink))
        }
    }

    private func confirmSetAside() -> Bool {
        guard setAsideAlert().runModal() == .alertSecondButtonReturn else { return false }
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
        let reply = profile(2)
        if reply["profile"] as? String != "fresh" {
            retry(reply["error"] as? String == "vault" ? .protectedProfile : .setAsideFailed, link: retryLink)
        } else {
            let link = queuedLink ?? retryLink
            DispatchQueue.main.async {
                self.prompting = false
                self.start(link)
            }
        }
    }

    fileprivate func didStart() {
        prompting = false
        queuedLink = nil
    }

    fileprivate func warnRegistration(_ message: String) {
        guard running, !startingOver else { return }
        if prompting { registrationWarning = message; return }
        registrationWarningAlert(message).runModal()
    }

    private func stopped(_ failure: SignerStartFailure, link: String?) {
        running = false
        registrationWarning = nil
        if startingOver {
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
        let location = profile(cleanupNeeded ? 1 : 0)
        guard let state = location["profile"] as? String else {
            retry(location["error"] as? String == "data-folder-unavailable" ? .dataFolderUnavailable : .unexpected, link: link)
            return
        }
        cleanupNeeded = false
        if state == "fresh" {
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
        var launch: [String: Any] = ["args": args]
        if let link = link {
            launch["pairing_url"] = link
            // First confirm the coordinator. Rust checks the whole link without any network
            // request and returns its canonical origin and slot; LokiSigner contacts that
            // coordinator only after the member continues.
            let reply = nativeQuery(loki_member_app_pairing_target, launch)
            guard let target = reply["target"] as? [String: Any], let origin = target["coordinator"] as? String,
                  let slot = (target["slot"] as? NSNumber)?.stringValue else {
                let different = (reply["error"] as? String)?.hasPrefix("this profile is already paired with ") == true
                retry(different ? .differentPairing : .invalidLink, link: link)
                return
            }
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
        NSApp.activate(ignoringOtherApps: true)
        return alert.runModal() == .alertFirstButtonReturn
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
        let alert = NSAlert()
        let slot = (config["slot"] as? NSNumber)?.stringValue ?? "?"
        let endpoints = configurationText(config)
        if link != nil {
            alert.messageText = "Pair this device with slot \(slot)?"
            alert.informativeText = "\(endpoints)\nCreate or unlock your local profile below. These values are saved once it unlocks."
        } else {
            alert.messageText = "Unlock your paired signer"
            alert.informativeText = "\(endpoints)\nFor a new device, cancel and open a pairing link from the wallet. Your passphrase stays in this app."
        }
        let password = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 420, height: 26))
        password.placeholderString = "Local profile passphrase"
        alert.accessoryView = password
        alert.addButton(withTitle: link == nil ? "Unlock" : "Pair")
        alert.addButton(withTitle: "Cancel")
        alert.window.initialFirstResponder = password
        NSApp.activate(ignoringOtherApps: true)
        let answer = alert.runModal()
        alert.window.endEditing(for: password)
        guard answer == .alertFirstButtonReturn else {
            password.stringValue = ""
            retry(.cancelled, link: link)
            return
        }
        guard !password.stringValue.isEmpty else { retry(.emptyPassphrase, link: link); return }
        var confirmed = launch
        confirmed["config"] = config
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
            let failure: SignerStartFailure
            switch code {
            case 3: failure = .unlock
            case 4: failure = .deviceKey
            case 5: failure = .registrationRefused
            case 6: failure = .registrationFailed
            default: failure = .unexpected
            }
            // A consumed pairing link cannot unlock again. Resume from the saved pin instead.
            DispatchQueue.main.async { self.stopped(failure, link: [3, 4].contains(code) ? link : nil) }
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
        let alert = NSAlert()
        alert.messageText = "Review the signer configuration"
        alert.informativeText = configurationText(config)
        alert.addButton(withTitle: "Continue")
        alert.addButton(withTitle: "Cancel")
        var confirmed = launch
        confirmed["config"] = config
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
            prompting = false
            return
        case .success(let value): input = value
        }
        DispatchQueue.global(qos: .userInitiated).async {
            let error = input.file.withCString { file in
                input.words.withUnsafeMutableBufferPointer { words in
                    recoveryError(loki_member_app_restore_vault(words.baseAddress, words.count, file))
                }
            }
            DispatchQueue.main.async {
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
                self.prompting = false
            }
        }
    }

    @objc func disconnectWalletTabs(_ sender: Any?) {
        loki_member_app_disconnect_wallet_tabs()
    }
}

func runNativeSigner(arguments: [String], link: String?) -> Never {
    var args = arguments
    if !args.contains("--data") {
        let root = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("LokiSigner")
        args += ["--data", root.path]
    }
    if !args.contains("--port") { args += ["--port", "0"] }
    let app = NSApplication.shared
    app.setActivationPolicy(.regular)
    let menu = NSMenu()
    let item = NSMenuItem()
    let actions = NSMenu()
    let delegate = NativeSigner(args: args, link: link)
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
