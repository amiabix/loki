import AppKit

@_silgen_name("loki_member_app_pair")
func loki_member_app_pair(_ launch: UnsafePointer<CChar>, _ pass: UnsafeMutablePointer<CChar>,
    _ notify: @convention(c) (UnsafePointer<CChar>?, UnsafePointer<CChar>?) -> Void,
    _ approve: @convention(c) (UnsafePointer<CChar>?) -> Int32,
    _ confirmRoster: @convention(c) (UnsafePointer<CChar>?) -> Int32) -> Int32

@_silgen_name("loki_member_app_pairing_target")
func loki_member_app_pairing_target(_ launch: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?

@_silgen_name("loki_member_app_configuration")
func loki_member_app_configuration(_ launch: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?

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

private func showStartError(_ reply: [String: Any]) {
    let alert = LokiAlert()
    alert.messageText = "Signer could not start"
    alert.informativeText = reply["error"] as? String ?? "unknown error"
    alert.runModal()
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
        let alert = LokiAlert()
        alert.alertStyle = .warning
        alert.messageText = "Approve this payment?"
        let memo = text("memo").isEmpty ? "" : "\nMemo: \(text("memo"))"
        let fee = (request["fee_verified"] as? Bool) == true ? zec(request["fee_zat"]) : "\(zec(request["fee_zat"])) (NOT VERIFIED)"
        let member = (request["member"] as? NSNumber)?.stringValue ?? "?"
        alert.detailText = """
            Recipient: \(text("recipient"))
            Amount: \(zec(request["amount_zat"]))
            Fee: \(fee)
            Change back to the vault: \(zec(request["change_zat"]))
            Network: \(text("network")) (branch \(text("branch_id")))\(memo)

            Member \(member) — Vault: \(text("vault"))
            Payment: \(text("payment"))
            Attempt: \(text("attempt"))
            Signs: \(text("sighash"))
            """
        alert.informativeText = """
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
        let alert = LokiAlert()
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
        codeField.font = .monospacedSystemFont(ofSize: 20, weight: .semibold)
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
        // the alert assigns its default button there.
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

private func nativeNotice(_ kind: UnsafePointer<CChar>?, _ message: UnsafePointer<CChar>?) {
    guard let kind = kind, let message = message else { return }
    let event = String(cString: kind), text = String(cString: message)
    // Synchronous delivery keeps recovery words on screen before registration continues.
    DispatchQueue.main.sync {
        let alert = LokiAlert()
        if event == "ready" || event == "restore-ready" || event == "restore-pending" {
            alert.messageText = event == "ready" ? "Signer paired and running" : "Vault restored"
            alert.informativeText = event == "restore-pending"
                ? "Your vault is saved on this Mac. LokiSigner could not reconnect to the coordinator yet. It will retry now and when you next unlock, without your recovery words. Pair the wallet tab after it reconnects."
                : "Paste this private session link into your wallet tab. Keep LokiSigner running to approve and sign."
            let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 420, height: 26))
            field.stringValue = text
            field.isEditable = false
            field.isSelectable = true
            alert.accessoryView = field
            alert.addButton(withTitle: "Done")
            alert.addButton(withTitle: "Copy private link")
            if alert.runModal() == .alertSecondButtonReturn {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(text, forType: .string)
            }
        } else {
            alert.messageText = event == "recovery" ? "Save your recovery words privately" : "Signer could not start"
            if event == "recovery" { alert.detailText = text } else { alert.informativeText = text }
            alert.addButton(withTitle: event == "recovery" ? "I saved these words" : "OK")
            alert.runModal()
        }
    }
}

final class NativeSigner: NSObject, NSApplicationDelegate {
    private var running = false
    private var prompting = false
    private var opened = false
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
        if let url = urls.first { start(url.absoluteString) }
    }

    func start(_ link: String?) {
        if running || prompting {
            let alert = LokiAlert()
            alert.messageText = "This signer is already running"
            alert.informativeText = "Quit to lock it before opening another pairing link."
            alert.runModal()
            return
        }
        prompting = true
        NSApp.activate(ignoringOtherApps: true)
        if let idx = args.firstIndex(of: "--data"), args.indices.contains(idx + 1),
           !FileManager.default.fileExists(atPath: URL(fileURLWithPath: args[idx + 1]).appendingPathComponent("profile/profile.sealed").path) {
            switch firstRunChoice() {
            case .alertSecondButtonReturn:
                beginRecovery()
                return
            case .alertFirstButtonReturn:
                if link == nil {
                    prompting = false
                    showStartError(["error": "Open a new pairing link from the wallet to pair this signer."])
                    return
                }
            default:
                prompting = false
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
                prompting = false
                showStartError(reply)
                return
            }
            guard confirmCoordinator(origin, title: "Pair this device with slot \(slot)?") else { prompting = false; return }
        }
        // A pairing link, or an unlock with nothing saved, asks the coordinator; keep the UI live.
        DispatchQueue.global(qos: .userInitiated).async {
            let reply = nativeQuery(loki_member_app_configuration, launch)
            DispatchQueue.main.async { self.confirm(link: link, launch: launch, reply: reply) }
        }
    }

    private func confirmCoordinator(_ origin: String, title: String) -> Bool {
        let alert = LokiAlert()
        alert.messageText = title
        alert.detailText = "Coordinator: \(origin)"
        alert.informativeText = "Only continue if this is the coordinator you intended. LokiSigner then asks it for the signer configuration and shows it to you before anything is saved."
        alert.addButton(withTitle: "Continue")
        alert.addButton(withTitle: "Cancel")
        NSApp.activate(ignoringOtherApps: true)
        return alert.runModal() == .alertFirstButtonReturn
    }

    /// The endpoints, and the note on who chose them.
    private func configurationText(_ config: [String: Any]) -> (endpoints: String, note: String) {
        let text = { (key: String) in config[key] as? String ?? "none" }
        let witnesses = (config["nonce_witnesses"] as? [String])?.joined(separator: "\n  ") ?? "none"
        return ("""
            Coordinator: \(text("coordinator"))
            Network: \(text("network"))
            frostd: \(text("frostd_url"))
            lightwalletd: \(text("lightwalletd_url"))
            Nonce witnesses:
              \(witnesses)
            """, """
            The coordinator above chose these endpoints, except any you set with launch flags \
            (those apply to this launch only, and then nothing is saved).
            """)
    }

    /// Shows the configuration before anything is saved; the member continues with exactly it.
    private func confirm(link: String?, launch: [String: Any], reply: [String: Any]) {
        defer { prompting = false }
        guard let config = reply["config"] as? [String: Any] else { showStartError(reply); return }
        let alert = LokiAlert()
        let slot = (config["slot"] as? NSNumber)?.stringValue ?? "?"
        let (endpoints, note) = configurationText(config)
        alert.detailText = endpoints
        if link != nil {
            alert.messageText = "Pair this device with slot \(slot)?"
            alert.informativeText = "\(note)\nCreate or unlock your local profile below. These values are saved once it unlocks."
        } else {
            alert.messageText = "Unlock your paired signer"
            alert.informativeText = "\(note)\nFor a new device, cancel and open a pairing link from the wallet. Your passphrase stays in this app."
        }
        let password = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 420, height: 26))
        password.placeholderString = "Local profile passphrase"
        alert.accessoryView = password
        alert.addButton(withTitle: link == nil ? "Unlock" : "Pair")
        alert.addButton(withTitle: "Cancel")
        alert.window.initialFirstResponder = password
        NSApp.activate(ignoringOtherApps: true)
        guard alert.runModal() == .alertFirstButtonReturn, !password.stringValue.isEmpty else { return }
        var confirmed = launch
        confirmed["config"] = config
        guard let json = try? JSONSerialization.data(withJSONObject: confirmed), let request = String(data: json, encoding: .utf8) else { return }
        var secret = Array(password.stringValue.utf8CString)
        password.stringValue = ""
        running = true
        DispatchQueue.global(qos: .userInitiated).async {
            defer { _ = secret.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
            _ = request.withCString { request in
                secret.withUnsafeMutableBufferPointer { pass in loki_member_app_pair(request, pass.baseAddress!, nativeNotice, nativeApprove, nativeConfirmRoster) }
            }
            DispatchQueue.main.async { self.running = false }
        }
    }

    private func beginRecovery() {
        let alert = LokiAlert()
        alert.messageText = "Enter your original coordinator"
        alert.informativeText = "Use the HTTPS origin of the wallet that your old Mac was paired with."
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 420, height: 26))
        field.placeholderString = "https://wallet.example"
        alert.accessoryView = field
        alert.addButton(withTitle: "Continue")
        alert.addButton(withTitle: "Cancel")
        alert.window.initialFirstResponder = field
        guard alert.runModal() == .alertFirstButtonReturn else { prompting = false; return }
        let launch: [String: Any] = ["args": args, "restore_origin": field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)]
        let reply = nativeQuery(loki_member_app_pairing_target, launch)
        guard let target = reply["target"] as? [String: Any], let origin = target["coordinator"] as? String else {
            prompting = false
            showRecoveryResult(error: reply["error"] as? String ?? "Enter the original coordinator’s HTTPS origin.")
            return
        }
        guard confirmCoordinator(origin, title: "Restore with this coordinator?") else { prompting = false; return }
        DispatchQueue.global(qos: .userInitiated).async {
            let reply = nativeQuery(loki_member_app_configuration, launch)
            DispatchQueue.main.async { self.confirmRecovery(launch: launch, reply: reply) }
        }
    }

    private func confirmRecovery(launch: [String: Any], reply: [String: Any]) {
        defer { prompting = false }
        guard let config = reply["config"] as? [String: Any] else {
            showRecoveryResult(error: reply["error"] as? String ?? "LokiSigner could not read the coordinator configuration.")
            return
        }
        let alert = LokiAlert()
        alert.messageText = "Review the signer configuration"
        (alert.detailText, alert.informativeText) = configurationText(config)
        alert.addButton(withTitle: "Continue")
        alert.addButton(withTitle: "Cancel")
        var confirmed = launch
        confirmed["config"] = config
        guard alert.runModal() == .alertFirstButtonReturn,
              let json = try? JSONSerialization.data(withJSONObject: confirmed), let request = String(data: json, encoding: .utf8),
              let input = restoreInput(newProfile: true) else { return }
        running = true
        DispatchQueue.global(qos: .userInitiated).async {
            let error = request.withCString { request in
                input.file.withCString { file in
                    input.words.withUnsafeMutableBufferPointer { words in
                        input.pass.withUnsafeMutableBufferPointer { pass in
                            recoveryError(loki_member_app_restore_profile(request, words.baseAddress, words.count,
                                pass.baseAddress, pass.count, file, nativeNotice, nativeApprove, nativeConfirmRoster))
                        }
                    }
                }
            }
            DispatchQueue.main.async {
                if let error { showRecoveryResult(error: error) }
                self.running = false
            }
        }
    }

    @objc func restoreVault(_ sender: Any?) {
        guard !prompting else { return }
        guard running else { showRecoveryResult(error: "Unlock LokiSigner before restoring a vault."); return }
        prompting = true
        guard let input = restoreInput(newProfile: false) else { prompting = false; return }
        DispatchQueue.global(qos: .userInitiated).async {
            let error = input.file.withCString { file in
                input.words.withUnsafeMutableBufferPointer { words in
                    recoveryError(loki_member_app_restore_vault(words.baseAddress, words.count, file))
                }
            }
            DispatchQueue.main.async {
                showRecoveryResult(error: error)
                self.prompting = false
            }
        }
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
