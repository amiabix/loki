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
    let alert = NSAlert()
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

/// One line of another party's text, shown inside its own box and never as the app's wording.
/// Rust already replaced control, invisible, bidi and line-breaking characters; this replaces
/// any that still arrive, so the box holds one line in reading order.
private func untrustedLine(_ text: String) -> NSTextField {
    let hidden: Set<Unicode.GeneralCategory> = [.control, .format, .lineSeparator, .paragraphSeparator]
    let line = String(String.UnicodeScalarView(text.unicodeScalars.map {
        hidden.contains($0.properties.generalCategory) ? "\u{FFFD}" : $0
    }))
    let field = NSTextField(labelWithString: line)
    field.isBordered = true
    field.drawsBackground = true
    field.backgroundColor = .textBackgroundColor
    field.usesSingleLineMode = true
    field.cell?.wraps = false
    field.lineBreakMode = .byTruncatingTail
    field.isSelectable = true
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
        let nameLabel = NSTextField(labelWithString: "Vault name, as the vault creator wrote it:")
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
        alert.buttons[1].keyEquivalent = ""
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
        let alert = NSAlert()
        alert.messageText = event == "recovery" ? "Save your recovery words privately" : event == "ready" ? "Signer paired and running" : "Signer could not start"
        if event == "ready" {
            alert.informativeText = "Paste this private session link into your wallet tab. Keep LokiSigner running to approve and sign."
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
            alert.informativeText = text
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
            let alert = NSAlert()
            alert.messageText = "This signer is already running"
            alert.informativeText = "Quit to lock it before opening another pairing link."
            alert.runModal()
            return
        }
        prompting = true
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
            let alert = NSAlert()
            alert.messageText = "Pair this device with slot \(slot)?"
            alert.informativeText = "Coordinator: \(origin)\n\nOnly continue if this is the coordinator you intended. LokiSigner then asks it for the signer configuration and shows it to you before anything is saved."
            alert.addButton(withTitle: "Continue")
            alert.addButton(withTitle: "Cancel")
            NSApp.activate(ignoringOtherApps: true)
            guard alert.runModal() == .alertFirstButtonReturn else { prompting = false; return }
        }
        // A pairing link, or an unlock with nothing saved, asks the coordinator; keep the UI live.
        DispatchQueue.global(qos: .userInitiated).async {
            let reply = nativeQuery(loki_member_app_configuration, launch)
            DispatchQueue.main.async { self.confirm(link: link, launch: launch, reply: reply) }
        }
    }

    /// Shows the configuration before anything is saved; the member continues with exactly it.
    private func confirm(link: String?, launch: [String: Any], reply: [String: Any]) {
        defer { prompting = false }
        guard let config = reply["config"] as? [String: Any] else { showStartError(reply); return }
        let alert = NSAlert()
        let slot = (config["slot"] as? NSNumber)?.stringValue ?? "?"
        let text = { (key: String) in config[key] as? String ?? "none" }
        let witnesses = (config["nonce_witnesses"] as? [String])?.joined(separator: "\n  ") ?? "none"
        let endpoints = """
            Coordinator: \(text("coordinator"))
            Network: \(text("network"))
            frostd: \(text("frostd_url"))
            lightwalletd: \(text("lightwalletd_url"))
            Nonce witnesses:
              \(witnesses)

            The coordinator above chose these endpoints, except any you set with launch flags \
            (those apply to this launch only, and then nothing is saved).
            """
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
    let vaultAddresses = VaultAddressesWindow()
    let showAddresses = actions.addItem(withTitle: "Vault addresses…", action: #selector(VaultAddressesWindow.show(_:)), keyEquivalent: "")
    showAddresses.target = vaultAddresses
    actions.addItem(.separator())
    actions.addItem(withTitle: "Quit and lock LokiSigner", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
    item.submenu = actions
    menu.addItem(item)
    app.mainMenu = menu
    let delegate = NativeSigner(args: args, link: link)
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
