import AppKit

@_silgen_name("loki_member_app_pair")
func loki_member_app_pair(_ launch: UnsafePointer<CChar>, _ pass: UnsafeMutablePointer<CChar>,
    _ notify: @convention(c) (UnsafePointer<CChar>?, UnsafePointer<CChar>?) -> Void) -> Int32

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
        let alert = NSAlert()
        if running || prompting {
            alert.messageText = "This signer is already running"
            alert.informativeText = "Quit to lock it before opening another pairing link."
            alert.runModal()
            return
        }
        prompting = true
        defer { prompting = false }
        // Rust validates the complete URL again before touching the coordinator.
        if let link = link {
            guard let parts = URLComponents(string: link), parts.scheme == "loki", parts.host == "pair",
                let origin = parts.queryItems?.first(where: { $0.name == "origin" })?.value,
                let slot = parts.queryItems?.first(where: { $0.name == "slot" })?.value else {
                alert.messageText = "Invalid pairing link"; alert.runModal(); return
            }
            alert.messageText = "Pair this device with slot \(slot)?"
            alert.informativeText = "Coordinator: \(origin)\nOnly continue if this is the coordinator you intended. Create or unlock your local profile below."
        } else {
            alert.messageText = "Unlock your paired signer"
            alert.informativeText = "For a new device, cancel and open a pairing link from the wallet. Your passphrase stays in this app."
        }
        let password = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 420, height: 26))
        password.placeholderString = "Local profile passphrase"
        alert.accessoryView = password
        alert.addButton(withTitle: link == nil ? "Unlock" : "Pair")
        alert.addButton(withTitle: "Cancel")
        alert.window.initialFirstResponder = password
        guard alert.runModal() == .alertFirstButtonReturn, !password.stringValue.isEmpty else { return }
        var launch: [String: Any] = ["args": args]
        if let link = link { launch["pairing_url"] = link }
        guard let json = try? JSONSerialization.data(withJSONObject: launch), let request = String(data: json, encoding: .utf8) else { return }
        var secret = Array(password.stringValue.utf8CString)
        password.stringValue = ""
        running = true
        DispatchQueue.global(qos: .userInitiated).async {
            defer { _ = secret.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
            _ = request.withCString { request in
                secret.withUnsafeMutableBufferPointer { pass in loki_member_app_pair(request, pass.baseAddress!, nativeNotice) }
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
    actions.addItem(withTitle: "Quit and lock LokiSigner", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
    item.submenu = actions
    menu.addItem(item)
    app.mainMenu = menu
    let delegate = NativeSigner(args: args, link: link)
    app.delegate = delegate
    withExtendedLifetime(delegate) { app.run() }
    exit(0)
}
