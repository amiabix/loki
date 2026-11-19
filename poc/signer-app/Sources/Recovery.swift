import AppKit
import UniformTypeIdentifiers

@_silgen_name("loki_member_app_restore_vault")
func loki_member_app_restore_vault(_ words: UnsafeMutablePointer<UInt8>?, _ count: Int,
    _ file: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?

@_silgen_name("loki_member_app_restore_profile")
func loki_member_app_restore_profile(_ launch: UnsafePointer<CChar>,
    _ words: UnsafeMutablePointer<UInt8>?, _ wordCount: Int,
    _ pass: UnsafeMutablePointer<UInt8>?, _ passCount: Int, _ file: UnsafePointer<CChar>,
    _ notify: @convention(c) (UnsafePointer<CChar>?, UnsafePointer<CChar>?) -> Void,
    _ approve: @convention(c) (UnsafePointer<CChar>?) -> Int32,
    _ confirmRoster: @convention(c) (UnsafePointer<CChar>?) -> Int32) -> UnsafeMutablePointer<CChar>?

func firstRunChoice() -> NSApplication.ModalResponse {
    let alert = LokiAlert()
    alert.messageText = "Set up LokiSigner"
    alert.informativeText = "Pair a new signer, or restore your existing member using its 24 recovery words and an encrypted vault backup file."
    alert.addButton(withTitle: "Pair a new signer")
    alert.addButton(withTitle: "Restore from recovery words")
    alert.addButton(withTitle: "Cancel")
    return alert.runModal()
}

// After the main thread hands this off, only the restore worker accesses these buffers.
final class RecoveryInput: @unchecked Sendable {
    let file: String
    var words: [UInt8]
    var pass: [UInt8]

    init(file: String, words: [UInt8], pass: [UInt8]) {
        self.file = file
        self.words = words
        self.pass = pass
    }
}

func restoreInput(newProfile: Bool) -> RecoveryInput? {
    // Choose a file before collecting any secret, so the picker never shares a field editor with it.
    let picker = NSOpenPanel()
    picker.title = "Choose a LokiSigner recovery backup"
    picker.prompt = "Choose backup"
    picker.allowedContentTypes = [.json]
    guard picker.runModal() == .OK, let file = picker.url else { return nil }

    let alert = LokiAlert()
    alert.messageText = "Restore a vault"
    alert.informativeText = "Encrypted backup selected. Enter its 24 recovery words here, never on the wallet page."
    let fields = NSView(frame: NSRect(x: 0, y: 0, width: 400, height: newProfile ? 52 : 22))
    let words = NSSecureTextField(frame: NSRect(x: 0, y: newProfile ? 30 : 0, width: 400, height: 22))
    words.placeholderString = "24 recovery words, separated by spaces"
    words.setAccessibilityLabel("24 recovery words")
    let pass = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 400, height: 22))
    pass.placeholderString = "New local profile passphrase"
    pass.setAccessibilityLabel("New local profile passphrase")
    fields.addSubview(words)
    if newProfile { fields.addSubview(pass); words.nextKeyView = pass }
    alert.accessoryView = fields
    alert.addButton(withTitle: "Restore vault")
    alert.addButton(withTitle: "Cancel")
    alert.window.initialFirstResponder = words
    if let editor = alert.window.fieldEditor(true, for: words) as? NSTextView {
        editor.isContinuousSpellCheckingEnabled = false
        editor.isGrammarCheckingEnabled = false
        editor.isAutomaticSpellingCorrectionEnabled = false
        editor.isAutomaticTextReplacementEnabled = false
        editor.allowsUndo = false
    }
    let result = alert.runModal()
    defer {
        alert.window.endEditing(for: words)
        alert.window.endEditing(for: pass)
        words.stringValue = ""
        pass.stringValue = ""
    }
    guard result == .alertFirstButtonReturn else { return nil }
    guard !words.stringValue.isEmpty, !newProfile || !pass.stringValue.isEmpty else {
        words.stringValue = ""
        pass.stringValue = ""
        showRecoveryResult(error: newProfile ? "Enter your recovery words and a new local passphrase." : "Enter your recovery words.")
        return nil
    }
    return RecoveryInput(file: file.path, words: Array(words.stringValue.utf8), pass: Array(pass.stringValue.utf8))
}

func recoveryError(_ reply: UnsafeMutablePointer<CChar>?) -> String? {
    defer { loki_member_app_free(reply) }
    if let reply,
       let result = try? JSONSerialization.jsonObject(with: Data(String(cString: reply).utf8)) as? [String: Any] {
        if result["restored"] as? Bool == true { return nil }
        if let error = result["error"] as? String { return error }
    }
    return "LokiSigner could not restore this vault."
}

func showRecoveryResult(error: String?) {
    let alert = LokiAlert()
    alert.alertStyle = error == nil ? .informational : .critical
    alert.messageText = error == nil ? "Vault restored" : "Could not restore vault"
    alert.informativeText = error ?? "LokiSigner rebuilt your share on this Mac. Reopen your vault list in the wallet to see the restored vault."
    alert.addButton(withTitle: "OK")
    alert.runModal()
}
