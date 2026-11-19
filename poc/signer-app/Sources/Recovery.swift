import AppKit
import UniformTypeIdentifiers

enum SignerStartFailure: Error, Equatable {
    case cancelled, pairingLinkNeeded, invalidLink, differentPairing, configuration, coordinatorOrigin
    case emptyPassphrase, unlock, deviceKey, registrationRefused, registrationFailed, unexpected
    case missingRecoveryInput, missingRecoveryWords, invalidBackup, backupMismatch, wrongProfile
    case vaultExists, rosterUnavailable, rosterMismatch, restoredButStopped, unlockToRestore
    case notFresh, dataFolderUnavailable, protectedProfile, setAsideFailed

    var message: String {
        switch self {
        case .cancelled: return "You cancelled. Try again to continue setting up or unlocking LokiSigner."
        case .pairingLinkNeeded: return "Open a pairing link from the wallet, then try again."
        case .invalidLink: return "This pairing link isn’t valid. Get a new link from the wallet and open it in LokiSigner."
        case .differentPairing: return "This link is for a different coordinator or member slot. Unlock your existing profile or use a link for its slot."
        case .configuration: return "LokiSigner couldn’t load its settings. Check your connection and try again."
        case .coordinatorOrigin: return "Enter the original coordinator’s HTTPS address, without a page or path, and try again."
        case .emptyPassphrase: return "Enter your local profile passphrase and try again."
        case .unlock: return "LokiSigner couldn’t unlock this profile. Check your passphrase and try again."
        case .deviceKey: return "This Mac couldn’t use the device key LokiSigner needs to connect. Try again, or set aside the profile if it has no vaults."
        case .registrationRefused: return "The coordinator refused this pairing. Try unlocking again, or get a new pairing link from the wallet."
        case .registrationFailed: return "LokiSigner couldn’t finish connecting to the coordinator. Check your connection and try again."
        case .unexpected: return "LokiSigner couldn’t finish this step. Try again."
        case .missingRecoveryInput: return "Enter your recovery words and a new local passphrase, then try again."
        case .missingRecoveryWords: return "Enter your recovery words and try again."
        case .invalidBackup: return "Choose a valid LokiSigner recovery backup file and try again."
        case .backupMismatch: return "LokiSigner couldn’t restore this vault. Check the recovery words and backup, then try again."
        case .wrongProfile: return "These recovery words or this backup don’t match the unlocked profile. Check that they belong to this member and try again."
        case .vaultExists: return "This vault already has data in the profile. LokiSigner didn’t replace it. Choose a different backup."
        case .rosterUnavailable: return "LokiSigner couldn’t read the coordinator’s member list. Check the coordinator and your connection, then try again."
        case .rosterMismatch: return "The coordinator’s member list doesn’t show exactly one slot for this backup. Check that you entered the original coordinator and try again."
        case .restoredButStopped: return "Your vault was saved. Try unlocking again; you don’t need your recovery words."
        case .unlockToRestore: return "Unlock LokiSigner before restoring another vault."
        case .notFresh: return "This data folder is no longer ready for a first restore. If the profile has no vaults, set it aside and try again."
        case .dataFolderUnavailable: return "LokiSigner’s data folder points to a location this Mac can’t open. Reconnect the drive or fix the folder link, then try again."
        case .protectedProfile: return "This profile holds vault data that may include a share. LokiSigner won’t set it aside. To restore a different member, use another Mac or macOS account."
        case .setAsideFailed: return "LokiSigner couldn’t set aside this profile. Try again."
        }
    }
}

@_silgen_name("loki_member_app_restore_vault")
func loki_member_app_restore_vault(_ words: UnsafeMutablePointer<UInt8>?, _ count: Int,
    _ file: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?

@_silgen_name("loki_member_app_restore_profile")
func loki_member_app_restore_profile(_ launch: UnsafePointer<CChar>,
    _ words: UnsafeMutablePointer<UInt8>?, _ wordCount: Int,
    _ pass: UnsafeMutablePointer<UInt8>?, _ passCount: Int, _ file: UnsafePointer<CChar>,
    _ notify: @convention(c) (UnsafePointer<CChar>?, UnsafePointer<CChar>?) -> Void,
    _ approve: @convention(c) (UnsafePointer<CChar>?) -> Int32,
    _ confirmRoster: @convention(c) (UnsafePointer<CChar>?) -> Int32,
    _ connect: ConnectDecision) -> UnsafeMutablePointer<CChar>?

func firstRunChoice() -> NSApplication.ModalResponse {
    let alert = NSAlert()
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

func restoreInput(newProfile: Bool) -> Result<RecoveryInput, SignerStartFailure> {
    // Choose a file before collecting any secret, so the picker never shares a field editor with it.
    let picker = NSOpenPanel()
    picker.title = "Choose a LokiSigner recovery backup"
    picker.prompt = "Choose backup"
    picker.allowedContentTypes = [.json]
    guard picker.runModal() == .OK, let file = picker.url else { return .failure(.cancelled) }

    let alert = NSAlert()
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
    guard result == .alertFirstButtonReturn else { return .failure(.cancelled) }
    guard !words.stringValue.isEmpty, !newProfile || !pass.stringValue.isEmpty else {
        return .failure(newProfile ? .missingRecoveryInput : .missingRecoveryWords)
    }
    return .success(RecoveryInput(file: file.path, words: Array(words.stringValue.utf8), pass: Array(pass.stringValue.utf8)))
}

func recoveryError(_ reply: UnsafeMutablePointer<CChar>?) -> SignerStartFailure? {
    defer { loki_member_app_free(reply) }
    if let reply,
       let result = try? JSONSerialization.jsonObject(with: Data(String(cString: reply).utf8)) as? [String: Any] {
        if result["restored"] as? Bool == true { return nil }
        switch result["error"] as? String {
        case "Choose a valid LokiSigner recovery backup file (at most 256 KiB).": return .invalidBackup
        case "This backup or these recovery words do not match the unlocked LokiSigner profile.": return .wrongProfile
        case "This vault already has data in the profile. LokiSigner did not replace it.": return .vaultExists
        case "First-run recovery needs a new LokiSigner profile directory.": return .notFresh
        case "data-folder-unavailable": return .dataFolderUnavailable
        case "LokiSigner could not read the coordinator roster. Check the coordinator and try again.": return .rosterUnavailable
        case "The coordinator roster does not identify exactly one slot for this backup.": return .rosterMismatch
        case "Vault restored to this Mac, but LokiSigner could not start. Try unlocking again; your recovery words are not needed.": return .restoredButStopped
        case "Unlock LokiSigner before restoring a vault.": return .unlockToRestore
        case "LokiSigner could not restore this vault. Check the recovery words and backup, then try again.": return .backupMismatch
        default: break
        }
    }
    return .unexpected
}

func showRecoveryResult(error: SignerStartFailure?) {
    let alert = NSAlert()
    alert.messageText = error == nil ? "Vault restored" : "Could not restore vault"
    alert.informativeText = error?.message ?? "LokiSigner rebuilt your share on this Mac. Reopen your vault list in the wallet to see the restored vault."
    alert.addButton(withTitle: "OK")
    alert.runModal()
}
