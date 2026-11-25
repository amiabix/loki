import AppKit
import LocalAuthentication
import UniformTypeIdentifiers

enum SignerStartFailure: Error, Equatable {
    case cancelled, pairingLinkNeeded, invalidLink, differentPairing, configuration, coordinatorOrigin
    case savedEndpointsRefreshFailed, witnessesNotSaved, witnessesSaveUncertain
    case invalidProfileName, emptyPassphrase, unlock, deviceKey, registrationRefused, registrationFailed, unexpected
    case missingRecoveryInput, missingRecoveryWords, invalidBackup, backupMismatch, badBackupFingerprint, wrongProfile
    case vaultExists, rosterUnavailable, rosterMismatch, restoredButStopped, unlockToRestore
    case notFresh, dataFolderUnavailable, protectedProfile, setAsideFailed
    case key(String), keyGone(String), registrationRosterUnavailable, testnetOnly
    case registrationExpired, pairingRefused(String)

    static func renewalRefusal(_ code: Int32) -> String {
        switch code {
        case 15: return "Your Loki server is limiting new connections right now. Try again later."
        case 16: return "Your Loki server has no free member spot right now. Try again later, or ask whoever runs it."
        case 17: return "Another member already took this spot. Remove this profile and connect again with your Loki server address."
        case 20: return "Your Loki server is holding this member spot right now. Wait two minutes for the hold to end, then connect again with your Loki server address. This profile can still finish."
        case 18: return "Loki couldn’t reach your Loki server to renew this Mac’s hold. Check your internet connection, then connect again with your Loki server address."
        default: return "Your Loki server didn’t renew this Mac’s hold. Try again, or ask whoever runs it."
        }
    }

    var keyIsGone: Bool {
        if case .keyGone = self { return true }
        return false
    }

    var message: String {
        switch self {
        case .cancelled: return "You cancelled. Try again to keep setting up or unlocking Loki."
        case .pairingLinkNeeded: return "Enter your Loki server address, or open a connection link from the wallet, then try again."
        case .invalidLink: return "This connection link isn’t valid. Get a new link from the wallet and open it in Loki."
        case .differentPairing: return "This link is for a different Loki server or member. Unlock your existing profile, or use a link for that member."
        case .configuration: return "Loki couldn’t load its settings. Check your internet connection and try again."
        case .witnessesSaveUncertain: return "Loki saved the signing safety servers, but couldn’t confirm the save finished, so it didn’t start and signed nothing. The next unlock will most likely use those servers. If Loki asks about them again, review them again."
        case .witnessesNotSaved: return "Loki couldn’t save the signing safety servers for this profile, so it didn’t start and signed nothing. If you approved new ones, they did not take effect. Check that the profile folder can be written to, then try again."
        case .testnetOnly: return "Loki only works on testnet. This Loki server isn’t set up for testnet."
        case .savedEndpointsRefreshFailed: return "A saved server address uses a format Loki no longer supports, and Loki couldn’t load new settings from your Loki server. Check that you can reach the server, or ask whoever runs it for help, then try again."
        case .coordinatorOrigin: return "Enter your original Loki server address, without a page or path, and try again."
        case .invalidProfileName: return "Choose a short, single-line profile name without invisible formatting characters, or leave it blank to use Member."
        case .emptyPassphrase: return "Enter your local profile passphrase and try again."
        case .unlock: return "Loki couldn’t unlock this profile. Check your passphrase and try again."
        case .deviceKey: return "This Mac couldn’t use the key Loki needs to connect. Try again, or set this profile aside if it has no vaults."
        case .registrationRefused: return "Your Loki server refused to add this Mac. Enter the server address to try the same spot again. If another member has taken that spot, remove this profile and connect again."
        case .registrationExpired: return "Time ran out before this Mac finished joining. Enter your Loki server address again. Loki asks for the same spot."
        case .pairingRefused(let message): return message
        case .registrationFailed: return "Loki couldn’t finish connecting to your Loki server. Check your internet connection and try again."
        case .registrationRosterUnavailable: return "Loki couldn’t reach your Loki server. Check your internet connection, then try again."
        case .key(let message), .keyGone(let message): return message
        case .unexpected: return "Loki couldn’t finish this step. Try again."
        case .missingRecoveryInput: return "Enter your recovery words and a new local passphrase, then try again."
        case .missingRecoveryWords: return "Enter your recovery words and try again."
        case .invalidBackup: return "Choose a valid Loki backup file and try again."
        case .backupMismatch: return "Loki couldn’t restore this vault. Check your recovery words and backup file, then try again."
        case .badBackupFingerprint: return "Enter the matching 64-character backup fingerprint you saved from your original Mac or a trusted offline copy. Don’t use a fingerprint that came with an untrusted file."
        case .wrongProfile: return "These recovery words or this backup don’t match the unlocked profile. Check that they belong to this member and try again."
        case .vaultExists: return "This vault already has data in the profile. Loki didn’t replace it. Choose a different backup."
        case .rosterUnavailable: return "Loki couldn’t read your Loki server’s member list. Check the server address and your internet connection, then try again."
        case .rosterMismatch: return "Your Loki server’s member list doesn’t match this backup to exactly one member. Check that you entered your original Loki server and try again."
        case .restoredButStopped: return "Your vault was saved. Try unlocking again; you don’t need your recovery words."
        case .unlockToRestore: return "Unlock Loki before restoring another vault."
        case .notFresh: return "This data folder is no longer ready for a first restore. If the profile has no vaults, set it aside and try again."
        case .dataFolderUnavailable: return "Loki’s data folder points to a location this Mac can’t open. Reconnect the drive or fix the folder link, then try again."
        case .protectedProfile: return "This profile holds vault data that may include your part of a vault key. Loki won’t set it aside. To restore a different member, use another Mac or macOS account."
        case .setAsideFailed: return "Loki couldn’t set aside this profile. Try again."
        }
    }
}

@_silgen_name("loki_member_app_restore_vault")
func loki_member_app_restore_vault(_ words: UnsafeMutablePointer<UInt8>?, _ count: Int,
    _ file: UnsafePointer<CChar>, _ fingerprint: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?

@_silgen_name("loki_member_app_restore_profile")
func loki_member_app_restore_profile(_ launch: UnsafePointer<CChar>,
    _ words: UnsafeMutablePointer<UInt8>?, _ wordCount: Int,
    _ pass: UnsafeMutablePointer<UInt8>?, _ passCount: Int, _ file: UnsafePointer<CChar>,
    _ fingerprint: UnsafePointer<CChar>,
    _ notify: NativeNotice,
    _ approve: ApprovalDecision,
    _ confirmRoster: @convention(c) (UnsafePointer<CChar>?) -> Int32,
    _ connect: ConnectDecision) -> UnsafeMutablePointer<CChar>?

func touchIDSetupAlert(_ error: NSError?) -> NSAlert {
    let code = error.flatMap { $0.domain == LAError.errorDomain ? LAError.Code(rawValue: $0.code) : nil }
    let alert = NSAlert()
    alert.alertStyle = .warning
    if code == .passcodeNotSet {
        alert.messageText = "This Mac account has no login password"
        alert.informativeText = "Set one in System Settings, then try again."
    } else {
        alert.messageText = "Touch ID or your Mac password cannot be used right now"
        alert.informativeText = "Unlock your Mac and try again in Loki."
    }
    alert.addButton(withTitle: "OK")
    return alert
}

private func touchIDSetupAlertIfNeeded() -> NSAlert? {
    var error: NSError?
    let context = LAContext()
    guard !context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else { return nil }
    return touchIDSetupAlert(error)
}

func touchIDSetupFailure() -> SignerStartFailure? {
    guard let alert = touchIDSetupAlertIfNeeded() else { return nil }
    return .key("\(alert.messageText)\n\n\(alert.informativeText)")
}

func canSetUpWithTouchID() -> Bool {
    guard let alert = touchIDSetupAlertIfNeeded() else { return true }
    alert.runModal()
    return false
}

func firstRunChoice() -> NSApplication.ModalResponse {
    let alert = NSAlert()
    alert.messageText = "Set up LokiSigner"
    alert.informativeText = """
        Pair a new signer, or restore your existing member using its 24 recovery words and an encrypted vault backup file.

        LokiSigner unlocks with Touch ID or your Mac password. If this Mac’s signer keys are lost, you’ll need your recovery words and the encrypted backup file downloaded from the wallet.
        """
    alert.addButton(withTitle: "Pair a new signer")
    alert.addButton(withTitle: "Restore from recovery words")
    alert.addButton(withTitle: "Cancel")
    return alert.runModal()
}

final class RecoveryInput: @unchecked Sendable {
    let file: String
    let fingerprint: String
    var words: [UInt8]
    var pass: [UInt8]

    init(file: String, fingerprint: String, words: [UInt8], pass: [UInt8]) {
        self.file = file
        self.fingerprint = fingerprint
        self.words = words
        self.pass = pass
    }
}

private func recoveryBackupPicker() -> NSOpenPanel {
    let picker = NSOpenPanel()
    picker.title = "Choose your Loki backup file"
    picker.prompt = "Choose backup"
    picker.allowedContentTypes = [.json]
    return picker
}

private struct RecoveryPrompt {
    let fingerprint: NSTextField
    let words: NSSecureTextField
    let pass: NSSecureTextField
    private let newProfile: Bool

    init(newProfile: Bool) {
        self.newProfile = newProfile
        fingerprint = NSTextField(frame: NSRect(x: 0, y: newProfile ? 60 : 30, width: 400, height: 22))
        fingerprint.placeholderString = "Backup fingerprint you saved separately (64 characters)"
        fingerprint.setAccessibilityLabel("Backup fingerprint you saved separately")
        words = NSSecureTextField(frame: NSRect(x: 0, y: newProfile ? 30 : 0, width: 400, height: 22))
        words.placeholderString = "24 recovery words, separated by spaces"
        words.setAccessibilityLabel("24 recovery words")
        pass = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 400, height: 22))
        pass.placeholderString = "New local profile passphrase"
        pass.setAccessibilityLabel("New local profile passphrase")
    }

    var fields: [NSTextField] { newProfile ? [fingerprint, words, pass] : [fingerprint, words] }

    func standaloneAlert() -> NSAlert {
        let alert = NSAlert()
        alert.messageText = "Restore a vault"
        alert.informativeText = "Enter the SHA-256 fingerprint you saved from your original signer or a known-good offline copy, not one supplied with this file. Enter your recovery words here, never on the wallet page."
        let view = NSView(frame: NSRect(x: 0, y: 0, width: 400, height: newProfile ? 82 : 52))
        view.addSubview(fingerprint)
        view.addSubview(words)
        fingerprint.nextKeyView = words
        if newProfile { view.addSubview(pass); words.nextKeyView = pass }
        alert.accessoryView = view
        alert.addButton(withTitle: "Restore vault")
        alert.addButton(withTitle: "Cancel")
        return alert
    }

    func review() -> SignerReview {
        let r = SignerReview.self
        let entry = r.field("Backup fingerprint · the one you saved separately", fingerprint) + r.field("24 recovery words", words)
            + (newProfile ? r.field("New local profile passphrase", pass) : [])
        return SignerReview(section: newProfile ? "Recovery · new profile" : "Recovery · unlocked profile",
            title: newProfile ? "Restore Loki on this Mac" : "Restore another vault",
            intro: "Use the backup file and recovery words for this member.", content: [
                r.card("Encrypted backup file", [r.label("Backup selected", weight: .semibold),
                    r.label("You chose it with the macOS file picker. Its contents stay on this Mac.", tone: r.muted)]),
                r.card("Private entry on this Mac", entry + [
                    r.label("Use the fingerprint you saved from your original Mac or a trusted offline copy. Never use one that came with this file.", tone: r.muted),
                    r.label("Existing vault data will not be overwritten.", tone: r.muted)]),
            ], hint: newProfile ? "Your recovery words stay in Loki on this Mac." : "Your unlocked profile is kept.",
            actions: [newProfile ? "Restore" : "Restore vault", "Cancel"], primary: 0)
    }

    func input(_ response: NSApplication.ModalResponse, file: URL) -> Result<RecoveryInput, SignerStartFailure> {
        guard response == .alertFirstButtonReturn else { return .failure(.cancelled) }
        let anchor = fingerprint.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard anchor.utf8.count == 64, anchor.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }) else {
            return .failure(.badBackupFingerprint)
        }
        guard !words.stringValue.isEmpty, !newProfile || !pass.stringValue.isEmpty else {
            return .failure(newProfile ? .missingRecoveryInput : .missingRecoveryWords)
        }
        return .success(RecoveryInput(file: file.path, fingerprint: anchor, words: Array(words.stringValue.utf8), pass: Array(pass.stringValue.utf8)))
    }

    func clear() {
        fingerprint.stringValue = ""
        words.stringValue = ""
        pass.stringValue = ""
    }
}

func restoreInput(newProfile: Bool) -> Result<RecoveryInput, SignerStartFailure> {
    guard newProfile || canSetUpWithTouchID() else { return .failure(.cancelled) }
    let picker = recoveryBackupPicker()
    guard picker.runModal() == .OK, let file = picker.url else { return .failure(.cancelled) }

    let prompt = RecoveryPrompt(newProfile: newProfile)
    let alert = prompt.standaloneAlert()
    let words = prompt.words
    alert.window.initialFirstResponder = prompt.fingerprint
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
        alert.window.endEditing(for: prompt.pass)
        prompt.clear()
    }
    return prompt.input(result, file: file)
}

@MainActor
func restoreInput(newProfile: Bool, signer: NativeSigner, complete: @escaping (Result<RecoveryInput, SignerStartFailure>) -> Void) {
    if !newProfile, let failure = touchIDSetupFailure() {
        complete(.failure(failure))
        return
    }
    let picker = recoveryBackupPicker()
    picker.begin { response in
        guard response == .OK, let file = picker.url else { complete(.failure(.cancelled)); return }

        let prompt = RecoveryPrompt(newProfile: newProfile)
        signer.presentPrompt(prompt.review(), fields: prompt.fields) { response in
            let input = prompt.input(response, file: file)
            prompt.clear()
            complete(input)
        }
    }
}

func recoveryError(_ reply: UnsafeMutablePointer<CChar>?) -> SignerStartFailure? {
    defer { loki_member_app_free(reply) }
    if let reply,
       let result = try? JSONSerialization.jsonObject(with: Data(String(cString: reply).utf8)) as? [String: Any] {
        if result["restored"] as? Bool == true { return nil }
        switch result["error"] as? String {
        case "key-error":
            if let message = result["key_error"] as? String { return .key(message) }
        case "invalid-backup": return .invalidBackup
        case "backup-fingerprint-mismatch": return .badBackupFingerprint
        case "wrong-profile": return .wrongProfile
        case "vault-exists": return .vaultExists
        case "profile-not-fresh": return .notFresh
        case "data-folder-unavailable": return .dataFolderUnavailable
        case "roster-unavailable": return .rosterUnavailable
        case "roster-mismatch": return .rosterMismatch
        case "restored-but-stopped": return .restoredButStopped
        case "profile-locked": return .unlockToRestore
        case "restore-refused": return .backupMismatch
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
