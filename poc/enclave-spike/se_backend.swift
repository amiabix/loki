import Foundation
import LocalAuthentication
import Security

// C-ABI Secure Enclave backend for loki's `SecureElement` trait
// (poc/src/signer/secure_element.rs). The Enclave is P-256 only, so it holds the KEK and
// wraps/unwraps the per-share DEK via ECIES (X9.63 KDF + AES-GCM); the FROST share itself
// never enters the Enclave.
//
// Two key lifetimes behind the SAME wrap/unwrap surface:
//   - EPHEMERAL  (se_open_ephemeral): kSecAttrIsPermanent=false, no keychain, no signing
//     identity needed. Works offline, unsigned, today — this is what the FFI verifier runs.
//   - PERSISTENT (se_open_persistent): kSecAttrIsPermanent=true + kSecAttrApplicationTag,
//     biometric access control (.biometryCurrentSet | .privateKeyUsage). Needs the binary
//     signed with an Apple Team ID (free personal team is enough); unsigned it returns
//     errSecMissingEntitlement (-34018). Gated here, not reachable on this unsigned build.
//
// Error codes returned to Rust (negative = failure, >=0 = byte count written):
//   -1 no key handle          -2 ECIES encrypt failed      -3 output buffer too small
//   -4 ECIES decrypt failed   -5 key create failed         -6 key load/not-found
//   -7 access-control build    -8 unknown handle           -9 ECDSA sign failed
//   -10 public-key export failed    -11 biometric authentication cancelled or failed

private let algo = SecKeyAlgorithm.eciesEncryptionCofactorX963SHA256AESGCM
// ECDSA over SHA-256 of the message, ASN.1/DER (X9.62) output — the device login-challenge
// signature. The same Enclave key signs and wraps; no usage flag restricts it.
private let sigAlgo = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256

// Opaque handle table: Rust holds a u64, Swift owns the SecKey. Avoids leaking SecKey
// pointers across the FFI and lets one process hold several elements (tests do).
private var table: [UInt64: SecKey] = [:]
private var nextHandle: UInt64 = 1
private let lock = NSLock()

private func store(_ k: SecKey) -> UInt64 {
    lock.lock(); defer { lock.unlock() }
    let h = nextHandle; nextHandle += 1; table[h] = k; return h
}
private func fetch(_ h: UInt64) -> SecKey? {
    lock.lock(); defer { lock.unlock() }
    return table[h]
}

// MARK: - Ephemeral key (unsigned-safe)

@_cdecl("se_open_ephemeral")
public func se_open_ephemeral(_ outHandle: UnsafeMutablePointer<UInt64>) -> Int {
    guard let ac = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage], nil
    ) else { return -7 }
    let attrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: false,
            kSecAttrAccessControl as String: ac,
        ],
    ]
    guard let k = SecKeyCreateRandomKey(attrs as CFDictionary, nil) else { return -5 }
    outHandle.pointee = store(k)
    return 0
}

// MARK: - Persistent + biometric key (REQUIRES a signed binary — gated, not run unsigned)

// Opens the persistent Enclave KEK identified by `tag`, creating it on first use. The
// access control adds `.biometryCurrentSet` so `unwrap_dek` prompts Face/Touch ID and is
// invalidated if the enrolled biometrics change. Unsigned, SecKeyCreateRandomKey here
// returns nil (errSecMissingEntitlement -34018); the handle is never produced.
@_cdecl("se_open_persistent")
public func se_open_persistent(_ tagPtr: UnsafePointer<UInt8>, _ tagLen: Int,
                               _ outHandle: UnsafeMutablePointer<UInt64>) -> Int {
    let tag = Data(bytes: tagPtr, count: tagLen)
    // Try to load an existing key by tag first.
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: tag,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecUseDataProtectionKeychain as String: true,
        kSecReturnRef as String: true,
    ]
    var out: CFTypeRef?
    if SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess, let r = out {
        outHandle.pointee = store(r as! SecKey)
        return 0
    }
    // Not found: create and persist it, biometric-gated.
    guard let ac = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.biometryCurrentSet, .privateKeyUsage], nil
    ) else { return -7 }
    let attrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecUseDataProtectionKeychain as String: true,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: tag,
            kSecAttrAccessControl as String: ac,
        ],
    ]
    guard let k = SecKeyCreateRandomKey(attrs as CFDictionary, nil) else { return -5 }
    outHandle.pointee = store(k)
    return 0
}

// MARK: - wrap / unwrap (identical for both lifetimes)

@_cdecl("se_wrap")
public func se_wrap(_ handle: UInt64,
                    _ dek: UnsafePointer<UInt8>, _ dekLen: Int,
                    _ out: UnsafeMutablePointer<UInt8>, _ outCap: Int) -> Int {
    guard let k = fetch(handle) else { return -8 }
    guard let pub = SecKeyCopyPublicKey(k) else { return -1 }
    let data = Data(bytes: dek, count: dekLen)
    guard let ct = SecKeyCreateEncryptedData(pub, algo, data as CFData, nil) as Data? else { return -2 }
    if ct.count > outCap { return -3 }
    ct.copyBytes(to: out, count: ct.count)
    return ct.count
}

@_cdecl("se_unwrap")
public func se_unwrap(_ handle: UInt64,
                      _ ct: UnsafePointer<UInt8>, _ ctLen: Int,
                      _ out: UnsafeMutablePointer<UInt8>, _ outCap: Int) -> Int {
    guard let k = fetch(handle) else { return -8 }
    let data = Data(bytes: ct, count: ctLen)
    // On a persistent biometric key this call triggers the Face/Touch ID prompt; the
    // private op runs inside the Secure Enclave and only the plaintext DEK comes back.
    var failure: Unmanaged<CFError>?
    guard let pt = SecKeyCreateDecryptedData(k, algo, data as CFData, &failure) as Data? else {
        var error = failure.map { $0.takeRetainedValue() as Error as NSError }
        while let current = error {
            if current.domain == LAError.errorDomain ||
                (current.domain == NSOSStatusErrorDomain &&
                    [errSecUserCanceled, errSecAuthFailed, errSecInteractionNotAllowed].map(Int.init).contains(current.code)) {
                return -11
            }
            error = current.userInfo[NSUnderlyingErrorKey] as? NSError
        }
        return -4
    }
    if pt.count > outCap { return -3 }
    pt.copyBytes(to: out, count: pt.count)
    return pt.count
}

// MARK: - device login key (same Enclave key, ECDSA path)

// Sign `msg` with the Enclave key (ECDSA/SHA-256, DER). On a persistent biometric key this
// prompts Face/Touch ID — proof of user presence for a login challenge. The private op runs
// inside the Secure Enclave; only the signature comes back.
@_cdecl("se_sign")
public func se_sign(_ handle: UInt64,
                    _ msg: UnsafePointer<UInt8>, _ msgLen: Int,
                    _ out: UnsafeMutablePointer<UInt8>, _ outCap: Int) -> Int {
    guard let k = fetch(handle) else { return -8 }
    let data = Data(bytes: msg, count: msgLen)
    guard let sig = SecKeyCreateSignature(k, sigAlgo, data as CFData, nil) as Data? else { return -9 }
    if sig.count > outCap { return -3 }
    sig.copyBytes(to: out, count: sig.count)
    return sig.count
}

// Export the Enclave key's PUBLIC point as X9.63 uncompressed bytes (04 || X || Y, 65B for
// P-256) — what Loki enrolls and verifies challenge signatures against. The private key never
// leaves the Enclave (SecKeyCopyExternalRepresentation on it would refuse).
@_cdecl("se_public_key")
public func se_public_key(_ handle: UInt64,
                          _ out: UnsafeMutablePointer<UInt8>, _ outCap: Int) -> Int {
    guard let k = fetch(handle) else { return -8 }
    guard let pub = SecKeyCopyPublicKey(k) else { return -1 }
    guard let rep = SecKeyCopyExternalRepresentation(pub, nil) as Data? else { return -10 }
    if rep.count > outCap { return -3 }
    rep.copyBytes(to: out, count: rep.count)
    return rep.count
}

@_cdecl("se_close")
public func se_close(_ handle: UInt64) {
    lock.lock(); defer { lock.unlock() }
    table.removeValue(forKey: handle)
}
