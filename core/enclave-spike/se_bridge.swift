import Foundation
import Security

// Ephemeral, process-lifetime Secure Enclave key (demo). The real backend persists it
// once a signing identity exists; wrap/unwrap are identical either way.
private var cached: SecKey?

private func key() -> SecKey? {
    if let k = cached { return k }
    guard let ac = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], nil
    ) else { return nil }
    let attrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: false,
            kSecAttrAccessControl as String: ac,
        ],
    ]
    cached = SecKeyCreateRandomKey(attrs as CFDictionary, nil)
    return cached
}

private let algo = SecKeyAlgorithm.eciesEncryptionCofactorX963SHA256AESGCM

@_cdecl("se_wrap")
public func se_wrap(_ dek: UnsafePointer<UInt8>, _ dekLen: Int,
                    _ out: UnsafeMutablePointer<UInt8>, _ outCap: Int) -> Int {
    guard let k = key(), let pub = SecKeyCopyPublicKey(k) else { return -1 }
    let data = Data(bytes: dek, count: dekLen)
    guard let ct = SecKeyCreateEncryptedData(pub, algo, data as CFData, nil) as Data? else { return -2 }
    if ct.count > outCap { return -3 }
    ct.copyBytes(to: out, count: ct.count)
    return ct.count
}

@_cdecl("se_unwrap")
public func se_unwrap(_ ct: UnsafePointer<UInt8>, _ ctLen: Int,
                      _ out: UnsafeMutablePointer<UInt8>, _ outCap: Int) -> Int {
    guard let k = key() else { return -1 }
    let data = Data(bytes: ct, count: ctLen)
    guard let pt = SecKeyCreateDecryptedData(k, algo, data as CFData, nil) as Data? else { return -2 }
    if pt.count > outCap { return -3 }
    pt.copyBytes(to: out, count: pt.count)
    return pt.count
}
