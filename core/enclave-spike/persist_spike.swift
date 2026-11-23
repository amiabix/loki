import Foundation
import Security

// Demonstrates the ONE thing that needs a signing identity: a PERSISTENT Secure Enclave
// key (created at wallet init, reloaded on the next launch). Unsigned this returns
// errSecMissingEntitlement (-34018); ad-hoc signed with a made-up access group the OS
// SIGKILLs the process (TeamIdentifier=not set). A free Apple ID "personal team" in
// Xcode produces the cert that makes this work on your own device.

func fail(_ m: String) -> Never { FileHandle.standardError.write(("FAIL: "+m+"\n").data(using:.utf8)!); exit(1) }

let tag = "cash.loki.signer.kek.spike".data(using: .utf8)!
SecItemDelete([kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: tag] as CFDictionary)

func createPersistentEnclaveKey() -> SecKey {
    guard let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], nil
    ) else { fail("access control") }
    let attrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecUseDataProtectionKeychain as String: true,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: tag,
            kSecAttrAccessControl as String: access,
        ],
    ]
    var err: Unmanaged<CFError>?
    guard let k = SecKeyCreateRandomKey(attrs as CFDictionary, &err) else {
        fail("create persistent SE key: \(err!.takeRetainedValue())")
    }
    return k
}

func loadPersistentEnclaveKey() -> SecKey {
    let q: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: tag,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecUseDataProtectionKeychain as String: true,
        kSecReturnRef as String: true,
    ]
    var out: CFTypeRef?
    let s = SecItemCopyMatching(q as CFDictionary, &out)
    guard s == errSecSuccess, let r = out else { fail("reload SE key: OSStatus \(s)") }
    return (r as! SecKey)
}

let algo = SecKeyAlgorithm.eciesEncryptionCofactorX963SHA256AESGCM

let created = createPersistentEnclaveKey()
guard let pub = SecKeyCopyPublicKey(created) else { fail("pub") }
var dek = Data(count: 32)
_ = dek.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
guard let wrapped = SecKeyCreateEncryptedData(pub, algo, dek as CFData, nil) as Data? else { fail("wrap") }
print("OK  init: persistent Secure Enclave KEK created; DEK wrapped (\(wrapped.count)B)")

let reloaded = loadPersistentEnclaveKey()
guard let got = SecKeyCreateDecryptedData(reloaded, algo, wrapped as CFData, nil) as Data? else { fail("unwrap after reload") }
guard got == dek else { fail("round-trip mismatch after reload") }
print("OK  reload: same Enclave key fetched by tag; DEK recovered byte-for-byte")

SecItemDelete([kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: tag] as CFDictionary)
print("PERSIST SPIKE PASS: create-at-init + reload-at-next-launch through the Secure Enclave works")
