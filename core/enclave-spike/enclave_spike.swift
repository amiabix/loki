import Foundation
import Security

func fail(_ msg: String) -> Never {
    FileHandle.standardError.write(("FAIL: " + msg + "\n").data(using: .utf8)!)
    exit(1)
}

var acErr: Unmanaged<CFError>?
guard let access = SecAccessControlCreateWithFlags(
    kCFAllocatorDefault,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    [.privateKeyUsage],
    &acErr
) else { fail("SecAccessControlCreateWithFlags: \(acErr!.takeRetainedValue())") }

// 2. Create a P-256 key INSIDE the Secure Enclave (ephemeral; not persisted to keychain).
let attrs: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeySizeInBits as String: 256,
    kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
    kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: false,
        kSecAttrAccessControl as String: access,
    ],
]
var keyErr: Unmanaged<CFError>?
guard let priv = SecKeyCreateRandomKey(attrs as CFDictionary, &keyErr) else {
    fail("SecKeyCreateRandomKey (Secure Enclave): \(keyErr!.takeRetainedValue())")
}
guard let pub = SecKeyCopyPublicKey(priv) else { fail("SecKeyCopyPublicKey") }
print("OK  created P-256 key in the Secure Enclave (ephemeral, token=SecureEnclave)")

var expErr: Unmanaged<CFError>?
if SecKeyCopyExternalRepresentation(priv, &expErr) != nil {
    fail("SECURITY: private key is exportable (must not be)")
}
print("OK  private key is non-exportable (SecKeyCopyExternalRepresentation refused)")

var dek = Data(count: 32)
let rc = dek.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
guard rc == errSecSuccess else { fail("SecRandomCopyBytes") }
let algo = SecKeyAlgorithm.eciesEncryptionCofactorX963SHA256AESGCM
guard SecKeyIsAlgorithmSupported(pub, .encrypt, algo) else { fail("ECIES algo unsupported") }
var encErr: Unmanaged<CFError>?
guard let wrapped = SecKeyCreateEncryptedData(pub, algo, dek as CFData, &encErr) as Data? else {
    fail("wrap_dek SecKeyCreateEncryptedData: \(encErr!.takeRetainedValue())")
}
print("OK  wrap_dek -> \(wrapped.count) bytes ciphertext")

var decErr: Unmanaged<CFError>?
guard let unwrapped = SecKeyCreateDecryptedData(priv, algo, wrapped as CFData, &decErr) as Data? else {
    fail("unwrap_dek SecKeyCreateDecryptedData: \(decErr!.takeRetainedValue())")
}
guard unwrapped == dek else { fail("SECURITY: round-trip mismatch") }
print("OK  unwrap_dek round-trips — 32-byte DEK recovered byte-for-byte")
print("SPIKE PASS: Secure Enclave wrap/unwrap of a DEK works on this machine")
