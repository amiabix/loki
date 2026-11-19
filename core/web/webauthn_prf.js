// WebAuthn PRF glue for the in-browser signer (ws1-signer §4, tiers 1 & 2).
//
// This is the ONLY place the passkey ceremony lives; the Rust `WebAuthnSecureElement`
// (core/src/signer/secure_element_webauthn.rs) takes the 32-byte secret these functions return
// and derives the share-wrapping KEK (HKDF-SHA256). The secret never leaves the browser.
//
// Flow:
//   createSignerPasskey(...)  -> during "Create your signer": registers a passkey and proves
//                                PRF is available on this authenticator.
//   unlockPrfSecret(...)      -> every unlock/seal/open: Touch/Face ID (or security key / phone)
//                                releases the PRF secret; hand its bytes to the wasm signer.
//
// The PRF salt is a FIXED, per-use label (not a secret): the same (passkey, salt) always yields
// the same 32-byte secret, so a reloaded signer re-derives the same KEK and opens its share.
// Use distinct salts for distinct KEKs; here one salt == one signer's share-wrapping KEK.

const PRF_SALT = new TextEncoder().encode("loki/signer/share-kek/v1");

// A relying-party-scoped, non-secret user handle. One passkey per signer identity.
function randomBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

// Tier 1/2 registration. `authenticator` selects the tier:
//   "platform"       -> Touch/Face ID / Windows Hello (biometric, tier 1)
//   "cross-platform" -> security key or phone passkey over hybrid/caBLE (tier 2)
//   undefined        -> let the browser offer all of them.
// A resident (discoverable) credential is REQUIRED so the signer can be unlocked later without
// the server handing back a credential id (true self-custody: the platform stores nothing).
export async function createSignerPasskey({
  rpId = location.hostname,
  rpName = "Loki",
  userName,
  authenticator, // "platform" | "cross-platform" | undefined
} = {}) {
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge: randomBytes(32), // registration challenge; verified server-side if you attest
      rp: { id: rpId, name: rpName },
      user: { id: randomBytes(16), name: userName, displayName: userName },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 }, // ES256
        { type: "public-key", alg: -257 }, // RS256
      ],
      authenticatorSelection: {
        authenticatorAttachment: authenticator, // undefined => any
        residentKey: "required",
        userVerification: "required",
      },
      extensions: {
        // Ask for PRF up front so we can detect authenticators that don't support it and fall
        // back to the passphrase tier BEFORE the user commits a share to this passkey.
        prf: { eval: { first: PRF_SALT } },
      },
    },
  });

  const ext = cred.getClientExtensionResults();
  const prfSupported = !!(ext.prf && ext.prf.enabled);
  // Some platforms (notably Chrome on the create() call) report `enabled` but defer the first
  // PRF evaluation to a subsequent get(). `prfSupported === false` => this authenticator has no
  // PRF; the UI must offer the passphrase fallback (tier 3) instead.
  return { credentialId: new Uint8Array(cred.rawId), prfSupported };
}

// Tier 1/2 unlock: release the 32-byte PRF secret. Returns a Uint8Array(32) to hand straight to
// the wasm `WebAuthnSecureElement::from_prf_secret`. With a resident key, `allowCredentials` can
// be empty and the authenticator discovers the credential itself.
export async function unlockPrfSecret({ rpId = location.hostname } = {}) {
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: randomBytes(32), // fresh anti-replay challenge each unlock
      rpId,
      userVerification: "required",
      extensions: {
        prf: { eval: { first: PRF_SALT } },
      },
    },
  });

  const results = assertion.getClientExtensionResults().prf?.results;
  if (!results || !results.first) {
    throw new Error("WebAuthn PRF not available on this authenticator; use the passphrase tier");
  }
  // `results.first` is an ArrayBuffer of (typically) 32 bytes of HMAC output from the passkey.
  const secret = new Uint8Array(results.first);
  if (secret.length < 32) {
    throw new Error(`PRF secret too short: ${secret.length} bytes`);
  }
  return secret.slice(0, 32);
}
