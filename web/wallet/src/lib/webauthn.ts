"use client";

// WebAuthn PRF ceremony for the in-browser signer (tiers 1 & 2). This is the ONLY place the
// passkey ceremony lives on the main thread — `navigator.credentials` is unavailable in the
// Worker, so signer.ts runs this here and hands the 32-byte secret to the wasm core, which
// derives the share-wrapping KEK. The secret never leaves the browser. Ported from
// poc/web/webauthn_prf.js; the salt and params must stay fixed so the derived secret is stable.

const PRF_SALT = new TextEncoder().encode("loki/signer/share-kek/v1");

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

// Register a passkey and prove PRF is available. `prfSupported === false` => this authenticator
// has no PRF and the caller must fall back to the passphrase tier. A resident key is required so
// the credential id is the only thing we persist for unlock.
export async function createWebAuthnCredential(
  userName: string,
  authenticator: "platform" | "cross-platform",
): Promise<{ credentialId: Uint8Array; prfSupported: boolean }> {
  const cred = (await navigator.credentials.create({
    publicKey: {
      challenge: randomBytes(32),
      rp: { id: window.location.hostname, name: "Loki" },
      user: { id: randomBytes(16), name: userName, displayName: userName },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      authenticatorSelection: {
        authenticatorAttachment: authenticator,
        residentKey: "required",
        userVerification: "required",
      },
      extensions: { prf: { eval: { first: PRF_SALT } } },
    } as PublicKeyCredentialCreationOptions,
  })) as PublicKeyCredential;
  const ext = cred.getClientExtensionResults() as { prf?: { enabled?: boolean } };
  return { credentialId: new Uint8Array(cred.rawId), prfSupported: !!ext.prf?.enabled };
}

// Release the 32-byte PRF secret for the stored credential. Same salt as create() => same secret,
// so the reloaded signer re-derives the same KEK and opens its share.
export async function getPrfSecret(credentialId: Uint8Array): Promise<Uint8Array> {
  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: randomBytes(32),
      rpId: window.location.hostname,
      allowCredentials: [{ type: "public-key", id: credentialId }],
      userVerification: "required",
      extensions: { prf: { eval: { first: PRF_SALT } } },
    } as PublicKeyCredentialRequestOptions,
  })) as PublicKeyCredential;
  const results = (assertion.getClientExtensionResults() as { prf?: { results?: { first?: ArrayBuffer } } }).prf?.results;
  if (!results?.first) throw new Error("WebAuthn PRF not available on this authenticator; use the passphrase tier");
  const secret = new Uint8Array(results.first);
  if (secret.length < 32) throw new Error(`PRF secret too short: ${secret.length} bytes`);
  return secret.slice(0, 32);
}
