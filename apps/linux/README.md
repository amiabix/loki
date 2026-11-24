# Run LokiSigner on Linux

LokiSigner is **Zcash testnet only**. The Linux desktop app uses the shared Flutter wallet and the Rust software signer. Its local passphrase protects the profile and signing keys at rest; it does not use a TPM or biometrics. Lock or quit the app when leaving the device unattended.

Use Flutter 3.50.1, Rust 1.100 or newer, and the Flutter Linux build dependencies. On Debian or Ubuntu:

```sh
sudo apt install clang cmake ninja-build pkg-config libgtk-3-dev libfontconfig-dev libstdc++-12-dev
cd apps
flutter pub get
flutter build linux --release
```

Run `loki_signer` from `build/linux/<arch>/release/bundle/`. Keep the adjacent `lib/` and `data/` directories with the executable. For a debug build use `flutter build linux --debug` and the `debug/bundle/` directory instead. Cargo builds the Rust signer as part of either build.

The default profile is `$XDG_DATA_HOME/LokiSigner`, or `~/.local/share/LokiSigner`. To use a separate profile, pass `--data /absolute/path/to/profile`. Never open the same profile in two signer processes.

## Pair, join and sign

1. Paste the coordinator’s one-use `loki://pair` link. Verify the HTTPS origin and member slot before allowing the app to contact it. The coordinator must provide a testnet `/api/signer-config` with HTTPS endpoints for frostd, lightwalletd and two nonce witnesses. Obtain the witness-pair fingerprint separately from the witness operators.
2. Review the endpoints on the in-window signer page, choose a strong local passphrase, and record the 24 recovery words offline. An existing signer unlocks with its passphrase and does not need another link.
3. To join a vault, paste the `https://<paired-coordinator>/#invite=<code>` link or its bare code into **Join vault**. Linux does not register as an HTTPS link handler. The creator stays unlocked and all members use the same frostd; no member wallet port needs a proxy. Linux supports relay invites, not legacy direct-peer setup. Compare the full roster code independently before confirming.
4. Preview payments in the wallet, then approve or refuse the signer-derived recipient, amount and fee on the in-window signer page. The wallet preview, unlock passphrase and roster agreement never approve payments.

In **Recovery**, export an encrypted backup and save the displayed SHA-256 fingerprint separately. To restore a signer from scratch, launch a fresh profile and choose **Restore signer**. You’ll need the original coordinator origin, your 24 words, the encrypted backup and its separately saved fingerprint. Close the old signer before restoring its identity in a different profile.
