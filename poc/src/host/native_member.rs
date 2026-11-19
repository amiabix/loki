//! In-process queries from LokiSigner, never from the loopback router.

use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
};

use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::network::VaultNetwork;
use super::{ceremony, custody::SignerViewingKey, state::Shared, Config, FetchedConfig, LocalApproval, LocalNotice};

const LOCKED: &str = "Unlock LokiSigner to view vault addresses.";
const LIST_ERROR: &str = "LokiSigner could not list vaults.";
const VAULT_ERROR: &str = "LokiSigner could not verify this vault’s receive address.";

struct NativeMember {
    state: Shared,
    viewing_keys: Mutex<BTreeMap<(String, u16), (SignerViewingKey, VaultNetwork)>>,
}

static RUNNING: Mutex<Option<Arc<NativeMember>>> = Mutex::new(None);

struct NativeScope;

impl NativeScope {
    fn install(state: &Shared) -> Result<Self, String> {
        let mut running = RUNNING.lock().unwrap_or_else(|e| e.into_inner());
        if running.is_some() {
            return Err("LokiSigner is already running.".into());
        }
        *running = Some(Arc::new(NativeMember { state: state.clone(), viewing_keys: Mutex::default() }));
        Ok(Self)
    }
}

impl Drop for NativeScope {
    fn drop(&mut self) {
        RUNNING.lock().unwrap_or_else(|e| e.into_inner()).take();
    }
}

pub(crate) fn run_native(
    config: Config,
    pass: Zeroizing<String>,
    notice: LocalNotice,
    approval: LocalApproval,
    fetched: Option<FetchedConfig>,
) -> Result<(), String> {
    super::run_local_with(config, Some(pass), Some(notice), Some(approval), fetched, NativeScope::install)
}

/// Snapshot the running member without keeping the process handle locked over a query. Discard
/// the result if its member stopped or was replaced while the worker was doing I/O.
fn with_running_member<T>(query: impl FnOnce(&NativeMember) -> Result<T, &'static str>) -> Result<T, &'static str> {
    let member = RUNNING.lock().map_err(|_| LIST_ERROR)?.clone().ok_or(LOCKED)?;
    let result = query(&member);
    let running = RUNNING.lock().map_err(|_| LIST_ERROR)?;
    if !running.as_ref().is_some_and(|current| Arc::ptr_eq(current, &member)) {
        return Err(LOCKED);
    }
    result
}

/// Called from a native worker thread, not a Tokio task or the app's main thread.
pub(crate) fn vault_addresses() -> Result<Vec<Value>, &'static str> {
    with_running_member(|member| {
        let (data, pass) = {
            let session = member.state.session.blocking_read();
            let session = session.as_ref().ok_or(LOCKED)?;
            (session.data.clone(), session.passphrase.clone())
        };
        let rows = member.list(&data, &pass);
        if member.state.session.blocking_read().is_none() {
            return Err(LOCKED);
        }
        rows
    })
}

impl NativeMember {
    fn list(&self, data: &Path, pass: &str) -> Result<Vec<Value>, &'static str> {
        let entries = match std::fs::read_dir(data.join("vaults")) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(_) => return Err(LIST_ERROR),
        };
        let mut entries = entries.collect::<Result<Vec<_>, _>>().map_err(|_| LIST_ERROR)?;
        entries.sort_by_key(|entry| entry.file_name());
        let mut rows = Vec::new();
        for entry in entries {
            let name = entry.file_name();
            let Some(vault) = name.to_str() else { continue };
            let Ok(dir) = ceremony::dir(data, vault) else { continue };
            if !dir.exists("vault.sealed") {
                continue;
            }
            let Ok(c) = ceremony::load(data, pass, vault) else {
                rows.push(json!({ "error": VAULT_ERROR }));
                continue;
            };
            let slot = c.my_slot;
            let label = vault_label(&c.name);
            let row = match self.address(data, pass, vault, slot) {
                Ok((network, address)) => json!({ "name": label, "slot": slot, "network": network, "address": address }),
                Err(_) => json!({ "name": label, "slot": slot, "error": VAULT_ERROR }),
            };
            rows.push(row);
        }
        Ok(rows)
    }

    fn address(&self, data: &Path, pass: &str, vault: &str, slot: u16) -> Result<(&'static str, String), String> {
        // Don't migrate from vault.sealed or hold any host/cache lock over the Enclave prompt.
        let id = (vault.to_owned(), slot);
        let cached = self.viewing_keys.lock().map_err(|e| e.to_string())?.get(&id).cloned();
        let (key, network) = match cached {
            Some(entry) => entry,
            None => SignerViewingKey::open(&self.state, data, pass, vault, slot)?,
        };
        // Read the seal after any prompt, even when the key was already cached.
        let raw = Zeroizing::new(ceremony::dir(data, vault)?.read_sealed("vault.sealed", pass).map_err(|e| e.to_string())?);
        let sealed: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        if sealed["vault"] != vault || sealed["my_frost_id"] != slot || sealed["network"] != network.label()
            || sealed["key_derivation"] != crate::zip2005::VERSION
        {
            return Err("vault metadata mismatch".into());
        }
        let address = key.checked_address(&sealed, network)?;
        self.viewing_keys.lock().map_err(|e| e.to_string())?.entry(id).or_insert((key, network));
        Ok((network.label(), address))
    }
}

fn vault_label(name: &str) -> &str {
    // Refuse multiline, terminal controls and bidi overrides. Swift also confines names to a
    // single plain-text field separate from trusted labels, addresses, and error messages.
    if name.chars().any(|c| {
        c.is_control() || (c.is_whitespace() && c != ' ')
            || matches!(c, '\u{061c}' | '\u{200e}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
    }) {
        "Name hidden (unsupported characters)"
    } else {
        name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        signer::{local::encode_share, store::{FileKind, SignerStore}, Network},
        state::MemberDir,
        vault, zip2005,
    };
    use reddsa_frost::frost::redpallas as frost;
    use zcash_protocol::consensus::NetworkType;

    static TEST_MEMBER: Mutex<()> = Mutex::new(());
    const PASS: &str = "local test unlock";
    const SLOT: u16 = 2;

    fn config(data: &Path) -> Config {
        super::super::config_from_args(&[
            "--data".into(), data.to_str().unwrap().into(), "--port".into(), "0".into(),
            "--network".into(), "testnet".into(),
        ]).unwrap()
    }

    fn write(dir: &MemberDir, file: &str, value: &Value) {
        if dir.exists(file) {
            std::fs::remove_file(dir.path().join(file)).unwrap();
        }
        dir.write_sealed(file, &serde_json::to_vec(value).unwrap(), PASS).unwrap();
    }

    fn ceremony(dir: &MemberDir, id: &str, name: &str) {
        write(dir, "ceremony.sealed", &json!({
            "vault": id, "name": name, "my_slot": SLOT, "threshold": 2, "members": 3,
            "creator_base_url": "http://127.0.0.1:3001", "frostd_url": "http://127.0.0.1:2744",
            "slots": {}, "agreed": [], "dkg_started": false,
        }));
    }

    #[test]
    fn addresses_require_the_signer_store_and_check_each_seal_even_after_caching() {
        let _test = TEST_MEMBER.lock().unwrap();
        let data = std::env::temp_dir().join(format!("loki-addresses-{}", uuid::Uuid::new_v4()));
        let state = Arc::new(crate::host::state::AppState::new(config(&data)));
        let _native = NativeScope::install(&state).unwrap();
        *state.session.blocking_write() = Some(crate::host::state::Session {
            passphrase: Zeroizing::new(PASS.into()), data: data.clone(),
        });
        assert!(vault_addresses().unwrap().is_empty());

        let pending = "10".repeat(32);
        let pending_dir = MemberDir::create(&data.join("vaults"), &pending).unwrap();
        ceremony(&pending_dir, &pending, "Pending vault");
        assert!(vault_addresses().unwrap().is_empty());

        let id = [43u8; 32];
        let id_hex = hex::encode(id);
        let dir = MemberDir::create(&data.join("vaults"), &id_hex).unwrap();
        ceremony(&dir, &id_hex, "Shared reserve");
        let (shares, public) = frost::keys::generate_with_dealer(
            3, 2, frost::keys::IdentifierList::Default, rand_core::OsRng,
        ).unwrap();
        let slot = frost::Identifier::try_from(SLOT).unwrap();
        let share = frost::keys::KeyPackage::try_from(shares[&slot].clone()).unwrap();
        let ak: [u8; 32] = public.verifying_key().serialize().unwrap().try_into().unwrap();
        let vs = [62; 32];
        let fvk = zip2005::frost_viewing_key(&ak, &vs).unwrap();
        let expected = vault::unified_receiver(vault::test_only_address(&fvk).to_raw_address_bytes(), NetworkType::Test);
        let sealed: Value = serde_json::from_slice(&super::super::ceremony::vault_sealed_bytes(
            &id_hex, SLOT, 2, 3, "fixture", &public, &fvk, 4465026, VaultNetwork::Testnet,
        ).unwrap()).unwrap();
        write(&dir, "vault.sealed", &sealed);
        let error_row = json!({ "name": "Shared reserve", "slot": SLOT,
            "error": "LokiSigner could not verify this vault’s receive address." });
        assert_eq!(vault_addresses().unwrap(), vec![error_row.clone()], "a seal alone isn't enough");

        let signer_dir = super::super::ceremony::signer_dir(&data, &id_hex).unwrap();
        let store = SignerStore::create(&signer_dir, Network::Testnet, id, SLOT).unwrap();
        let se = state.config.open_secure_element(&signer_dir, PASS).unwrap();
        let raw = encode_share(&share.serialize().unwrap(), &public.serialize().unwrap(), &vs);
        store.write(&se, FileKind::Share, 0, &raw).unwrap();
        let correct = json!({ "name": "Shared reserve", "slot": SLOT, "network": "testnet", "address": expected });
        assert_eq!(vault_addresses().unwrap(), vec![correct.clone()]);
        #[cfg(all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))]
        {
            let reply = crate::enclave_ffi::loki_member_app_vault_addresses();
            assert!(!reply.is_null());
            let value: Value = serde_json::from_slice(unsafe { std::ffi::CStr::from_ptr(reply) }.to_bytes()).unwrap();
            unsafe { crate::enclave_ffi::loki_member_app_free(reply); }
            assert_eq!(value, json!({ "vaults": [correct] }));
        }

        let other_fvk = zip2005::frost_viewing_key(&ak, &[63; 32]).unwrap();
        let other_address = vault::unified_address(&other_fvk, NetworkType::Test);
        let (_, other_package) = frost::keys::generate_with_dealer(
            3, 2, frost::keys::IdentifierList::Default, rand_core::OsRng,
        ).unwrap();
        for (field, tampered) in [
            ("group_address", other_address),
            ("public_package", hex::encode(other_package.serialize().unwrap())),
        ] {
            let mut invalid = sealed.clone();
            invalid[field] = json!(tampered);
            write(&dir, "vault.sealed", &invalid);
            assert_eq!(vault_addresses().unwrap(), vec![error_row.clone()], "changed {field}");
        }
        // A consistent-looking address and network aren't evidence of the store's network.
        let mut wrong_network = sealed.clone();
        wrong_network["network"] = json!("regtest");
        wrong_network["group_address"] = json!(vault::regtest_unified_address(&fvk));
        write(&dir, "vault.sealed", &wrong_network);
        assert_eq!(vault_addresses().unwrap(), vec![error_row]);

        write(&dir, "vault.sealed", &sealed);
        for hidden in ['\n', '\u{0085}', '\u{2028}', '\u{202e}', '\u{001b}'] {
            ceremony(&dir, &id_hex, &format!("Reserve{hidden}Copy this address instead"));
            let mut safe = correct.clone();
            safe["name"] = json!("Name hidden (unsupported characters)");
            assert_eq!(vault_addresses().unwrap(), vec![safe], "{hidden:?}");
        }
        *state.session.blocking_write() = None;
        assert_eq!(vault_addresses(), Err("Unlock LokiSigner to view vault addresses."));
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn only_native_startup_installs_the_handle_and_unwind_clears_it() {
        struct Ready;
        let _test = TEST_MEMBER.lock().unwrap();
        let data = Path::new("unused");
        for native in [false, true] {
            let notice: LocalNotice = Arc::new(move |kind, _| {
                assert_eq!(kind, "ready");
                assert_eq!(RUNNING.lock().unwrap().is_some(), native);
                assert_eq!(std::thread::spawn(vault_addresses).join().unwrap(), Err("Unlock LokiSigner to view vault addresses."));
                std::panic::panic_any(Ready); // Stop once startup reached ready, without leaving a listener running.
            });
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if native {
                    run_native(config(data), Zeroizing::new(PASS.into()), notice, Arc::new(|_| false), None)
                } else {
                    super::super::run_local(config(data), None, Some(notice), None, None)
                }
            }));
            assert!(result.unwrap_err().is::<Ready>());
            assert_eq!(vault_addresses(), Err("Unlock LokiSigner to view vault addresses."));
        }
    }
}
