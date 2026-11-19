//! In-process queries from LokiSigner, never from the loopback router.

use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
};

use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::network::VaultNetwork;
use super::{ceremony, custody::{is_legacy, SignerViewingKey}, state::Shared, Config, FetchedConfig, LocalApproval, LocalNotice, LocalRosterConfirmation, vault_label};

const LOCKED: &str = "Unlock LokiSigner to view vault addresses.";
const LIST_ERROR: &str = "LokiSigner could not list vaults.";
const VAULT_ERROR: &str = "LokiSigner could not verify this vault’s receive address.";
const UPGRADE_VAULT: &str = "Open this vault in the wallet once to upgrade it.";

struct NativeMember {
    state: Shared,
    viewing_keys: Mutex<BTreeMap<(String, u16), (SignerViewingKey, VaultNetwork)>>,
    stop: Arc<tokio::sync::Notify>,
    #[cfg(all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))]
    notice: Option<LocalNotice>,
}

static RUNNING: Mutex<Option<Arc<NativeMember>>> = Mutex::new(None);
// The UI may request recovery, but only a local key failure for this launch grants it.
static KEY_RECOVERY: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);

struct NativeScope;

impl NativeScope {
    fn install(state: &Shared, stop: Arc<tokio::sync::Notify>, _notice: Option<LocalNotice>) -> Result<Self, String> {
        let mut running = RUNNING.lock().unwrap_or_else(|e| e.into_inner());
        if running.is_some() {
            return Err("LokiSigner is already running.".into());
        }
        KEY_RECOVERY.lock().map_err(|_| "LokiSigner could not access profile recovery.")?.take();
        *running = Some(Arc::new(NativeMember { state: state.clone(), viewing_keys: Mutex::default(), stop,
            #[cfg(all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))]
            notice: _notice,
        }));
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
    roster_confirmation: LocalRosterConfirmation,
    connect: super::connect::LocalConnect,
    fetched: Option<FetchedConfig>,
) -> Result<(), String> {
    struct ClearCache;
    impl Drop for ClearCache {
        fn drop(&mut self) { crate::seal_kdf::clear_session_cache(); }
    }
    let _cache = ClearCache;
    let stop = Arc::new(tokio::sync::Notify::new());
    super::run_local_with(config, Some(pass), Some(notice.clone()), Some(approval), Some(roster_confirmation), fetched,
        Some(&stop), Some(connect), |state| NativeScope::install(state, stop.clone(), Some(notice)))
}

pub(crate) fn request_stop() -> bool {
    RUNNING.lock().is_ok_and(|running| running.as_ref().is_some_and(|member| {
        member.stop.notify_one();
        true
    }))
}

#[cfg(all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))]
pub(super) fn authorize_key_recovery(data: &Path) {
    if let Ok(running) = RUNNING.lock() {
        if running.as_ref().is_some_and(|member| member.state.config.data == data) {
            if let Ok(mut recovery) = KEY_RECOVERY.lock() { *recovery = Some(data.to_owned()); }
        }
    }
}

#[cfg(all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))]
pub(super) fn report_vault_key_gone(data: &Path) {
    let notice = RUNNING.lock().ok().and_then(|running| {
        let member = running.as_ref().filter(|member| member.state.config.data == data)?;
        let mut recovery = KEY_RECOVERY.lock().ok()?;
        if recovery.as_deref() == Some(data) { return None; }
        *recovery = Some(data.to_owned());
        member.notice.clone()
    });
    if let Some(notice) = notice {
        use crate::signer::secure_element_apple::KeyFailure;
        notice("registration-key-gone", KeyFailure::Missing.message());
    }
}

pub(crate) fn set_aside(data: &Path, recover: bool) -> Result<(), &'static str> {
    let running = RUNNING.lock().map_err(|_| super::native_recovery::REFUSED)?;
    if running.is_some() { return Err(super::native_recovery::REFUSED); }
    let mut evidence = KEY_RECOVERY.lock().map_err(|_| super::native_recovery::REFUSED)?;
    super::native_recovery::set_aside(data, recover && evidence.as_deref() == Some(data))?;
    evidence.take();
    Ok(())
}

pub(crate) fn disconnect_wallet_tabs() {
    if let Some(tabs) = RUNNING.lock().unwrap().as_ref().and_then(|m| m.state.wallet_tabs.as_ref()) {
        tabs.revoke_all();
    }
}

pub(crate) fn restore_running(words: Zeroizing<Vec<u8>>, file: &Path) -> Result<(), &'static str> {
    let member = RUNNING.lock().map_err(|_| super::native_recovery::REFUSED)?.clone()
        .ok_or(super::native_recovery::LOCKED)?;
    super::native_recovery::restore_running(&member.state, words, file)
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
    vault_addresses_with(|| {})
}

fn vault_addresses_with(after_list: impl FnOnce()) -> Result<Vec<Value>, &'static str> {
    with_running_member(|member| {
        let (data, pass) = {
            let session = member.state.session.blocking_read();
            let session = session.as_ref().ok_or(LOCKED)?;
            (session.data.clone(), session.passphrase.clone())
        };
        let rows = member.list(&data, &pass);
        after_list();
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
                Err(error) => json!({ "name": label, "slot": slot, "error": error }),
            };
            rows.push(row);
        }
        Ok(rows)
    }

    fn address(&self, data: &Path, pass: &str, vault: &str, slot: u16) -> Result<(&'static str, String), &'static str> {
        // Don't migrate from vault.sealed or hold any host/cache lock over the Enclave prompt.
        let id = (vault.to_owned(), slot);
        let cached = self.viewing_keys.lock().map_err(|_| VAULT_ERROR)?.get(&id).cloned();
        let opened = cached.map_or_else(|| SignerViewingKey::open(&self.state, data, pass, vault, slot), Ok);
        // Read after any prompt, including when the store could not be opened for a legacy vault.
        let dir = ceremony::dir(data, vault).map_err(|_| VAULT_ERROR)?;
        let raw = Zeroizing::new(dir.read_sealed("vault.sealed", pass).map_err(|_| VAULT_ERROR)?);
        let sealed: Value = serde_json::from_slice(&raw).map_err(|_| VAULT_ERROR)?;
        if is_legacy(&sealed) {
            return Err(UPGRADE_VAULT);
        }
        let (key, network) = opened.map_err(|e| super::state::member_key_message(&e).unwrap_or(VAULT_ERROR))?;
        if sealed["vault"] != vault || sealed["my_frost_id"] != slot || sealed["network"] != network.label()
            || sealed["key_derivation"] != crate::zip2005::VERSION
        {
            return Err(VAULT_ERROR);
        }
        let address = key.checked_address(&sealed, network).map_err(|_| VAULT_ERROR)?;
        self.viewing_keys.lock().map_err(|_| VAULT_ERROR)?.entry(id).or_insert((key, network));
        Ok((network.label(), address))
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
        let mut settings = super::super::native_config_from_args(&[
            "--data".into(), data.to_str().unwrap().into(), "--port".into(), "0".into(),
            "--network".into(), "testnet".into(),
        ]).unwrap();
        settings.secure_element = "software".into();
        settings
    }

    #[test]
    fn a_paired_native_app_runs_offline_and_only_sets_aside_after_stop() {
        let _test = TEST_MEMBER.lock().unwrap();
        let root = std::env::temp_dir().join(format!("loki-native-stop-{}", uuid::Uuid::new_v4()));
        let data = root.join("LokiSigner");
        crate::profile::create(&data, PASS, "Test member").unwrap();
        super::super::registration::save_coordinator(&data, "https://127.0.0.1:1", 7).unwrap();
        let mut settings = config(&data);
        settings.registration = Some(super::super::RegistrationConfig::resume(&data, false).unwrap());
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let notice: LocalNotice = Arc::new(move |kind, message| {
                if kind != "recovery" { ready_tx.send((kind.to_owned(), message.to_owned())).unwrap(); }
            });
            stop_tx.send(run_native(settings, Zeroizing::new(PASS.into()), notice, Arc::new(|_| false),
                Arc::new(|_| crate::host::RosterAnswer::Differ), Arc::new(|_, _, _| false), None)).unwrap();
        });
        let timeout = std::time::Duration::from_secs(10);
        let events: BTreeMap<_, _> = (0..2).map(|_| ready_rx.recv_timeout(timeout).unwrap()).collect();
        assert_eq!(events["registration-warning"], "LokiSigner couldn’t reach the coordinator. Your profile is unlocked and LokiSigner will keep trying in the background.");
        assert_eq!(events["ready"], "", "native readiness does not expose a local pairing link");
        assert!(vault_addresses().unwrap().is_empty(), "local features work while offline");
        // A subsequent attempt still fails, but the modal warning is once per launch.
        assert_eq!(ready_rx.recv_timeout(std::time::Duration::from_secs(6)).unwrap_err(), std::sync::mpsc::RecvTimeoutError::Timeout);
        assert!(set_aside(&data, false).is_err());
        assert!(request_stop());
        stop_rx.recv_timeout(timeout).unwrap().unwrap();
        worker.join().unwrap();
        set_aside(&data, false).unwrap();
        assert!(!data.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))]
    #[test]
    fn only_a_gone_vault_key_allows_archiving_vault_data_after_stop() {
        use crate::signer::secure_element_apple::KeyFailure;
        let _test = TEST_MEMBER.lock().unwrap();
        let root = std::env::temp_dir().join(format!("loki-native-key-gone-{}", uuid::Uuid::new_v4()));
        let data = root.join("LokiSigner");
        let share = "vaults/member-vault/signer/share.sealed";
        let key_dir = data.join(share).parent().unwrap().to_owned();
        std::fs::create_dir_all(&key_dir).unwrap();
        std::fs::write(data.join(share), b"existing sealed share").unwrap();
        let mut settings = config(&data);
        settings.secure_element = "apple".into();
        let state = Arc::new(crate::host::state::AppState::new(settings));
        let (tx, rx) = std::sync::mpsc::channel();
        let notice: LocalNotice = Arc::new(move |kind, text| tx.send((kind.to_owned(), text.to_owned())).unwrap());
        for failure in [KeyFailure::Cancelled, KeyFailure::LockedOut, KeyFailure::Missing] {
            let scope = NativeScope::install(&state, Arc::default(), Some(notice.clone())).unwrap();
            let _fixture = super::super::state::apple_test::install(&data, move |_, _, create| {
                assert!(!create);
                Err(failure)
            });
            assert_eq!(state.config.open_secure_element(&key_dir, PASS).err().as_deref(), Some(failure.message()));
            assert!(set_aside(&data, true).is_err(), "cannot archive a running profile");
            drop(scope);
            if !failure.is_gone() {
                assert!(rx.try_recv().is_err());
                assert_eq!(set_aside(&data, true), Err("vault"));
            }
        }
        assert_eq!(rx.try_recv().unwrap(), ("registration-key-gone".into(), KeyFailure::Missing.message().into()));
        assert_eq!(set_aside(&data, false), Err("vault"));
        set_aside(&data, true).unwrap();
        assert!(!data.exists());
        let archived = std::fs::read_dir(&root).unwrap().next().unwrap().unwrap().path();
        assert_eq!(std::fs::read(archived.join(share)).unwrap(), b"existing sealed share");
        std::fs::remove_dir_all(root).unwrap();
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
        let _native = NativeScope::install(&state, Arc::default(), None).unwrap();
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

        let mut legacy = sealed.clone();
        legacy["key_package"] = json!(hex::encode(share.serialize().unwrap()));
        legacy["vault_secret"] = json!(hex::encode(vs));
        write(&dir, "vault.sealed", &legacy);
        let upgrade_row = json!({ "name": "Shared reserve", "slot": SLOT,
            "error": "Open this vault in the wallet once to upgrade it." });
        assert_eq!(vault_addresses().unwrap(), vec![upgrade_row.clone()], "legacy seal with no signer store");
        write(&dir, "vault.sealed", &sealed);

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

        write(&dir, "vault.sealed", &legacy);
        assert_eq!(vault_addresses().unwrap(), vec![upgrade_row], "legacy seal with a cached viewing key");

        let other_fvk = zip2005::frost_viewing_key(&ak, &[63; 32]).unwrap();
        let other_address = vault::unified_address(&other_fvk, NetworkType::Test);
        let (_, other_package) = frost::keys::generate_with_dealer(
            3, 2, frost::keys::IdentifierList::Default, rand_core::OsRng,
        ).unwrap();
        for (field, tampered) in [
            ("group_address", json!(other_address)),
            ("public_package", json!(hex::encode(other_package.serialize().unwrap()))),
            ("my_frost_id", json!(SLOT + 1)),
        ] {
            let mut invalid = sealed.clone();
            invalid[field] = tampered;
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
        for hidden in ['\n', '\u{0085}', '\u{2028}', '\u{202e}', '\u{001b}', '\u{200b}', '\u{200c}', '\u{200d}', '\u{2060}', '\u{feff}'] {
            ceremony(&dir, &id_hex, &format!("Reserve{hidden}Copy this address instead"));
            let mut safe = correct.clone();
            safe["name"] = json!("Name hidden (unsupported characters)");
            assert_eq!(vault_addresses().unwrap(), vec![safe], "{hidden:?}");
        }
        let max_label = "é".repeat(80);
        assert_eq!(vault_label(&max_label), max_label);
        ceremony(&dir, &id_hex, &(max_label + "!"));
        let mut safe = correct;
        safe["name"] = json!("Name hidden (unsupported characters)");
        assert_eq!(vault_addresses().unwrap(), vec![safe]);

        let rows = vault_addresses_with(|| *state.session.blocking_write() = None);
        assert_eq!(rows, Err("Unlock LokiSigner to view vault addresses."), "profile locked during listing");
        assert_eq!(vault_addresses(), Err("Unlock LokiSigner to view vault addresses."));
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn running_handle_refuses_second_install_and_discards_rows_after_replacement() {
        let _test = TEST_MEMBER.lock().unwrap();
        let state = Arc::new(crate::host::state::AppState::new(config(Path::new("unused"))));
        let scope = NativeScope::install(&state, Arc::default(), None).unwrap();
        assert_eq!(NativeScope::install(&state, Arc::default(), None).err().as_deref(), Some("LokiSigner is already running."));

        let mut replacement = None;
        let rows = with_running_member(|_| {
            drop(scope);
            replacement = Some(NativeScope::install(&state, Arc::default(), None).unwrap());
            Ok(vec![json!({ "name": "Old member’s vault" })])
        });
        assert!(replacement.is_some());
        assert_eq!(rows, Err("Unlock LokiSigner to view vault addresses."));
        assert_eq!(with_running_member(|_| Ok(())), Ok(()));
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
                // Only LokiSigner's entry attaches its roster dialog, and it is the one given.
                let roster = RUNNING.lock().unwrap().as_ref()
                    .and_then(|member| member.state.roster_confirmation.as_ref().map(|confirm| confirm("{}")));
                assert_eq!(roster, native.then_some(crate::host::RosterAnswer::Differ));
                assert_eq!(std::thread::spawn(vault_addresses).join().unwrap(), Err("Unlock LokiSigner to view vault addresses."));
                std::panic::panic_any(Ready); // Stop once startup reached ready, without leaving a listener running.
            });
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if native {
                    run_native(config(data), Zeroizing::new(PASS.into()), notice, Arc::new(|_| false),
                        Arc::new(|_| crate::host::RosterAnswer::Differ), Arc::new(|_, _, _| false), None)
                } else {
                    let config = super::super::config_from_args(&["--data".into(), data.to_str().unwrap().into(),
                        "--port".into(), "0".into()]).unwrap();
                    super::super::run_local(config, None, Some(notice), None, None)
                }
            }));
            assert!(result.unwrap_err().is::<Ready>());
            assert_eq!(vault_addresses(), Err("Unlock LokiSigner to view vault addresses."));
        }
    }
}
