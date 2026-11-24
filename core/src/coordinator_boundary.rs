pub use crate::signer::{CandidateRef, Connection, Network, Session, Signer, VaultRef};

pub fn assert_keyless<E>(signers: &[&dyn Signer<Error = E>], session: &Session) {
    for s in signers {
        let _public: Result<Vec<VaultRef>, E> = s.list_vaults(session);
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    #[test]
    fn coordinator_source_links_no_secret_type() {
        let src = std::fs::read_to_string(Path::new(file!()))
            .or_else(|_| std::fs::read_to_string("core/src/coordinator_boundary.rs"))
            .or_else(|_| std::fs::read_to_string("src/coordinator_boundary.rs"))
            .expect("read coordinator_boundary.rs");
        let shipped = src.split("#[cfg(test)]").next().unwrap_or("");
        let code: String = shipped
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");

        let forbidden = [
            "KeyPackage",
            "SigningNonces",
            "signing_share",
            "SpendingKey",
            "SpendAuthorizingKey",
            "member_state",
            "MemberState",
            "signing_session",
            "read_sealed",
            "SecretKey",
            "SealedShare",
            "LocalSigner",
        ];
        for needle in forbidden {
            assert!(
                !code.contains(needle),
                "coordinator must not link secret type `{needle}` (keyless invariant #1)"
            );
        }
    }

    #[test]
    fn coordinator_drive_loop_is_viewing_key_less() {
        let src = std::fs::read_to_string(Path::new(
            "loki-signer-core/src/signer/coordination.rs",
        ))
        .or_else(|_| {
            std::fs::read_to_string("core/loki-signer-core/src/signer/coordination.rs")
        })
        .or_else(|_| {
            std::fs::read_to_string(
                Path::new(file!())
                    .parent()
                    .unwrap()
                    .join("../loki-signer-core/src/signer/coordination.rs"),
            )
        })
        .expect("read coordination.rs");
        let shipped = src.split("#[cfg(test)]").next().unwrap_or("");
        let code: String = shipped
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");

        let forbidden = [
            "FullViewingKey",
            "IncomingViewingKey",
            "OutgoingViewingKey",
            "CandidateInputs",
            "quote_fee",
            "intent.note",
            "vault_fvk",
        ];
        for needle in forbidden {
            assert!(
                !code.contains(needle),
                "coordinator drive loop must be viewing-key-less: found `{needle}`"
            );
        }
    }

    #[test]
    fn assert_keyless_accepts_public_only_surface() {
        use crate::signer::{Session, VaultRef};
        struct Dummy;
        impl crate::signer::Signer for Dummy {
            type Error = ();
            fn connect(
                &mut self,
                _: &str,
                _: crate::signer::Network,
                _: &[u8],
            ) -> Result<crate::signer::Connection, ()> {
                Err(())
            }
            fn list_vaults(&self, _: &Session) -> Result<Vec<VaultRef>, ()> {
                Ok(vec![])
            }
            fn dkg_begin(&mut self, _: &Session, _: &[u8]) -> Result<VaultRef, ()> {
                Err(())
            }
            fn dkg_step(
                &mut self,
                _: &Session,
                _: &VaultRef,
                _: &[crate::signer::DkgInput],
            ) -> Result<Vec<crate::signer::DkgWire>, ()> {
                Ok(vec![])
            }
            fn backup(&mut self, _: &Session) -> Result<Vec<crate::signer::DkgWire>, ()> {
                Err(())
            }
            fn release_address(
                &mut self,
                _: &Session,
            ) -> Result<crate::signer::ReleasedAddress, ()> {
                Err(())
            }
            fn build_candidate(
                &self,
                _: &Session,
                _: &crate::signer::CandidateRef,
                _: &crate::signer::PublicPaymentParams,
                _: &[[u8; 32]],
            ) -> Result<crate::signer::CandidatePczt, ()> {
                Err(())
            }
            fn sign_commit(
                &mut self,
                _: &Session,
                _: &crate::signer::CandidateRef,
            ) -> Result<reddsa_frost::frost::redpallas::round1::SigningCommitments, ()> {
                Err(())
            }
            fn sign_approve(
                &mut self,
                _: &Session,
                _: &crate::signer::CandidateRef,
                _: &crate::signer::PublicPaymentParams,
                _: &[u8],
                _: &reddsa_frost::frost::redpallas::SigningPackage,
                _: &[u8],
            ) -> Result<reddsa_frost::frost::redpallas::round2::SignatureShare, ()> {
                Err(())
            }
            fn disconnect(&mut self, _: Session) -> Result<(), ()> {
                Ok(())
            }
        }
        let d = Dummy;
        super::assert_keyless(&[&d], &Session([0u8; 32]));
    }
}
