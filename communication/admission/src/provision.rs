use crate::{AdmissionError, AdmissionResult, AdmissionStore, ProvisionIntent};
use loki_relay_client::{OperatorSet, RelayHttp, Secret32};
use loki_relay_protocol::types::RelayRoute;
use std::sync::{Arc, Mutex};

pub struct OwnedProvisioner {
    routes: [RelayRoute; 3],
    credentials: [Secret32; 3],
    http: RelayHttp,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProvisionProgress {
    pub attempted: usize,
    pub completed: usize,
}
impl OwnedProvisioner {
    pub fn new(operators: &OperatorSet, credentials: [Secret32; 3]) -> AdmissionResult<Self> {
        Self::build(operators, credentials, false)
    }
    pub fn development(
        operators: &OperatorSet,
        credentials: [Secret32; 3],
    ) -> AdmissionResult<Self> {
        Self::build(operators, credentials, true)
    }
    fn build(
        operators: &OperatorSet,
        credentials: [Secret32; 3],
        development: bool,
    ) -> AdmissionResult<Self> {
        for route in operators.relay_routes() {
            loki_relay_client::validate_endpoint(&route.endpoint, development)
                .map_err(|_| AdmissionError::Malformed)?;
        }
        Ok(Self {
            routes: operators
                .relay_routes()
                .to_vec()
                .try_into()
                .map_err(|_| AdmissionError::Malformed)?,
            credentials,
            http: RelayHttp::for_setup(operators, development)
                .map_err(|_| AdmissionError::Unavailable)?,
        })
    }
    async fn one(&self, intent: Option<&ProvisionIntent>) -> Option<bool> {
        let intent = intent?;
        let index = usize::from(intent.relay()).checked_sub(1)?;
        let mut route = self.routes.get(index)?.clone();
        route.mailbox = *intent.mailbox();
        if self
            .http
            .authenticate_endpoint(&route.pin, &route.endpoint)
            .await
            .is_err()
        {
            return Some(false);
        }
        Some(if intent.purpose() == 1 {
            self.http
                .setup_control(
                    &route,
                    &self.credentials[index],
                    intent.request(),
                    intent.expires(),
                    intent.retire(),
                )
                .await
                .is_ok()
        } else {
            self.http
                .create(&route, &self.credentials[index], intent.request())
                .await
                .is_ok()
        })
    }
    pub async fn drive_once(
        &self,
        store: &Arc<Mutex<AdmissionStore>>,
        now: u64,
    ) -> AdmissionResult<ProvisionProgress> {
        let mut intents = store
            .lock()
            .map_err(|_| AdmissionError::Unavailable)?
            .pending_retirement(now, 3)?;
        if intents.len() < 3 {
            let limit = 3 - intents.len();
            intents.extend(
                store
                    .lock()
                    .map_err(|_| AdmissionError::Unavailable)?
                    .pending(now, limit)?,
            );
        }
        let results = tokio::join!(
            self.one(intents.first()),
            self.one(intents.get(1)),
            self.one(intents.get(2))
        );
        let mut progress = ProvisionProgress::default();
        for (intent, success) in intents.iter().zip([results.0, results.1, results.2]) {
            let success = success.ok_or(AdmissionError::Storage)?;
            store
                .lock()
                .map_err(|_| AdmissionError::Unavailable)?
                .finish_provision(intent, success, now)?;
            progress.attempted += 1;
            progress.completed += usize::from(success);
        }
        Ok(progress)
    }
}
