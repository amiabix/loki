//! One exclusive member transport session. Payment and the relay CLI share this opener.
use super::{load, ConfigStore, LoadedMember, MemberError};
use loki_relay_client::{
    open_descriptor, AuthenticatedDescriptor, ClientConfig, ClientError, ClientStore,
};
use std::{fmt, path::Path};

impl fmt::Debug for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Member(error) => write!(formatter, "{error}"),
            Self::Client(error) => write!(formatter, "{error}"),
        }
    }
}

pub struct Session {
    pub member: LoadedMember,
    pub configs: ConfigStore,
    pub db: ClientStore,
}

pub enum SessionError {
    Member(MemberError),
    Client(ClientError),
}

pub fn open_session(root: &Path, pass: &Path, roster: &Path) -> Result<Session, SessionError> {
    let member = load(root, pass, roster).map_err(SessionError::Member)?;
    let configs = ConfigStore::open(root, pass).map_err(SessionError::Member)?;
    let db = ClientStore::open(
        &root.join("transport"),
        &member.roster,
        member.identity.public().id,
    )
    .map_err(SessionError::Client)?;
    Ok(Session {
        member,
        configs,
        db,
    })
}

pub fn routed(session: &Session) -> Result<(ClientConfig, AuthenticatedDescriptor), SessionError> {
    let config = session
        .configs
        .routing(&session.db, &session.member)
        .map_err(SessionError::Member)?;
    let local = session
        .configs
        .load(&session.db, &session.member)
        .map_err(SessionError::Member)?
        .ok_or(SessionError::Member(MemberError::Sealed))?;
    let wire = local
        .self_wire
        .as_ref()
        .ok_or(SessionError::Member(MemberError::Sealed))?;
    let self_route = open_descriptor(&session.member.identity, &session.member.roster, wire)
        .map_err(SessionError::Client)?;
    Ok((config, self_route))
}
