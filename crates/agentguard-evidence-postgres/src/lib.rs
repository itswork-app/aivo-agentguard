//! PostgreSQL reference adapter for `AgentGuard` append-only evidence.
//!
//! This adapter serializes appends per stream using a PostgreSQL row lock.
//! A successful append is acknowledged only after the transaction commits.
//! Database roles used in production must deny UPDATE and DELETE on the
//! committed-events table to the application role.

use agentguard_evidence::{
    AppendOnlyEvidenceStore, EvidenceError, EvidenceEventV1, GENESIS_PREVIOUS_HASH, verify_event,
    verify_stream,
};
use postgres::{Client, NoTls};
use std::{error::Error, fmt, sync::Mutex};

#[derive(Debug)]
pub enum PostgresEvidenceStoreError {
    Database(postgres::Error),
    Serialization(serde_json::Error),
    Evidence(EvidenceError),
    LockPoisoned,
    Conflict(&'static str),
    CorruptStoredEvent,
    IntegerOutOfRange,
}

impl fmt::Display for PostgresEvidenceStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(f, "PostgreSQL evidence storage error: {error}"),
            Self::Serialization(error) => write!(f, "evidence serialization error: {error}"),
            Self::Evidence(error) => write!(f, "evidence validation error: {error}"),
            Self::LockPoisoned => f.write_str("PostgreSQL client lock was poisoned"),
            Self::Conflict(reason) => write!(f, "evidence append conflict: {reason}"),
            Self::CorruptStoredEvent => f.write_str("stored evidence payload is corrupt"),
            Self::IntegerOutOfRange => f.write_str("evidence sequence exceeds PostgreSQL BIGINT"),
        }
    }
}

impl Error for PostgresEvidenceStoreError {}

impl From<postgres::Error> for PostgresEvidenceStoreError {
    fn from(value: postgres::Error) -> Self {
        Self::Database(value)
    }
}

impl From<serde_json::Error> for PostgresEvidenceStoreError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value)
    }
}

impl From<EvidenceError> for PostgresEvidenceStoreError {
    fn from(value: EvidenceError) -> Self {
        Self::Evidence(value)
    }
}

/// A synchronous PostgreSQL store. Clone by constructing another instance
/// from the same connection string; PostgreSQL row locks coordinate instances.
pub struct PostgresEvidenceStore {
    client: Mutex<Client>,
    authenticated_tenant_id: String,
}

impl PostgresEvidenceStore {
    /// Connects a tenant-scoped store to PostgreSQL. The tenant ID must come
    /// from authenticated server-side identity, never directly from request data.
    /// Apply the checked-in migration before use. This convenience constructor
    /// uses `NoTls` and is intended for local development and CI only.
    ///
    /// # Errors
    /// Returns an error when the tenant scope is empty or the connection fails.
    pub fn connect(
        connection_string: &str,
        authenticated_tenant_id: &str,
    ) -> Result<Self, PostgresEvidenceStoreError> {
        if authenticated_tenant_id.trim().is_empty() {
            return Err(PostgresEvidenceStoreError::Conflict(
                "authenticated tenant scope is required",
            ));
        }
        let client = Client::connect(connection_string, NoTls)?;
        Ok(Self {
            client: Mutex::new(client),
            authenticated_tenant_id: authenticated_tenant_id.to_owned(),
        })
    }

    /// Constructs a tenant-scoped store from a TLS-configured PostgreSQL client.
    ///
    /// # Errors
    /// Returns an error when the authenticated tenant scope is empty.
    pub fn from_client(
        client: Client,
        authenticated_tenant_id: &str,
    ) -> Result<Self, PostgresEvidenceStoreError> {
        if authenticated_tenant_id.trim().is_empty() {
            return Err(PostgresEvidenceStoreError::Conflict(
                "authenticated tenant scope is required",
            ));
        }
        Ok(Self {
            client: Mutex::new(client),
            authenticated_tenant_id: authenticated_tenant_id.to_owned(),
        })
    }

    fn lock_client(&self) -> Result<std::sync::MutexGuard<'_, Client>, PostgresEvidenceStoreError> {
        self.client
            .lock()
            .map_err(|_| PostgresEvidenceStoreError::LockPoisoned)
    }

    fn verify_existing_event(
        transaction: &mut postgres::Transaction<'_>,
        event: &EvidenceEventV1,
        payload: &[u8],
    ) -> Result<bool, PostgresEvidenceStoreError> {
        let Some(existing) = transaction.query_opt(
            "SELECT sequence, previous_event_hash, event_hash, payload_bytes
             FROM agentguard_evidence_events
             WHERE tenant_id = $1 AND stream_id = $2 AND event_id = $3",
            &[&event.tenant_id, &event.stream_id, &event.event_id],
        )? else {
            return Ok(false);
        };
        let stored_sequence: i64 = existing.get(0);
        let stored_previous_hash: String = existing.get(1);
        let stored_event_hash: String = existing.get(2);
        let existing_payload: Vec<u8> = existing.get(3);
        let stored_event: EvidenceEventV1 = serde_json::from_slice(&existing_payload)
            .map_err(|_| PostgresEvidenceStoreError::CorruptStoredEvent)?;
        verify_event(&stored_event)?;
        if stored_event.tenant_id != event.tenant_id
            || stored_event.stream_id != event.stream_id
            || i64::try_from(stored_event.sequence).ok() != Some(stored_sequence)
            || stored_event.event_id != event.event_id
            || stored_event.previous_event_hash != stored_previous_hash
            || stored_event.event_hash != stored_event_hash
        {
            return Err(PostgresEvidenceStoreError::CorruptStoredEvent);
        }
        if existing_payload == payload {
            return Ok(true);
        }
        Err(PostgresEvidenceStoreError::Conflict(
            "event ID reused with different payload",
        ))
    }
}

impl AppendOnlyEvidenceStore for PostgresEvidenceStore {
    type Error = PostgresEvidenceStoreError;

    fn append(&self, event: EvidenceEventV1) -> Result<(), Self::Error> {
        if event.tenant_id != self.authenticated_tenant_id {
            return Err(PostgresEvidenceStoreError::Conflict(
                "event tenant does not match authenticated tenant scope",
            ));
        }
        verify_event(&event)?;
        let sequence = i64::try_from(event.sequence)
            .map_err(|_| PostgresEvidenceStoreError::IntegerOutOfRange)?;
        let payload = serde_json::to_vec(&event)?;
        let mut client = self.lock_client()?;
        let mut transaction = client.transaction()?;

        transaction.execute(
            "INSERT INTO agentguard_evidence_stream_heads
                (tenant_id, stream_id, last_sequence, last_event_hash)
             VALUES ($1, $2, 0, $3)
             ON CONFLICT (tenant_id, stream_id) DO NOTHING",
            &[&event.tenant_id, &event.stream_id, &GENESIS_PREVIOUS_HASH],
        )?;

        let head = transaction.query_one(
            "SELECT last_sequence, last_event_hash
             FROM agentguard_evidence_stream_heads
             WHERE tenant_id = $1 AND stream_id = $2
             FOR UPDATE",
            &[&event.tenant_id, &event.stream_id],
        )?;
        let last_sequence: i64 = head.get(0);
        let last_hash: String = head.get(1);

        // Exact retries are idempotent; a reused ID with different bytes is a conflict.
        if Self::verify_existing_event(&mut transaction, &event, &payload)? {
            transaction.commit()?;
            return Ok(());
        }

        let expected_sequence = last_sequence
            .checked_add(1)
            .ok_or(PostgresEvidenceStoreError::IntegerOutOfRange)?;
        if sequence != expected_sequence {
            return Err(PostgresEvidenceStoreError::Conflict(
                "sequence is not the next stream sequence",
            ));
        }
        if event.previous_event_hash != last_hash {
            return Err(PostgresEvidenceStoreError::Conflict(
                "predecessor hash does not match committed stream head",
            ));
        }

        transaction.execute(
            "INSERT INTO agentguard_evidence_events
                (tenant_id, stream_id, sequence, event_id, previous_event_hash, event_hash, payload_bytes)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[
                &event.tenant_id,
                &event.stream_id,
                &sequence,
                &event.event_id,
                &event.previous_event_hash,
                &event.event_hash,
                &payload,
            ],
        )?;
        let changed = transaction.execute(
            "UPDATE agentguard_evidence_stream_heads
             SET last_sequence = $3, last_event_hash = $4
             WHERE tenant_id = $1 AND stream_id = $2 AND last_sequence = $5",
            &[
                &event.tenant_id,
                &event.stream_id,
                &sequence,
                &event.event_hash,
                &last_sequence,
            ],
        )?;
        if changed != 1 {
            return Err(PostgresEvidenceStoreError::Conflict(
                "stream head compare-and-swap failed",
            ));
        }
        transaction.commit()?;
        Ok(())
    }

    fn read_stream(
        &self,
        tenant_id: &str,
        stream_id: &str,
    ) -> Result<Vec<EvidenceEventV1>, Self::Error> {
        if tenant_id != self.authenticated_tenant_id {
            return Err(PostgresEvidenceStoreError::Conflict(
                "requested tenant does not match authenticated tenant scope",
            ));
        }
        if stream_id.trim().is_empty() {
            return Err(PostgresEvidenceStoreError::Conflict(
                "stream ID is required",
            ));
        }
        let mut client = self.lock_client()?;
        let mut transaction = client
            .build_transaction()
            .isolation_level(postgres::IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()?;
        let rows = transaction.query(
            "SELECT sequence, event_id, previous_event_hash, event_hash, payload_bytes
             FROM agentguard_evidence_events
             WHERE tenant_id = $1 AND stream_id = $2
             ORDER BY sequence ASC",
            &[&tenant_id, &stream_id],
        )?;
        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            let stored_sequence: i64 = row.get(0);
            let stored_event_id: String = row.get(1);
            let stored_previous_hash: String = row.get(2);
            let stored_event_hash: String = row.get(3);
            let payload: Vec<u8> = row.get(4);
            let event: EvidenceEventV1 = serde_json::from_slice(&payload)
                .map_err(|_| PostgresEvidenceStoreError::CorruptStoredEvent)?;
            if event.tenant_id != tenant_id
                || event.stream_id != stream_id
                || i64::try_from(event.sequence).ok() != Some(stored_sequence)
                || event.event_id != stored_event_id
                || event.previous_event_hash != stored_previous_hash
                || event.event_hash != stored_event_hash
            {
                return Err(PostgresEvidenceStoreError::CorruptStoredEvent);
            }
            events.push(event);
        }
        let head = transaction.query_opt(
            "SELECT last_sequence, last_event_hash
             FROM agentguard_evidence_stream_heads
             WHERE tenant_id = $1 AND stream_id = $2",
            &[&tenant_id, &stream_id],
        )?;
        match (head, events.last()) {
            (None, None) => {}
            (Some(row), Some(last)) => {
                let head_sequence: i64 = row.get(0);
                let head_hash: String = row.get(1);
                if i64::try_from(events.len()).ok() != Some(head_sequence)
                    || last.event_hash != head_hash
                {
                    return Err(PostgresEvidenceStoreError::CorruptStoredEvent);
                }
            }
            _ => return Err(PostgresEvidenceStoreError::CorruptStoredEvent),
        }
        verify_stream(&events)?;
        transaction.commit()?;
        Ok(events)
    }
}
