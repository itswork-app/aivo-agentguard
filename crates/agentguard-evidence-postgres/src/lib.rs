//! PostgreSQL reference adapter for AgentGuard append-only evidence.
//!
//! This adapter serializes appends per stream using a PostgreSQL row lock.
//! A successful append is acknowledged only after the transaction commits.
//! Database roles used in production must deny UPDATE and DELETE on the
//! committed-events table to the application role.

use agentguard_evidence::{
    verify_event, verify_stream, AppendOnlyEvidenceStore, EvidenceError, EvidenceEventV1,
    GENESIS_PREVIOUS_HASH,
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
    fn from(value: postgres::Error) -> Self { Self::Database(value) }
}
impl From<serde_json::Error> for PostgresEvidenceStoreError {
    fn from(value: serde_json::Error) -> Self { Self::Serialization(value) }
}
impl From<EvidenceError> for PostgresEvidenceStoreError {
    fn from(value: EvidenceError) -> Self { Self::Evidence(value) }
}

/// A synchronous PostgreSQL store. Clone by constructing another instance
/// from the same connection string; PostgreSQL row locks coordinate instances.
pub struct PostgresEvidenceStore {
    client: Mutex<Client>,
}

impl PostgresEvidenceStore {
    /// Connects to PostgreSQL. Apply the checked-in migration before use.
    ///
    /// # Errors
    /// Returns a database error when the connection cannot be established.
    pub fn connect(connection_string: &str) -> Result<Self, PostgresEvidenceStoreError> {
        let client = Client::connect(connection_string, NoTls)?;
        Ok(Self { client: Mutex::new(client) })
    }

    /// Constructs a store from an already configured PostgreSQL client.
    #[must_use]
    pub fn from_client(client: Client) -> Self {
        Self { client: Mutex::new(client) }
    }

    fn lock_client(&self) -> Result<std::sync::MutexGuard<'_, Client>, PostgresEvidenceStoreError> {
        self.client.lock().map_err(|_| PostgresEvidenceStoreError::LockPoisoned)
    }
}

impl AppendOnlyEvidenceStore for PostgresEvidenceStore {
    type Error = PostgresEvidenceStoreError;

    fn append(&self, event: EvidenceEventV1) -> Result<(), Self::Error> {
        verify_event(&event)?;
        let sequence = i64::try_from(event.sequence)
            .map_err(|_| PostgresEvidenceStoreError::IntegerOutOfRange)?;
        let payload = serde_json::to_vec(&event)?;
        let mut client = self.lock_client()?;
        let mut transaction = client.transaction()?;

        transaction.execute(
            "INSERT INTO agentguard_evidence_stream_heads              (tenant_id, stream_id, last_sequence, last_event_hash)              VALUES ($1, $2, 0, $3) ON CONFLICT (tenant_id, stream_id) DO NOTHING",
            &[&event.tenant_id, &event.stream_id, &GENESIS_PREVIOUS_HASH],
        )?;

        let head = transaction.query_one(
            "SELECT last_sequence, last_event_hash FROM agentguard_evidence_stream_heads              WHERE tenant_id = $1 AND stream_id = $2 FOR UPDATE",
            &[&event.tenant_id, &event.stream_id],
        )?;
        let last_sequence: i64 = head.get(0);
        let last_hash: String = head.get(1);

        // Exact retries are idempotent; a reused ID with different bytes is a conflict.
        if let Some(existing) = transaction.query_opt(
            "SELECT payload_bytes FROM agentguard_evidence_events              WHERE tenant_id = $1 AND stream_id = $2 AND event_id = $3",
            &[&event.tenant_id, &event.stream_id, &event.event_id],
        )? {
            let existing_payload: Vec<u8> = existing.get(0);
            if existing_payload == payload {
                transaction.commit()?;
                return Ok(());
            }
            return Err(PostgresEvidenceStoreError::Conflict("event ID reused with different payload"));
        }

        let expected_sequence = last_sequence.checked_add(1)
            .ok_or(PostgresEvidenceStoreError::IntegerOutOfRange)?;
        if sequence != expected_sequence {
            return Err(PostgresEvidenceStoreError::Conflict("sequence is not the next stream sequence"));
        }
        if event.previous_event_hash != last_hash {
            return Err(PostgresEvidenceStoreError::Conflict("predecessor hash does not match committed stream head"));
        }

        transaction.execute(
            "INSERT INTO agentguard_evidence_events              (tenant_id, stream_id, sequence, event_id, previous_event_hash, event_hash, payload_bytes)              VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[&event.tenant_id, &event.stream_id, &sequence, &event.event_id,
              &event.previous_event_hash, &event.event_hash, &payload],
        )?;
        let changed = transaction.execute(
            "UPDATE agentguard_evidence_stream_heads              SET last_sequence = $3, last_event_hash = $4              WHERE tenant_id = $1 AND stream_id = $2 AND last_sequence = $5",
            &[&event.tenant_id, &event.stream_id, &sequence, &event.event_hash, &last_sequence],
        )?;
        if changed != 1 {
            return Err(PostgresEvidenceStoreError::Conflict("stream head compare-and-swap failed"));
        }
        transaction.commit()?;
        Ok(())
    }

    fn read_stream(
        &self,
        tenant_id: &str,
        stream_id: &str,
    ) -> Result<Vec<EvidenceEventV1>, Self::Error> {
        if tenant_id.trim().is_empty() || stream_id.trim().is_empty() {
            return Err(PostgresEvidenceStoreError::Conflict("tenant and stream IDs are required"));
        }
        let mut client = self.lock_client()?;
        let mut transaction = client.build_transaction()
            .isolation_level(postgres::IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()?;
        let rows = transaction.query(
            "SELECT payload_bytes FROM agentguard_evidence_events              WHERE tenant_id = $1 AND stream_id = $2 ORDER BY sequence ASC",
            &[&tenant_id, &stream_id],
        )?;
        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            let payload: Vec<u8> = row.get(0);
            let event: EvidenceEventV1 = serde_json::from_slice(&payload)
                .map_err(|_| PostgresEvidenceStoreError::CorruptStoredEvent)?;
            if event.tenant_id != tenant_id || event.stream_id != stream_id {
                return Err(PostgresEvidenceStoreError::CorruptStoredEvent);
            }
            events.push(event);
        }
        verify_stream(&events)?;
        transaction.commit()?;
        Ok(events)
    }
}
