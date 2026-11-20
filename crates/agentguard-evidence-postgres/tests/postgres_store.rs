use agentguard_evidence::{
    ActorRefV1, AppendOnlyEvidenceStore, DecisionOutcome, EvidenceEventDraftV1, EvidenceEventType,
    GENESIS_PREVIOUS_HASH, seal_event,
};
use agentguard_evidence_postgres::PostgresEvidenceStore;
use postgres::{Client, NoTls};
use std::time::{SystemTime, UNIX_EPOCH};

fn database_url() -> Option<String> {
    std::env::var("DATABASE_URL").ok()
}

fn unique_id(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    format!("{prefix}-{nanos}")
}

fn draft(tenant: &str, stream: &str, sequence: u64, event_id: &str) -> EvidenceEventDraftV1 {
    EvidenceEventDraftV1 {
        schema_version: "agentguard.evidence-v1".to_owned(),
        event_id: event_id.to_owned(),
        tenant_id: tenant.to_owned(),
        stream_id: stream.to_owned(),
        sequence,
        occurred_at: "2026-11-20T00:00:00Z".to_owned(),
        event_type: if sequence == 1 {
            EvidenceEventType::RequestReceived
        } else {
            EvidenceEventType::DecisionRecorded
        },
        request_id: "request-integration".to_owned(),
        actor_ref: ActorRefV1 {
            kind: "service".to_owned(),
            id: "integration-test".to_owned(),
        },
        request_digest: None,
        action_digest: None,
        policy_digest: None,
        decision: if sequence == 1 {
            None
        } else {
            Some(DecisionOutcome::Deny)
        },
        reason_codes: Vec::new(),
        correction_of_event_id: None,
    }
}

#[test]
fn postgres_append_is_atomic_idempotent_and_tenant_scoped() {
    let Some(url) = database_url() else {
        eprintln!("DATABASE_URL not set; PostgreSQL integration test skipped");
        return;
    };
    let mut migration_client = Client::connect(&url, NoTls).expect("connect migration client");
    migration_client
        .batch_execute(include_str!("../migrations/0001_evidence_store.sql"))
        .expect("apply migration");

    let tenant = unique_id("tenant");
    let stream = unique_id("stream");
    let store = PostgresEvidenceStore::connect(&url, &tenant).expect("connect evidence store");

    let first = seal_event(draft(&tenant, &stream, 1, "event-1"), GENESIS_PREVIOUS_HASH)
        .expect("seal first event");
    store.append(first.clone()).expect("append first event");
    store
        .append(first.clone())
        .expect("exact retry must be idempotent");

    let second = seal_event(draft(&tenant, &stream, 2, "event-2"), &first.event_hash)
        .expect("seal second event");
    store.append(second.clone()).expect("append second event");

    let events = store.read_stream(&tenant, &stream).expect("read stream");
    assert_eq!(events, vec![first.clone(), second.clone()]);

    assert!(
        store
            .read_stream(&unique_id("other-tenant"), &stream)
            .is_err()
    );
    let other_tenant_id = unique_id("other-tenant");
    let other_store =
        PostgresEvidenceStore::connect(&url, &other_tenant_id).expect("connect other tenant scope");
    assert!(
        other_store
            .read_stream(&other_tenant_id, &stream)
            .expect("isolated tenant read")
            .is_empty()
    );

    let mut conflicting_draft = draft(&tenant, &stream, 1, "event-1");
    conflicting_draft.reason_codes.push("tampered".to_owned());
    let reused_id =
        seal_event(conflicting_draft, GENESIS_PREVIOUS_HASH).expect("seal conflicting payload");
    // Same event identity with different canonical bytes must never be accepted.
    assert!(store.append(reused_id).is_err());

    let gap = seal_event(draft(&tenant, &stream, 4, "event-gap"), &second.event_hash)
        .expect("seal sequence gap");
    assert!(store.append(gap).is_err());

    let tampered_hash = "f".repeat(64);
    let first_event_id = "event-1".to_owned();
    migration_client
        .execute(
            "UPDATE agentguard_evidence_events
             SET event_hash = $1
             WHERE tenant_id = $2 AND stream_id = $3 AND event_id = $4",
            &[&tampered_hash, &tenant, &stream, &first_event_id],
        )
        .expect("tamper denormalized event hash column");
    assert!(
        store.read_stream(&tenant, &stream).is_err(),
        "read must detect indexed-column and sealed-payload disagreement"
    );
}

#[test]
fn postgres_serializes_concurrent_writers_across_connections() {
    let Some(url) = database_url() else {
        eprintln!("DATABASE_URL not set; PostgreSQL integration test skipped");
        return;
    };
    let mut migration_client = Client::connect(&url, NoTls).expect("connect migration client");
    migration_client
        .batch_execute(include_str!("../migrations/0001_evidence_store.sql"))
        .expect("apply migration");

    let tenant = unique_id("tenant-concurrent");
    let stream = unique_id("stream-concurrent");
    let store_a = PostgresEvidenceStore::connect(&url, &tenant).expect("connect writer A");
    let store_b = PostgresEvidenceStore::connect(&url, &tenant).expect("connect writer B");

    let event_a = seal_event(
        draft(&tenant, &stream, 1, "concurrent-event-a"),
        GENESIS_PREVIOUS_HASH,
    )
    .expect("seal concurrent event A");
    let event_b = seal_event(
        draft(&tenant, &stream, 1, "concurrent-event-b"),
        GENESIS_PREVIOUS_HASH,
    )
    .expect("seal concurrent event B");

    let writer_a = std::thread::spawn(move || store_a.append(event_a));
    let writer_b = std::thread::spawn(move || store_b.append(event_b));
    let result_a = writer_a.join().expect("writer A thread");
    let result_b = writer_b.join().expect("writer B thread");

    assert_ne!(
        result_a.is_ok(),
        result_b.is_ok(),
        "exactly one competing first append may commit"
    );

    let reader = PostgresEvidenceStore::connect(&url, &tenant).expect("connect reader");
    let events = reader
        .read_stream(&tenant, &stream)
        .expect("read concurrently written stream");
    assert_eq!(events.len(), 1, "the stream must contain one committed event");

    reader
        .append(events[0].clone())
        .expect("retry of the committed event must be idempotent");
    assert_eq!(
        reader
            .read_stream(&tenant, &stream)
            .expect("read after idempotent retry")
            .len(),
        1
    );
}
