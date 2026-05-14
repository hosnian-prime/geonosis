//! Postgres-backed audit sink.
//!
//! Inserts each event into the partitioned `audit_event` table (created
//! by `geonosis-migrate`). Insertion is bounded by the same connection
//! pool the storage layer uses; failures are logged and re-tried on
//! the next event (Postgres being unavailable does NOT block the
//! producing request — `Publisher` calls the sink off the hot path).

use async_trait::async_trait;
use sqlx::postgres::PgPool;

use crate::{AuditEvent, AuditError, AuditSink};

pub struct PostgresAuditSink {
    pool: PgPool,
}

impl PostgresAuditSink {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AuditSink for PostgresAuditSink {
    async fn ingest(&self, event: AuditEvent) -> Result<(), AuditError> {
        let actor = serde_json::to_value(&event.actor)
            .map_err(|e| AuditError::Backend(format!("actor serde: {e}")))?;
        let target = event
            .target
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|e| AuditError::Backend(format!("target serde: {e}")))?;

        sqlx::query(
            "INSERT INTO audit_event (id, realm_id, occurred_at, actor, action, target, detail)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(event.id.to_string())
        .bind(event.realm_id.to_string())
        .bind(event.occurred_at)
        .bind(actor)
        .bind(&event.action)
        .bind(target)
        .bind(&event.detail)
        .execute(&self.pool)
        .await
        .map_err(|e| AuditError::Backend(e.to_string()))?;
        Ok(())
    }
}

