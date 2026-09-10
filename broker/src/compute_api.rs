//! HTTP surface of the compute-contention feature: the two controller
//! ingest endpoints and the five read endpoints
//! (docs/design/compute-contention-monitoring.md, D5 / D7 / "Read
//! endpoints"; wire names per the compute contract).
//!
//! Ingest:
//! - `POST /pod/compute/batch` — every sample interval, one per node.
//!   Upserts `pod_compute_latest` (PK `container_uid`) and
//!   `node_compute_latest` (PK `node`), so neither table grows with
//!   cadence.
//! - `POST /pod/compute/history/batch` — every 60 s. Inserts one
//!   `pod_compute_history` row per container and one
//!   `pod_contention_history` row per blame pair. Silently accepted and
//!   dropped when `COMPUTE_HISTORY_RETENTION_DAYS=0` (history off).
//!
//! Reads: every GET validates its query first (a 400 must not wait on the
//! budget), then acquires a `ReadPermit` charged at
//! `COMPUTE_ROW_COST_BYTES` x the endpoint's row cap, held across the
//! query and the serialise. The caps are what bound the response, so the
//! charge is exact rather than guessed from the table size.

use actix_web::{get, post, web, Error, HttpResponse, Responder};
use chrono::NaiveDateTime;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use diesel::upsert::excluded;
use serde::Serialize;
use tracing::{debug, info};

use crate::compute::{compute_findings, ComputeThresholds, WINDOW_MINUTES};
use crate::compute_types::{
    Accepted, ComputeBatch, ComputeHistoryBatch, Finding, NewPodComputeHistory, NewPodContention,
    NodeComputeLatest, PodComputeHistoryRow, PodComputeLatest, PodContentionRow,
};
use crate::read_budget::{cost_kib, ReadBudget, COMPUTE_ROW_COST_BYTES};
use crate::retention::compute_history_retention_days;
use crate::schema;

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
type DbError = Box<dyn std::error::Error + Send + Sync>;

/// Rows per INSERT statement. Postgres caps bind parameters at 65 535
/// and a history row binds 46 of them, so 500 rows is ~23 000 binds —
/// comfortably inside, and a batch from a 110-pod node never chunks.
const INSERT_CHUNK: usize = 500;

/// `GET /compute/latest` row cap and charge: one row per live container
/// in the namespace. 5 000 matches `ASSUMED_MAX_PODS` — a namespace
/// larger than that is truncated, and charged for what it can return.
pub const LATEST_ROW_CAP: i64 = 5_000;
/// `GET /compute/history/{pod_uid}` hard row cap (see
/// [`history_row_limit`]).
pub const HISTORY_ROW_CAP: i64 = 20_000;
/// Longest history window, minutes (7 days — the retention default).
pub const HISTORY_MAX_MINUTES: i64 = 10_080;
/// Pairs kept per victim by `GET /compute/contention` (contract).
pub const CONTENTION_PER_VICTIM: i64 = 50;
/// `GET /compute/contention` overall row cap and charge.
pub const CONTENTION_ROW_CAP: i64 = 10_000;
/// History rows the findings engine is fed: 500 victims (the design's
/// per-call cap) x 5 minute rows x 2 for culprit rows on the same nodes.
pub const FINDINGS_HISTORY_ROW_CAP: i64 = 5_000;
/// Contention rows the findings engine is fed: 500 victims x 10 pairs x
/// 2 minutes of slack over the 5-minute window's top-10 lists.
pub const FINDINGS_PAIR_ROW_CAP: i64 = 10_000;
/// `GET /compute/nodes` charge; the table is node-count sized.
pub const NODES_ROWS_CHARGED: i64 = 512;

// ---------------------------------------------------------------------
// Ingest
// ---------------------------------------------------------------------

/// Header validation shared by both ingest envelopes. Pure for tests.
pub(crate) fn validate_envelope(node: &str, interval_ms: i64) -> Result<(), &'static str> {
    if node.trim().is_empty() {
        return Err("node must not be empty");
    }
    if node.len() > 253 {
        return Err("node too long");
    }
    if interval_ms <= 0 {
        return Err("interval_ms must be positive");
    }
    Ok(())
}

#[post("/pod/compute/batch")]
pub async fn add_compute_batch(
    pool: web::Data<DbPool>,
    form: web::Json<ComputeBatch>,
) -> Result<HttpResponse, Error> {
    let batch = form.into_inner();
    if let Err(msg) = validate_envelope(&batch.node, batch.interval_ms) {
        return Ok(HttpResponse::BadRequest().body(msg));
    }
    let now = chrono::Utc::now().naive_utc();
    let node_row = NodeComputeLatest::from_batch(&batch, now);
    // Dedup on the PK: two samples for one container in a batch would
    // make ON CONFLICT DO UPDATE touch the same row twice, which
    // Postgres rejects. Last one wins.
    let mut rows: Vec<PodComputeLatest> = Vec::with_capacity(batch.containers.len());
    for c in &batch.containers {
        if c.container_uid.trim().is_empty() || c.container_uid.len() > 512 {
            continue;
        }
        let row = PodComputeLatest::from_sample(&batch, c, now);
        match rows
            .iter_mut()
            .find(|r| r.container_uid == row.container_uid)
        {
            Some(existing) => *existing = row,
            None => rows.push(row),
        }
    }
    let accepted = rows.len();
    debug!(
        node = %batch.node,
        containers = accepted,
        "compute batch received"
    );

    web::block(move || -> Result<(), DbError> {
        let mut conn = pool.get()?;
        conn.transaction::<_, DbError, _>(|conn| {
            upsert_node(conn, &node_row)?;
            for chunk in rows.chunks(INSERT_CHUNK) {
                upsert_latest(conn, chunk)?;
            }
            Ok(())
        })
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(Accepted { accepted }))
}

fn upsert_node(conn: &mut PgConnection, row: &NodeComputeLatest) -> Result<(), DbError> {
    use schema::node_compute_latest::dsl::*;
    diesel::insert_into(node_compute_latest)
        .values(row)
        .on_conflict(node)
        .do_update()
        .set(row)
        .execute(conn)?;
    Ok(())
}

/// One statement per chunk: `INSERT ... ON CONFLICT (container_uid) DO
/// UPDATE SET <every column> = EXCLUDED.<column>`. This is the 5 s hot
/// path for every node, so it is one round-trip per node per interval
/// rather than one per container.
fn upsert_latest(conn: &mut PgConnection, rows: &[PodComputeLatest]) -> Result<(), DbError> {
    use schema::pod_compute_latest::dsl::*;
    if rows.is_empty() {
        return Ok(());
    }
    diesel::insert_into(pod_compute_latest)
        .values(rows)
        .on_conflict(container_uid)
        .do_update()
        .set((
            pod_uid.eq(excluded(pod_uid)),
            namespace.eq(excluded(namespace)),
            pod_name.eq(excluded(pod_name)),
            container.eq(excluded(container)),
            node.eq(excluded(node)),
            cgroup_id.eq(excluded(cgroup_id)),
            ts.eq(excluded(ts)),
            interval_ms.eq(excluded(interval_ms)),
            cpu_usage_millis.eq(excluded(cpu_usage_millis)),
            cpu_quota_usec.eq(excluded(cpu_quota_usec)),
            cpu_period_usec.eq(excluded(cpu_period_usec)),
            cpu_request_millis.eq(excluded(cpu_request_millis)),
            cpu_limit_millis.eq(excluded(cpu_limit_millis)),
            cpu_nr_periods.eq(excluded(cpu_nr_periods)),
            cpu_nr_throttled.eq(excluded(cpu_nr_throttled)),
            cpu_throttled_usec.eq(excluded(cpu_throttled_usec)),
            cpu_psi_some10.eq(excluded(cpu_psi_some10)),
            cpu_psi_full10.eq(excluded(cpu_psi_full10)),
            mem_current.eq(excluded(mem_current)),
            mem_working_set.eq(excluded(mem_working_set)),
            mem_limit.eq(excluded(mem_limit)),
            mem_request.eq(excluded(mem_request)),
            mem_psi_some10.eq(excluded(mem_psi_some10)),
            mem_psi_full10.eq(excluded(mem_psi_full10)),
            mem_events_high.eq(excluded(mem_events_high)),
            mem_events_max.eq(excluded(mem_events_max)),
            mem_oom_kill.eq(excluded(mem_oom_kill)),
            mem_refault.eq(excluded(mem_refault)),
            mem_pgmajfault.eq(excluded(mem_pgmajfault)),
            runq_count.eq(excluded(runq_count)),
            runq_p50_us.eq(excluded(runq_p50_us)),
            runq_p95_us.eq(excluded(runq_p95_us)),
            runq_p99_us.eq(excluded(runq_p99_us)),
            runq_max_us.eq(excluded(runq_max_us)),
            runq_overflow.eq(excluded(runq_overflow)),
            blame.eq(excluded(blame)),
            updated_at.eq(excluded(updated_at)),
        ))
        .execute(conn)?;
    Ok(())
}

#[post("/pod/compute/history/batch")]
pub async fn add_compute_history_batch(
    pool: web::Data<DbPool>,
    form: web::Json<ComputeHistoryBatch>,
) -> Result<HttpResponse, Error> {
    let batch = form.into_inner();
    if let Err(msg) = validate_envelope(&batch.node, batch.interval_ms) {
        return Ok(HttpResponse::BadRequest().body(msg));
    }
    if batch.resolution_secs <= 0 {
        return Ok(HttpResponse::BadRequest().body("resolution_secs must be positive"));
    }
    // History off: accept and drop. The controller keeps sending (it
    // does not know the broker's retention setting) and must not see
    // errors for a deliberate operator choice.
    if compute_history_retention_days() == 0 {
        debug!(node = %batch.node, "compute history disabled; batch dropped");
        return Ok(HttpResponse::Ok().json(Accepted { accepted: 0 }));
    }
    let mut rows: Vec<NewPodComputeHistory> = Vec::with_capacity(batch.containers.len());
    let mut pairs: Vec<NewPodContention> = Vec::new();
    for c in &batch.containers {
        if c.container_uid.trim().is_empty() || c.container_uid.len() > 512 {
            continue;
        }
        rows.push(NewPodComputeHistory::from_history(&batch, c));
        for b in &c.blame {
            if b.kind.is_empty() || b.wait_ns <= 0 {
                continue;
            }
            pairs.push(NewPodContention::from_blame(&batch, c, b));
        }
    }
    let accepted = rows.len();
    let pair_count = pairs.len();

    web::block(move || -> Result<(), DbError> {
        let mut conn = pool.get()?;
        conn.transaction::<_, DbError, _>(|conn| {
            for chunk in rows.chunks(INSERT_CHUNK) {
                diesel::insert_into(schema::pod_compute_history::table)
                    .values(chunk)
                    .execute(conn)?;
            }
            for chunk in pairs.chunks(INSERT_CHUNK) {
                diesel::insert_into(schema::pod_contention_history::table)
                    .values(chunk)
                    .execute(conn)?;
            }
            Ok(())
        })
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    info!(
        node = %batch.node,
        rows = accepted,
        pairs = pair_count,
        "compute history batch inserted"
    );
    Ok(HttpResponse::Ok().json(Accepted { accepted }))
}

// ---------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------

/// Empty string → absent, so `?namespace=` from a blank form field is
/// "no filter", the same convention `get.rs` applies.
fn non_empty(v: Option<String>) -> Option<String> {
    v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Clamp a `minutes` query param into `[1, HISTORY_MAX_MINUTES]`.
pub(crate) fn clamp_minutes(raw: Option<i64>, default: i64) -> i64 {
    raw.unwrap_or(default).clamp(1, HISTORY_MAX_MINUTES)
}

/// Rows charged and returned for a history window: 4 rows per minute
/// (a pod's containers at minute resolution; far more than that at
/// 5-minute resolution) capped at [`HISTORY_ROW_CAP`]. The full 7-day
/// window is 1 440 minute + 1 728 five-minute rows per container, so the
/// cap covers six containers over the whole retention.
pub(crate) fn history_row_limit(minutes: i64) -> i64 {
    minutes.saturating_mul(4).clamp(4, HISTORY_ROW_CAP)
}

#[derive(serde::Deserialize)]
pub struct NamespaceQuery {
    pub namespace: Option<String>,
}

#[derive(Serialize)]
pub struct LatestResponse {
    pub containers: Vec<PodComputeLatest>,
    pub nodes: Vec<NodeComputeLatest>,
}

#[get("/compute/latest")]
pub async fn get_compute_latest(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
    query: web::Query<NamespaceQuery>,
) -> actix_web::Result<impl Responder> {
    let Some(ns) = non_empty(query.into_inner().namespace) else {
        return Ok(HttpResponse::BadRequest().body("namespace query parameter is required"));
    };
    let _permit = match budget
        .acquire(cost_kib(LATEST_ROW_CAP, COMPUTE_ROW_COST_BYTES))
        .await
    {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let resp = web::block(move || -> Result<LatestResponse, DbError> {
        let mut conn = pool.get()?;
        latest_for_namespace(&mut conn, &ns)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(HttpResponse::Ok().json(resp))
}

pub fn latest_for_namespace(conn: &mut PgConnection, ns: &str) -> Result<LatestResponse, DbError> {
    let containers = {
        use schema::pod_compute_latest::dsl::*;
        pod_compute_latest
            .filter(namespace.eq(ns))
            .order((pod_name.asc(), container.asc()))
            .limit(LATEST_ROW_CAP)
            .load::<PodComputeLatest>(conn)?
    };
    let mut node_names: Vec<String> = containers.iter().map(|c| c.node.clone()).collect();
    node_names.sort();
    node_names.dedup();
    let nodes = if node_names.is_empty() {
        Vec::new()
    } else {
        use schema::node_compute_latest::dsl::*;
        node_compute_latest
            .filter(node.eq_any(&node_names))
            .order(node.asc())
            .load::<NodeComputeLatest>(conn)?
    };
    Ok(LatestResponse { containers, nodes })
}

#[derive(serde::Deserialize)]
pub struct MinutesQuery {
    pub minutes: Option<i64>,
}

#[derive(Serialize)]
pub struct HistoryResponse {
    pub rows: Vec<PodComputeHistoryRow>,
}

#[get("/compute/history/{pod_uid}")]
pub async fn get_compute_history(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
    path: web::Path<String>,
    query: web::Query<MinutesQuery>,
) -> actix_web::Result<impl Responder> {
    let uid = path.into_inner();
    if uid.trim().is_empty() {
        return Ok(HttpResponse::BadRequest().body("pod_uid must not be empty"));
    }
    let minutes = clamp_minutes(query.minutes, 60);
    let row_limit = history_row_limit(minutes);
    let _permit = match budget
        .acquire(cost_kib(row_limit, COMPUTE_ROW_COST_BYTES))
        .await
    {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let cutoff = chrono::Utc::now().naive_utc() - chrono::Duration::minutes(minutes);
    let rows = web::block(move || -> Result<Vec<PodComputeHistoryRow>, DbError> {
        let mut conn = pool.get()?;
        history_for_pod(&mut conn, &uid, cutoff, row_limit)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(HttpResponse::Ok().json(HistoryResponse { rows }))
}

/// Newest rows first at the database (so a truncated read drops the
/// OLD end of the window, not the end the caller is looking at), then
/// reversed to the contract's `ts asc`.
pub fn history_for_pod(
    conn: &mut PgConnection,
    uid: &str,
    cutoff: NaiveDateTime,
    row_limit: i64,
) -> Result<Vec<PodComputeHistoryRow>, DbError> {
    use schema::pod_compute_history::dsl::*;
    let mut rows = pod_compute_history
        .filter(pod_uid.eq(uid))
        .filter(ts.ge(cutoff))
        .order((ts.desc(), id.desc()))
        .limit(row_limit)
        .load::<PodComputeHistoryRow>(conn)?;
    rows.reverse();
    Ok(rows)
}

#[derive(serde::Deserialize)]
pub struct ScopeQuery {
    pub namespace: Option<String>,
    pub node: Option<String>,
    pub minutes: Option<i64>,
}

#[derive(Serialize)]
pub struct ContentionResponse {
    pub pairs: Vec<PodContentionRow>,
}

#[get("/compute/contention")]
pub async fn get_compute_contention(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
    query: web::Query<ScopeQuery>,
) -> actix_web::Result<impl Responder> {
    let q = query.into_inner();
    let ns = non_empty(q.namespace);
    let node = non_empty(q.node);
    if ns.is_none() && node.is_none() {
        return Ok(HttpResponse::BadRequest().body("namespace or node query parameter is required"));
    }
    let minutes = clamp_minutes(q.minutes, 5);
    let _permit = match budget
        .acquire(cost_kib(CONTENTION_ROW_CAP, COMPUTE_ROW_COST_BYTES))
        .await
    {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let cutoff = chrono::Utc::now().naive_utc() - chrono::Duration::minutes(minutes);
    let pairs = web::block(move || -> Result<Vec<PodContentionRow>, DbError> {
        let mut conn = pool.get()?;
        contention_pairs(&mut conn, ns, node, cutoff)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(HttpResponse::Ok().json(ContentionResponse { pairs }))
}

/// Top [`CONTENTION_PER_VICTIM`] pairs by wait per victim in the window,
/// under an overall [`CONTENTION_ROW_CAP`]. A window function has no
/// diesel DSL form, hence `sql_query`; the row type is the same
/// `PodContentionRow` (`QueryableByName` on the table's columns).
pub fn contention_pairs(
    conn: &mut PgConnection,
    ns: Option<String>,
    node: Option<String>,
    cutoff: NaiveDateTime,
) -> Result<Vec<PodContentionRow>, DbError> {
    use diesel::sql_types::{BigInt, Nullable, Text, Timestamp};
    let rows = diesel::sql_query(
        "SELECT id, ts, node, victim_container_uid, victim_pod_uid, victim_namespace, \
                culprit_cgroup_id, culprit_kind, culprit_ref, culprit_container_uid, count, wait_ns \
         FROM ( \
             SELECT p.*, ROW_NUMBER() OVER ( \
                        PARTITION BY victim_container_uid ORDER BY wait_ns DESC, id DESC) AS rn \
             FROM pod_contention_history p \
             WHERE ts >= $1 \
               AND ($2::text IS NULL OR victim_namespace = $2) \
               AND ($3::text IS NULL OR node = $3) \
         ) ranked \
         WHERE rn <= $4 \
         ORDER BY victim_container_uid, wait_ns DESC, id DESC \
         LIMIT $5",
    )
    .bind::<Timestamp, _>(cutoff)
    .bind::<Nullable<Text>, _>(ns)
    .bind::<Nullable<Text>, _>(node)
    .bind::<BigInt, _>(CONTENTION_PER_VICTIM)
    .bind::<BigInt, _>(CONTENTION_ROW_CAP)
    .load::<PodContentionRow>(conn)?;
    Ok(rows)
}

#[derive(Serialize)]
pub struct FindingsResponse {
    pub findings: Vec<Finding>,
}

#[get("/compute/findings")]
pub async fn get_compute_findings(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
    query: web::Query<ScopeQuery>,
) -> actix_web::Result<impl Responder> {
    let q = query.into_inner();
    let ns = non_empty(q.namespace);
    let node = non_empty(q.node);
    let _permit = match budget
        .acquire(cost_kib(
            FINDINGS_HISTORY_ROW_CAP + FINDINGS_PAIR_ROW_CAP,
            COMPUTE_ROW_COST_BYTES,
        ))
        .await
    {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let thresholds = ComputeThresholds::from_env();
    let cutoff = chrono::Utc::now().naive_utc() - chrono::Duration::minutes(WINDOW_MINUTES);
    let findings = web::block(move || -> Result<Vec<Finding>, DbError> {
        let mut conn = pool.get()?;
        findings_in_scope(&mut conn, ns, node, cutoff, &thresholds)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(HttpResponse::Ok().json(FindingsResponse { findings }))
}

/// Load the window and run the engine. The engine needs every container
/// on a victim's NODE (culprits are cross-namespace by nature), so the
/// scope is resolved to a node set first: an explicit `node`, else the
/// nodes currently hosting the namespace's containers, else the whole
/// cluster. Findings are then filtered back down to the requested
/// victims.
pub fn findings_in_scope(
    conn: &mut PgConnection,
    ns: Option<String>,
    node: Option<String>,
    cutoff: NaiveDateTime,
    thresholds: &ComputeThresholds,
) -> Result<Vec<Finding>, DbError> {
    let nodes_in_scope: Option<Vec<String>> = match (&node, &ns) {
        (Some(n), _) => Some(vec![n.clone()]),
        (None, Some(ns)) => {
            use schema::pod_compute_latest::dsl::*;
            let mut names = pod_compute_latest
                .filter(namespace.eq(ns))
                .select(node)
                .distinct()
                .limit(LATEST_ROW_CAP)
                .load::<String>(conn)?;
            names.sort();
            Some(names)
        }
        (None, None) => None,
    };
    if nodes_in_scope.as_ref().is_some_and(Vec::is_empty) {
        return Ok(Vec::new());
    }

    let history = {
        use schema::pod_compute_history::dsl::*;
        let mut q = pod_compute_history
            .filter(resolution_secs.eq(60))
            .filter(ts.ge(cutoff))
            .into_boxed();
        if let Some(names) = &nodes_in_scope {
            q = q.filter(node.eq_any(names));
        }
        q.order((ts.desc(), id.desc()))
            .limit(FINDINGS_HISTORY_ROW_CAP)
            .load::<PodComputeHistoryRow>(conn)?
    };
    let pairs = {
        use schema::pod_contention_history::dsl::*;
        let mut q = pod_contention_history.filter(ts.ge(cutoff)).into_boxed();
        if let Some(names) = &nodes_in_scope {
            q = q.filter(node.eq_any(names));
        }
        q.order((ts.desc(), id.desc()))
            .limit(FINDINGS_PAIR_ROW_CAP)
            .load::<PodContentionRow>(conn)?
    };
    let node_rows = {
        use schema::node_compute_latest::dsl::*;
        let mut q = node_compute_latest.into_boxed();
        if let Some(names) = &nodes_in_scope {
            q = q.filter(node.eq_any(names));
        }
        q.load::<NodeComputeLatest>(conn)?
    };

    let mut findings = compute_findings(&history, &pairs, &node_rows, thresholds);
    findings.retain(|f| {
        ns.as_ref().is_none_or(|n| &f.victim.namespace == n)
            && node.as_ref().is_none_or(|n| &f.victim.node == n)
    });
    Ok(findings)
}

#[derive(Serialize)]
pub struct NodesResponse {
    pub nodes: Vec<NodeComputeLatest>,
}

#[get("/compute/nodes")]
pub async fn get_compute_nodes(
    pool: web::Data<DbPool>,
    budget: web::Data<ReadBudget>,
) -> actix_web::Result<impl Responder> {
    let _permit = match budget
        .acquire(cost_kib(NODES_ROWS_CHARGED, COMPUTE_ROW_COST_BYTES))
        .await
    {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let nodes = web::block(move || -> Result<Vec<NodeComputeLatest>, DbError> {
        use schema::node_compute_latest::dsl::*;
        let mut conn = pool.get()?;
        Ok(node_compute_latest
            .order(node.asc())
            .load::<NodeComputeLatest>(&mut conn)?)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(HttpResponse::Ok().json(NodesResponse { nodes }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_validation() {
        assert_eq!(validate_envelope("worker-3", 5000), Ok(()));
        assert!(validate_envelope("", 5000).is_err());
        assert!(validate_envelope("   ", 5000).is_err());
        assert!(validate_envelope("worker-3", 0).is_err());
        assert!(validate_envelope("worker-3", -1).is_err());
        assert!(validate_envelope(&"x".repeat(300), 5000).is_err());
    }

    #[test]
    fn minutes_clamp() {
        assert_eq!(clamp_minutes(None, 60), 60);
        assert_eq!(clamp_minutes(Some(0), 60), 1);
        assert_eq!(clamp_minutes(Some(-5), 5), 1);
        assert_eq!(clamp_minutes(Some(30), 60), 30);
        assert_eq!(clamp_minutes(Some(99_999), 60), HISTORY_MAX_MINUTES);
    }

    #[test]
    fn history_row_limit_scales_and_caps() {
        assert_eq!(history_row_limit(1), 4);
        assert_eq!(history_row_limit(60), 240);
        assert_eq!(history_row_limit(HISTORY_MAX_MINUTES), HISTORY_ROW_CAP);
        // The cap must cover a single container over the whole default
        // retention (1 440 minute rows + 6 x 288 five-minute rows).
        const { assert!(HISTORY_ROW_CAP >= 1_440 + 6 * 288) };
    }

    #[test]
    fn empty_filters_are_absent() {
        assert_eq!(non_empty(Some("".into())), None);
        assert_eq!(non_empty(Some("  ".into())), None);
        assert_eq!(
            non_empty(Some(" payments ".into())),
            Some("payments".into())
        );
        assert_eq!(non_empty(None), None);
    }
}
