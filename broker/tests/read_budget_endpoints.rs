//! End-to-end proof that the read-memory budget is actually wired into the
//! handlers, and that exhausting it produces an explicit 503 rather than a
//! short read.
//!
//! # How this tests a DB-backed handler with no database
//!
//! Every test in this repo runs without Postgres. That is normally a limit,
//! but here it is the assertion: the budget check runs *before* the handler
//! touches the pool, so with an exhausted budget these handlers must answer
//! 503 without ever attempting a connection. The pool below points at an
//! unroutable host with a 50 ms connect timeout, so any request that reaches
//! the database path answers 500 instead. 503 therefore proves the budget
//! short-circuited; 500 would prove it did not.
//!
//! That distinction is the whole safety property: a request admitted past the
//! budget is a request whose memory nobody is accounting for.

use std::time::Duration;

use actix_web::{test, web, App};
use api::ReadBudget;
use diesel::r2d2::{self, ConnectionManager};
use diesel::PgConnection;

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;

/// A pool that will never successfully connect. `build_unchecked` skips
/// r2d2's usual startup connection test, so construction succeeds offline.
fn unreachable_pool() -> DbPool {
    let manager = ConnectionManager::<PgConnection>::new("postgres://u:p@127.0.0.1:1/nodb");
    r2d2::Pool::builder()
        .max_size(1)
        .connection_timeout(Duration::from_millis(50))
        .build_unchecked(manager)
}

/// A budget with every KiB already reserved, so the next read must shed.
/// The returned permit must stay alive for the duration of the test — drop it
/// and the budget refills, and the endpoint under test stops shedding.
async fn exhausted_budget() -> (web::Data<ReadBudget>, api::ReadPermit) {
    // Zero wait: fail fast, no queueing, so the test does not sleep.
    let budget = ReadBudget::with_budget_kib(64, Duration::from_millis(0));
    let hog = budget.acquire(64).await.expect("fills the budget");
    (web::Data::new(budget), hog)
}

macro_rules! sheds_when_budget_exhausted {
    ($name:ident, $service:path, $uri:expr) => {
        #[actix_web::test]
        async fn $name() {
            let (budget, _hog) = exhausted_budget().await;
            let app = test::init_service(
                App::new()
                    .app_data(web::Data::new(unreachable_pool()))
                    .app_data(budget.clone())
                    .service($service),
            )
            .await;

            let resp =
                test::call_service(&app, test::TestRequest::get().uri($uri).to_request()).await;

            assert_eq!(
                resp.status(),
                actix_web::http::StatusCode::SERVICE_UNAVAILABLE,
                "{} must shed with 503 when the read budget is exhausted. A 500 here means \
                 the handler reached the database without charging the budget — i.e. the \
                 memory bound is not actually enforced on this endpoint.",
                $uri
            );
            assert_eq!(
                resp.headers()
                    .get("Retry-After")
                    .and_then(|v| v.to_str().ok()),
                Some("1"),
                "{} shed must be marked retryable",
                $uri
            );

            let body = test::read_body(resp).await;
            let text = String::from_utf8_lossy(&body);
            assert!(
                text.contains("REFUSED, not truncated"),
                "the shed body must be unmistakable about not being a partial result, got: {text}"
            );
            assert_eq!(
                budget.get_ref().shed_count(),
                1,
                "the shed must be counted for broker_read_shed_total"
            );
        }
    };
}

// Every whole-result-set read endpoint. If a new one is added without
// charging the budget, it belongs in this list and will fail here until it is
// wired up.
sheds_when_budget_exhausted!(
    pod_traffic_sheds,
    api::get_pod_traffic,
    "/pod/traffic?limit=20000"
);
sheds_when_budget_exhausted!(
    pod_traffic_by_name_sheds,
    api::get_pod_traffic_name,
    "/pod/traffic/some-pod"
);
sheds_when_budget_exhausted!(pod_info_sheds, api::get_pod_details, "/pod/info");
sheds_when_budget_exhausted!(svc_info_sheds, api::get_svc_details, "/svc/info");
sheds_when_budget_exhausted!(
    pods_by_node_sheds,
    api::get_pods_by_node,
    "/pod/list/node-1"
);
sheds_when_budget_exhausted!(
    pod_syscalls_sheds,
    api::get_pod_syscall_name,
    "/pod/syscalls/some-pod"
);
sheds_when_budget_exhausted!(
    audit_verdicts_sheds,
    api::get_audit_verdicts,
    "/audit/verdicts?limit=500"
);
sheds_when_budget_exhausted!(
    compute_latest_sheds,
    api::get_compute_latest,
    "/compute/latest?namespace=payments"
);
sheds_when_budget_exhausted!(
    compute_history_sheds,
    api::get_compute_history,
    "/compute/history/some-pod-uid?minutes=60"
);
sheds_when_budget_exhausted!(
    compute_contention_sheds,
    api::get_compute_contention,
    "/compute/contention?namespace=payments&minutes=5"
);
sheds_when_budget_exhausted!(
    compute_findings_sheds,
    api::get_compute_findings,
    "/compute/findings"
);
sheds_when_budget_exhausted!(
    compute_nodes_sheds,
    api::get_compute_nodes,
    "/compute/nodes"
);

/// The complement of the shed tests: with budget available, the request is
/// admitted and proceeds to the database (which then fails, because there
/// isn't one). A 500 here is the *success* condition — it proves the budget
/// is a gate, not a wall, and that a healthy broker is not rejecting reads.
#[actix_web::test]
async fn read_is_admitted_when_budget_is_available() {
    let budget = web::Data::new(ReadBudget::with_budget_kib(
        1024 * 1024,
        Duration::from_millis(0),
    ));
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(unreachable_pool()))
            .app_data(budget.clone())
            .service(api::get_pod_traffic),
    )
    .await;

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/pod/traffic?limit=100")
            .to_request(),
    )
    .await;

    assert_eq!(
        resp.status(),
        actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
        "with budget free the request must be admitted and fail at the DB, not be shed"
    );
    assert_eq!(
        budget.get_ref().shed_count(),
        0,
        "an admitted read must not be counted as shed"
    );
}

/// A validation 400 must be returned without waiting on the budget. Rejecting
/// bad input is free; making it queue behind a saturated budget would turn a
/// client bug into a latency incident.
#[actix_web::test]
async fn bad_input_is_rejected_before_the_budget_is_consulted() {
    let (budget, _hog) = exhausted_budget().await;
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(unreachable_pool()))
            .app_data(budget.clone())
            .service(api::get_audit_verdicts),
    )
    .await;

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/audit/verdicts?verdict=Maybe")
            .to_request(),
    )
    .await;

    assert_eq!(
        resp.status(),
        actix_web::http::StatusCode::BAD_REQUEST,
        "an invalid ?verdict= must 400 even with the budget exhausted"
    );
    assert_eq!(
        budget.get_ref().shed_count(),
        0,
        "a rejected request must not consume or shed budget"
    );
}

/// Same property for the compute reads: a missing required filter is a
/// 400 straight away, not a queued read. `/compute/latest` requires
/// `namespace`; `/compute/contention` requires `namespace` or `node`.
#[actix_web::test]
async fn compute_reads_reject_missing_filters_before_the_budget() {
    let (budget, _hog) = exhausted_budget().await;
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(unreachable_pool()))
            .app_data(budget.clone())
            .service(api::get_compute_latest)
            .service(api::get_compute_contention),
    )
    .await;

    for uri in [
        "/compute/latest",
        "/compute/latest?namespace=",
        "/compute/contention",
    ] {
        let resp = test::call_service(&app, test::TestRequest::get().uri(uri).to_request()).await;
        assert_eq!(
            resp.status(),
            actix_web::http::StatusCode::BAD_REQUEST,
            "{uri} must 400 on a missing filter even with the budget exhausted"
        );
    }
    assert_eq!(
        budget.get_ref().shed_count(),
        0,
        "rejected requests must not consume or shed budget"
    );
}

/// The property the whole module exists for, exercised through the real HTTP
/// stack: concurrent heavy reads are bounded by the memory budget, and the
/// ones that do not fit are refused rather than admitted.
#[actix_web::test]
async fn concurrent_heavy_reads_are_capped_by_the_budget() {
    // 100 MiB of budget against ~50 MiB hard-cap reads: two fit, the rest shed.
    let budget = web::Data::new(ReadBudget::with_budget_kib(
        100 * 1024,
        Duration::from_millis(0),
    ));

    let mut held = Vec::new();
    for _ in 0..2 {
        held.push(
            budget
                .get_ref()
                .acquire(api::cost_kib(20_000, api::TRAFFIC_ROW_COST_BYTES))
                .await
                .expect("two hard-cap reads must fit 100 MiB"),
        );
    }

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(unreachable_pool()))
            .app_data(budget.clone())
            .service(api::get_pod_traffic),
    )
    .await;

    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/pod/traffic?limit=20000")
            .to_request(),
    )
    .await;

    assert_eq!(
        resp.status(),
        actix_web::http::StatusCode::SERVICE_UNAVAILABLE,
        "a third concurrent hard-cap read must be refused — this is the OOMKill that \
         DB_POOL_MAX_SIZE=32 used to allow"
    );

    // Releasing one lets the next in, proving the cap is a live bound rather
    // than a latch that stays stuck once tripped.
    held.pop();
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/pod/traffic?limit=20000")
            .to_request(),
    )
    .await;
    assert_eq!(
        resp.status(),
        actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
        "once budget frees, the read must be admitted again (and fail at the absent DB)"
    );
}
