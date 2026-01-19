use axum::{
    body::Body,
    extract::{MatchedPath, Request},
    http::{HeaderName, Response, StatusCode},
};
use std::time::Duration;
use tokio::{net::TcpListener, signal};
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tracing::{Span, error, info, info_span};

use crate::{
    domains::accounts::service::AccountsService, routes::app_router, secrets::SecretsManager,
};

const REQUEST_ID_HEADER: &str = "x-request-id";

pub async fn serve_http_server(
    tcp_listener: TcpListener,
    secrets_manager: impl SecretsManager,
    accounts_service: impl AccountsService,
) -> Result<(), anyhow::Error> {
    let x_request_id = HeaderName::from_static(REQUEST_ID_HEADER);

    let app = app_router(secrets_manager, accounts_service).layer((
        // Set `x-request-id` header for every request
        SetRequestIdLayer::new(x_request_id.clone(), MakeRequestUuid),
        // Log request and response
        TraceLayer::new_for_http()
            .make_span_with(|request: &Request<_>| {
                let matched_path = request
                    .extensions()
                    .get::<MatchedPath>()
                    .map(MatchedPath::as_str);

                let request_id = request.headers().get(REQUEST_ID_HEADER);

                match request_id {
                    Some(v) => info_span!(
                        "http_request",
                        method = ?request.method(),
                        matched_path,
                        request_id = ?v
                    ),
                    None => {
                        error!("Failed to extract `request_id` header");
                        info_span!(
                            "http_request",
                            method = ?request.method(),
                            matched_path,
                        )
                    }
                }
            })
            .on_response(
                |response: &Response<Body>, latency: Duration, _span: &Span| {
                    if response.status().is_server_error() {
                        error!("response: {} {latency:?}", response.status())
                    } else {
                        info!("response: {} {latency:?}", response.status())
                    }
                },
            ),
        // Timeout requests at 10 seconds
        TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, Duration::from_secs(10)),
        // Propagate the `x-request-id` header to responses
        PropagateRequestIdLayer::new(x_request_id),
    ));

    axum::serve(tcp_listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|err| {
            let err = format!("Error while serving the routes: {err}");
            error!(err);
            anyhow::anyhow!(err)
        })?;

    info!("App has been gracefully shutdown");

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
