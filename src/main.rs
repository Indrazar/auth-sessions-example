#[cfg(feature = "ssr")]
#[derive(Clone, Copy)]
struct Ports {
    http: u16,
    https: u16,
}

cfg_if::cfg_if! { if #[cfg(feature = "ssr")] {
    use auth_sessions_example::{
        fileserv::file_and_error_handler,
        pages::App,
        websocket::axum_ws_handler,
        security::{gen_128bit_base64, ServerSessionData},
    };
    use axum::{
        extract::{Extension, Host, Path, ConnectInfo},
        handler::HandlerWithoutStateExt,
        http::{Request, StatusCode, Uri, header::HeaderMap},
        response::{Response, Redirect, IntoResponse},
        routing::{post, get},
        BoxError, Router,
        body::Body as AxumBody,
    };
    use axum_server::tls_rustls::RustlsConfig;
    use leptos::*;
    use leptos_axum::*;
    use std::{env, net::SocketAddr, path::PathBuf, sync::Arc};
    use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
    use tower_http::compression::CompressionLayer;
}}

#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() {
    match dotenvy::dotenv() {
        Ok(path) => println!(".env read successfully from {}", path.display()),
        Err(e) => println!(
            "Could not load .env file: {e}. \nProceeding assuming variables are set in the \
             environment."
        ),
    };

    let conf = leptos::get_configuration(Some("Cargo.toml"))
        .await
        .expect("Cargo.toml could not be parsed by leptos::get_configuration");
    let leptos_options = conf.leptos_options;
    let addr_https = leptos_options.site_addr;
    let addr_http: SocketAddr = match leptos_options.env {
        leptos_config::Env::PROD => env::var("LIVE_HTTP_REDIRECT")
            .expect("LIVE_HTTP_REDIRECT not set")
            .parse()
            .expect("verify LIVE_HTTP_REDIRECT value"),
        // hard coded redirect
        leptos_config::Env::DEV => SocketAddr::from(([127, 0, 0, 1], 80)),
    };

    let ports = Ports {
        http: addr_http.port(),
        https: addr_https.port(),
    };

    // setup logging
    match leptos_options.env {
        // when in PROD mode suppress non-error logs
        leptos_config::Env::PROD => simple_logger::SimpleLogger::new()
            .with_level(log::LevelFilter::Error)
            .init()
            .expect("couldn't initialize logging"),
        // when in DEV mode suppress most logs from other crates, show all logs from this crate
        leptos_config::Env::DEV => simple_logger::SimpleLogger::new()
            .with_level(log::LevelFilter::Warn)
            .with_module_level("auth_sessions_example", log::LevelFilter::Trace)
            .init()
            .expect("couldn't initialize logging"),
    };
    //the logging levels are: Error, Warn, Info, Debug, Trace

    let rustls_config = match leptos_options.env {
        leptos_config::Env::PROD => RustlsConfig::from_pem_file(
            PathBuf::from(env::var("LIVE_CERT_PEM").expect("LIVE_CERT_PEM not set")),
            PathBuf::from(env::var("LIVE_KEY_PEM").expect("LIVE_KEY_PEM not set")),
        )
        .await
        .expect("verify CERT_PEM and KEY_PEM values"),
        leptos_config::Env::DEV => RustlsConfig::from_pem_file(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("self_signed_certs")
                .join("certificate.pem"),
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("self_signed_certs")
                .join("key.pem"),
        )
        .await
        .expect("debug cert files missing in self_signed_certs"),
    };

    // Generate the list of routes in your Leptos App
    let routes = generate_route_list(|| leptos::view! { <App/> }).await;

    //setup db pool
    let pool_options = SqlitePoolOptions::new()
        .connect(
            env::var("DATABASE_URL")
                .expect("DATABASE_URL not set")
                .as_str(),
        )
        .await
        .expect("Could not make pool.");

    sqlx::migrate!()
        .run(&pool_options)
        .await
        .expect("could not run SQLx migrations");

    log::debug!("\n\n\nServer process starting");
    log::debug!("Server {:#?}", leptos_options);
    log::debug!("Server registering functions");

    let server_session_data = ServerSessionData {
        csrf_server: gen_128bit_base64(),
    };

    // build our application with a route
    let app = Router::new()
        .route("/api/*fn_name", post(api_fn_handler))
        .route("/ws", get(axum_ws_handler))
        .leptos_routes_with_handler(routes, get(leptos_routes_handler))
        .fallback(file_and_error_handler)
        .layer(Extension(Arc::new(leptos_options.clone())))
        .layer(Extension(server_session_data))
        .layer(Extension(pool_options))
        .layer(CompressionLayer::new())
        .with_state(leptos_options);

    // spawn a redirect http to https
    tokio::spawn(redirect_http_to_https(ports));

    // run app with axum_server::bind_rustls for TLS
    log::info!("listening on https://{}", &addr_https);
    axum_server::bind_rustls(addr_https, rustls_config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}

#[cfg(feature = "ssr")]
async fn leptos_routes_handler(
    Extension(server_session_data): Extension<ServerSessionData>,
    Extension(pool): Extension<SqlitePool>,
    Extension(options): Extension<Arc<LeptosOptions>>,
    req: Request<AxumBody>,
) -> Response {
    let handler = leptos_axum::render_app_async_with_context(
        (*options).clone(),
        move || {
            provide_context(pool.clone());
            provide_context(server_session_data.clone());
            provide_context(options.clone());
        },
        || view! {<App/>},
    );
    handler(req).await.into_response()
}

#[cfg(feature = "ssr")]
async fn api_fn_handler(
    Extension(server_session_data): Extension<ServerSessionData>,
    Extension(pool): Extension<SqlitePool>,
    Extension(connect_info): Extension<ConnectInfo<SocketAddr>>,
    path: Path<String>,
    headers: HeaderMap,
    query: axum::extract::RawQuery,
    request: Request<AxumBody>,
) -> impl IntoResponse {
    log::trace!(
        "api_fn_handler: path: {:#?}, connect_info: {:#?}",
        path,
        connect_info
    );
    handle_server_fns_with_context(
        path,
        headers,
        query,
        move || {
            provide_context(pool.clone());
            provide_context(server_session_data.clone());
            provide_context(connect_info)
        },
        request,
    )
    .await
}

#[cfg(feature = "ssr")]
async fn redirect_http_to_https(ports: Ports) {
    fn make_https(host: String, uri: Uri, ports: Ports) -> Result<Uri, BoxError> {
        let mut parts = uri.into_parts();
        parts.scheme = Some(axum::http::uri::Scheme::HTTPS);

        if parts.path_and_query.is_none() {
            parts.path_and_query = Some("/".parse().unwrap());
        }

        let https_host = match host.contains(':') {
            true => host.replace(&ports.http.to_string(), &ports.https.to_string()),
            false => {
                let port = &ports.https.to_string();
                format!("{host}:{port}")
            }
        };

        parts.authority = Some(https_host.parse()?);
        let result = Uri::from_parts(parts)?;
        Ok(result)
    }

    let redirect = move |Host(host): Host, uri: Uri| async move {
        match make_https(host, uri, ports) {
            Ok(uri) => Ok(Redirect::temporary(&uri.to_string())),
            Err(error) => {
                log::warn!("error: {:#?}, failed to convert URI to HTTPS", error);
                Err(StatusCode::BAD_REQUEST)
            }
        }
    };

    let addr = SocketAddr::from(([127, 0, 0, 1], ports.http));
    log::debug!("http redirect listening on {}", addr);

    axum::Server::bind(&addr)
        .serve(redirect.into_make_service())
        .await
        .unwrap();
}

#[cfg(not(feature = "ssr"))]
pub fn main() {
    // no client-side main function
    // unless we want this to work with e.g., Trunk for pure client-side testing
    // see lib.rs for hydration function instead
}
