#[cfg(feature = "ssr")]
#[derive(Clone, Copy)]
struct Ports {
    http: u16,
    https: u16,
}

cfg_if::cfg_if! { if #[cfg(feature = "ssr")] {
    use auth_sessions_example::{
        defs::{AppState, ServerVars},
        fileserv::file_and_error_handler,
        app::{App, shell},
        websocket::axum_ws_handler,
        security::gen_128bit_base64,
    };
    use axum::{
        extract::{Host, Path, ConnectInfo, State},
        handler::HandlerWithoutStateExt,
        http::{Request, StatusCode, Uri, header::HeaderMap},
        response::{Response, Redirect, IntoResponse},
        routing::{post, get},
        BoxError, Router,
        body::Body as AxumBody,
    };
    use axum_server::tls_rustls::RustlsConfig;
    use leptos::prelude::*;
    use leptos_axum::{handle_server_fns_with_context, generate_route_list, LeptosRoutes};
    use std::{env, net::SocketAddr, path::PathBuf};
    use sqlx::sqlite::SqlitePoolOptions;
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
    // Setting get_configuration(None) means we'll be using cargo-leptos's env values
    // For deployment these variables are:
    // listed in .env.example
    println!("reading config");
    let conf = leptos::config::get_configuration(None)
        .expect("Cargo.toml could not be parsed by leptos::get_configuration");
    let leptos_options = conf.leptos_options;
    let addr_https = leptos_options.site_addr;
    let addr_http: SocketAddr = match leptos_options.env {
        Env::PROD => env::var("LIVE_HTTP_REDIRECT")
            .expect("LIVE_HTTP_REDIRECT not set")
            .parse()
            .expect("verify LIVE_HTTP_REDIRECT value"),
        // hard coded redirect
        Env::DEV => SocketAddr::from(([127, 0, 0, 1], 80)),
    };
    println!("config read complete");

    let ports = Ports {
        http: addr_http.port(),
        https: addr_https.port(),
    };

    // setup logging
    println!("setup logging");
    match leptos_options.env {
        // when in PROD mode suppress non-error logs
        Env::PROD => simple_logger::SimpleLogger::new()
            .with_level(log::LevelFilter::Error)
            .init()
            .expect("couldn't initialize logging"),
        // when in DEV mode suppress most logs from other crates, show all logs from this crate
        Env::DEV => simple_logger::SimpleLogger::new()
            .with_level(log::LevelFilter::Warn)
            .with_module_level(leptos_options.output_name.as_str(), log::LevelFilter::Trace)
            .init()
            .expect("couldn't initialize logging"),
    };
    //the logging levels are: Error, Warn, Info, Debug, Trace
    println!("logging set up");

    println!("reading certs");
    let rustls_config = match leptos_options.env {
        Env::PROD => RustlsConfig::from_pem_file(
            PathBuf::from(env::var("LIVE_CERT_PEM").expect("LIVE_CERT_PEM not set")),
            PathBuf::from(env::var("LIVE_KEY_PEM").expect("LIVE_KEY_PEM not set")),
        )
        .await
        .expect("verify CERT_PEM and KEY_PEM values"),
        Env::DEV => RustlsConfig::from_pem_file(
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
    println!("certs imported, but not checked");

    println!("generating routes, ignore next sql error during route generation only, sql isn't even up yet");
    // Generate the list of routes in your Leptos App
    let routes = generate_route_list(App);
    println!("routes generated");

    println!("setting up sqlite pool");
    //setup db pool
    let pool = SqlitePoolOptions::new()
        .connect(
            env::var("DATABASE_URL")
                .expect("DATABASE_URL not set")
                .as_str(),
        )
        .await
        .expect("Could not make pool.");

    sqlx::migrate!()
        .run(&pool)
        .await
        .expect("could not run SQLx migrations");
    println!("sqlite up");

    log::info!("Server process starting");
    log::info!("Server {:#?}", leptos_options);

    let app_state = AppState {
        leptos_options,
        pool,
        routes: routes.clone(),
        vars: ServerVars {
            csrf_server: gen_128bit_base64(),
        },
    };

    // build our application with a route
    let app = Router::new()
        .route("/api/*fn_name", post(server_fn_handler))
        .route("/ws", get(axum_ws_handler))
        .leptos_routes_with_handler(routes, get(leptos_routes_handler))
        .fallback(file_and_error_handler)
        .layer(CompressionLayer::new())
        .with_state(app_state);

    // spawn a redirect http to https
    tokio::spawn(redirect_http_to_https(ports));

    // run app with axum_server::bind_rustls for TLS
    log::info!("listening on https://{}", &addr_https);
    axum_server::bind_rustls(addr_https, rustls_config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();

    //axum::serve(
    //    tokio::net::TcpListener::bind(addr).await.unwrap(),
    //    redirect.into_make_service(),
    //)
    //.await
    //.unwrap();
}

#[cfg(feature = "ssr")]
async fn leptos_routes_handler(
    State(app_state): State<AppState>,
    connect_info: ConnectInfo<SocketAddr>,
    req: Request<AxumBody>,
) -> Response {
    let leptos_options = app_state.leptos_options.clone();
    let handler = leptos_axum::render_route_with_context(
        //app_state.leptos_options.clone(),
        app_state.routes.clone(),
        move || {
            provide_context(app_state.pool.clone());
            provide_context(app_state.vars.clone());
            provide_context(connect_info);
            provide_context(app_state.leptos_options.clone());
        },
        move || shell(leptos_options.clone()),
    );
    handler(req).await.into_response()
}

#[cfg(feature = "ssr")]
async fn server_fn_handler(
    State(app_state): State<AppState>,
    connect_info: ConnectInfo<SocketAddr>,
    path: Path<String>,
    headers: HeaderMap,
    query: axum::extract::RawQuery,
    request: Request<AxumBody>,
) -> impl IntoResponse {
    log::debug!(
        "server_fn_handler: \n\n path: {:?}\n\n headers: {:?}\n\n query: {:?}\n\n request: {:?}\n\n connect_info: {:?}\n\n",
        path,
        headers,
        query,
        request,
        connect_info,
    );
    handle_server_fns_with_context(
        move || {
            provide_context(app_state.pool.clone());
            provide_context(app_state.vars.clone());
            provide_context(connect_info);
            provide_context(app_state.leptos_options.clone());
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
                log::error!("error: {:#?}, failed to convert URI to HTTPS", error);
                Err(StatusCode::BAD_REQUEST)
            }
        }
    };

    let addr = SocketAddr::from(([127, 0, 0, 1], ports.http));
    log::info!("http redirect listening on {}", addr);

    axum::serve(
        tokio::net::TcpListener::bind(addr).await.unwrap(),
        redirect.into_make_service(),
    )
    .await
    .unwrap();
}

#[cfg(not(feature = "ssr"))]
pub fn main() {
    // no client-side main function
    // unless we want this to work with e.g., Trunk for pure client-side testing
    // see lib.rs for hydration function instead
}
