#[cfg(feature = "ssr")]
#[derive(Clone, Copy)]
struct Ports {
    http: u16,
    https: u16,
}

cfg_if::cfg_if! { if #[cfg(feature = "ssr")] {
    use leptos::*;
    use axum::{
        extract::Host,
        handler::HandlerWithoutStateExt,
        http::{StatusCode, Uri},
        response::Redirect,
        routing::post,
        extract::Extension,
        BoxError,
        Router,
    };
    use axum_server::tls_rustls::RustlsConfig;
    use leptos_axum::{generate_route_list, LeptosRoutes};

    use std::{
        fs,
        net::SocketAddr,
        sync::Arc,
        path::PathBuf,
    };

    use auth_example::pages::{App, AppProps, register_server_functions};
    use auth_example::fileserv::file_and_error_handler;
}}

#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() {
    let conf = leptos::get_configuration(Some("Cargo.toml"))
        .await
        .expect("");
    let leptos_options = conf.leptos_options;
    let addr_https = leptos_options.site_addr;
    let addr_http = SocketAddr::from(([127, 0, 0, 1], 80)); // hard coded redirect
    let ports = Ports {
        http: addr_http.port(),
        https: addr_https.port(),
    };

    // setup logging
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Warn)
        .with_module_level("auth_example", log::LevelFilter::Trace)
        .init()
        .expect("couldn't initialize logging");
    //the logging levels are:
    //Error
    //Warn
    //Info
    //Debug
    //Trace

    let rustls_config = RustlsConfig::from_pem_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("self_signed_certs")
            .join("certificate.pem"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("self_signed_certs")
            .join("key.pem"),
    )
    .await
    .unwrap();

    // Generate the list of routes in your Leptos App
    let routes = generate_route_list(|cx| leptos::view! { cx, <App/> }).await;

    log::debug!("Server process starting");
    log::debug!("Server {:#?}", leptos_options);

    let file =
        fs::read_to_string("./server_config.json").expect("Could not load server_config.json: ");
    let srv_config: serde_json::Value =
        serde_json::from_str(file.as_str()).expect("Could not decode server_config.json: ");
    log::debug!("Server configurations {:#?}", srv_config);

    log::debug!("Server registering functions");
    register_server_functions().expect("Could not register_server_functions: ");

    // build our application with a route
    let app = Router::new()
        .route("/api/*fn_name", post(leptos_axum::handle_server_fns))
        .leptos_routes(leptos_options.clone(), routes, |cx| view! { cx, <App/> })
        .fallback(file_and_error_handler)
        .layer(Extension(Arc::new(leptos_options)));

    // spawn a redirect http to https
    tokio::spawn(redirect_http_to_https(ports));

    // run app with axum_server::bind_rustls for TLS
    log::info!("listening on https://{}", &addr_https);
    axum_server::bind_rustls(addr_https, rustls_config)
        .serve(app.into_make_service())
        .await
        .unwrap();
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
        //log::trace!("uri::from_parts {:#?}", result.clone());

        Ok(result) //Ok(Uri::from_parts(parts)?)
    }

    let redirect = move |Host(host): Host, uri: Uri| async move {
        match make_https(host, uri, ports) {
            Ok(uri) => Ok(Redirect::temporary(&uri.to_string())),
            Err(error) => {
                tracing::warn!(%error, "failed to convert URI to HTTPS");
                Err(StatusCode::BAD_REQUEST)
            }
        }
    };

    let addr = SocketAddr::from(([127, 0, 0, 1], ports.http));
    tracing::debug!("http redirect listening on {}", addr);

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
