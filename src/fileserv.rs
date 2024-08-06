use cfg_if::cfg_if;

cfg_if! { if #[cfg(feature = "ssr")] {
    use axum::{
        body::Body as AxumBody,
        extract::State,
        response::IntoResponse,
        http::{Request, Response, HeaderMap, header::ACCEPT_ENCODING, StatusCode, Uri},
    };
    use axum::response::Response as AxumResponse;
    use tower::ServiceExt;
    use tower_http::services::ServeDir;
    use leptos::prelude::*;
    use crate::app::error_template::ErrorTemplate;
    use crate::app::error_template::AppPageError;
}}

#[cfg(feature = "ssr")]
pub async fn file_and_error_handler(
    uri: Uri,
    headers: HeaderMap,
    State(options): State<LeptosOptions>,
    req: Request<AxumBody>,
) -> AxumResponse {
    let root = options.site_root.clone();
    let res = get_static_file(headers, uri.clone(), &root).await.unwrap();

    if res.status() == StatusCode::OK {
        res.into_response()
    } else {
        let mut errors = Errors::default();
        errors.insert_with_default_key(AppPageError::NotFound);
        let handler = leptos_axum::render_app_to_stream(
            move || view! {<ErrorTemplate outside_errors=errors.clone()/>},
        );
        handler(req).await.into_response()
    }
}

#[cfg(feature = "ssr")]
async fn get_static_file(
    headers: HeaderMap,
    uri: Uri,
    root: &str,
) -> Result<Response<AxumBody>, (StatusCode, String)> {
    let req = match headers.get("accept-encoding") {
        Some(encodings) => Request::builder()
            .uri(uri.clone())
            .header(ACCEPT_ENCODING, encodings)
            .body(AxumBody::empty())
            .unwrap(),
        None => Request::builder()
            .uri(uri.clone())
            .body(AxumBody::empty())
            .unwrap(),
    };
    // `ServeDir` implements `tower::Service` so we can call it with `tower::ServiceExt::oneshot`
    // This path is relative to the cargo root
    match ServeDir::new(root).precompressed_gzip().oneshot(req).await {
        Ok(res) => Ok(res.into_response()),
        Err(err) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {err}"),
        )),
    }
}
