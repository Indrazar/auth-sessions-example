use cfg_if::cfg_if;
use leptos::*;

cfg_if! { if #[cfg(feature = "ssr")] {
    use axum::{
        http::header::{COOKIE, SET_COOKIE},
        http::{HeaderMap, HeaderValue},
    };
    use chrono::prelude::*;
    use leptos_axum::{RequestParts, ResponseParts};
}}

/// This component forces SSR to resolve and will leave behind a javascript-
/// enabled session cookie in the header which the WASM will read on load
/// if the cookie is present then the WASM will not double-send
/// if the cookie is not present then WASM will assume it navigated here
/// through the hydration.
#[component]
pub fn LoggedInRedirect(
    cx: Scope,
    success_route: Option<String>,
    fail_route: Option<String>,
) -> impl IntoView {
    //#[cfg(feature = "ssr")]
    //validate_session(cx)
}

#[server(ProcessLandingPage, "/api")]
pub async fn retrieve_session(cx: Scope) -> Result<bool, ServerFnError> {
    validate_session(cx)
}

#[cfg(feature = "ssr")]
pub fn validate_session(cx: Scope) -> Result<bool, ServerFnError> {
    let http_req = match use_context::<leptos_axum::RequestParts>(cx) {
        Some(rp) => rp,           // actual user request
        None => return Ok(false), // no request, building routes in main.rs
    };
    let unverified_session_id = parse_session_cookie(http_req);
    let session_id = match revalidate_token(unverified_session_id.as_str()) {
        Some(session) => session,
        None => return Ok(false),
    };
    let response = use_context::<leptos_axum::ResponseOptions>(cx)
        .expect("to have leptos_axum::ResposneParts");
    let expire_time: DateTime<Utc> = Utc::now() + chrono::Duration::days(30);
    let date_string: String = expire_time.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
    let mut response_parts = ResponseParts::default();
    let mut headers = HeaderMap::new();
    headers.insert(
        SET_COOKIE,
        HeaderValue::from_str(&format!(
            "SESSIONID={session_id}; Expires={date_string}; Secure; SameSite=Lax; HttpOnly; Path=/"
        ))
        .expect("to create header value"),
    );
    log::trace!("valid session renewed: {session_id}");
    response_parts.headers = headers;
    response.overwrite(response_parts);
    Ok(true)
}

#[cfg(feature = "ssr")]
fn parse_session_cookie(req: RequestParts) -> String {
    let cookies = match req.headers.get(COOKIE) {
        Some(t) => t.to_str().unwrap_or_default(),
        None => return generate_new_session(),
    };
    match get_cookie_value(cookies, "SESSIONID") {
        Some(t) => t,
        None => generate_new_session(),
    }
}

#[cfg(feature = "ssr")]
fn get_cookie_value(cookies: &str, key: &str) -> Option<String> {
    cookies.split(';').find_map(|cookie| {
        let cookie_arr = cookie.split_once('=').unwrap_or_default();
        if cookie_arr.0.trim().eq(key) && !cookie_arr.1.trim().is_empty() {
            Some(cookie_arr.1.to_string())
        } else {
            None
        }
    })
}

#[cfg(feature = "ssr")]
fn generate_new_session() -> String {
    "10".to_string()
}

#[cfg(feature = "ssr")]
fn revalidate_token(suspect_session: &str) -> Option<&str> {
    match suspect_session {
        "10" => Some("10"),
        _ => None,
    }
}
