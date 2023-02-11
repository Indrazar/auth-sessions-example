use cfg_if::cfg_if;
use leptos::*;

//#[cfg(feature = "ssr")]
//use axum_extra::extract::cookie::Cookie;

cfg_if! { if #[cfg(feature = "ssr")] {
    use axum::{
        http::header::{COOKIE, SET_COOKIE},
        http::{HeaderMap, HeaderValue},
    };
    use chrono::prelude::*;
    use leptos_axum::{RequestParts, ResponseParts};
}}

// General strategy:
// When you open any page the server checks if you are logged in (has a logged-in POLYID cookie)
// if you have a POLYID cookie a different page is loaded (logged in mode)
// if you do not have a POLYID cookie only: landing page, signup page, and login pages are accessable
//
// Either way a 24h-duration scope token is provided in a cookie on page load for CSRF protection
// if the client has a token already then we keep using it, but since it is short-duration
// they will likely keep getting new tokens

#[cfg(feature = "ssr")]
fn generate_csrf_token(cx: Scope) -> String {
    if let Some(req) = use_context::<leptos_axum::RequestParts>(cx) {
        if let Some(cookies) = req.headers.get(COOKIE) {
            let stored = cookies.to_str().unwrap_or("");
            log::debug!("cookies: {:#?}", stored);
            "old".to_string()
        } else {
            // generate a new token for session
            "new".to_string()
        }
    } else {
        // generate a new token for session
        "new".to_string()
    }
}

#[cfg(not(feature = "ssr"))]
fn generate_csrf_token(cx: Scope) -> String {
    log::debug!("at client generate or use token");
    let doc = document().unchecked_into::<web_sys::HtmlDocument>();
    let cookie = doc.cookie().unwrap_or_default();
    leptos::log!("cookies: {:#?}", cookie);
    if cookie.contains("POLYID=8") {
        "old".to_string()
    } else {
        "new".to_string()
    }
}

#[cfg(feature = "ssr")]
pub fn validate_session(cx: Scope) -> bool {
    // extract request, bailing if there is none
    let http_req = match use_context::<leptos_axum::RequestParts>(cx) {
        Some(rp) => rp,       // actual user request
        None => return false, // no request, building routes in main.rs
    };
    // grab request's session, bailing if there is none
    let unverified_session_id = parse_session_cookie(http_req);
    match validate_token(unverified_session_id.as_str()) {
        true => true,
        false => return false,
    }
    // do not renew cookies every time, force logins every 30 days
    //// build header to apply renewed cookie
    //let response = use_context::<leptos_axum::ResponseOptions>(cx)
    //    .expect("to have leptos_axum::ResposneParts");
    //let expire_time: DateTime<Utc> = Utc::now() + chrono::Duration::days(30);
    //let date_string: String = expire_time.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
    //let mut response_parts = ResponseParts::default();
    //let mut headers = HeaderMap::new();
    //headers.insert(
    //    SET_COOKIE,
    //    HeaderValue::from_str(&format!(
    //        "SESSIONID={session_id}; Expires={date_string}; Secure; SameSite=Lax; HttpOnly; Path=/"
    //    ))
    //    .expect("to create header value"),
    //);
    //log::trace!("valid session renewed: {session_id}");
    //response_parts.headers = headers;
    //response.overwrite(response_parts);
}

#[cfg(feature = "ssr")]
fn parse_session_cookie(req: RequestParts) -> String {
    let cookies = match req.headers.get(COOKIE) {
        Some(t) => t.to_str().unwrap_or_default(),
        None => return String::default(),
    };
    match get_cookie_value(cookies, "SESSIONID") {
        Some(t) => t,
        None => String::default(),
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
fn validate_token(suspect_session: &str) -> bool {
    match suspect_session {
        "10" => true,
        _ => false,
    }
}

#[cfg(feature = "ssr")]
pub fn set_ssr_cookie(cx: Scope) {
    // if we are in the router then do not attempt to set the ssr cookie
    // build header to apply renewed cookie
    let response = match use_context::<leptos_axum::ResponseOptions>(cx) {
        Some(ro) => ro,
        None => return,
    };
    response.append_header(
        SET_COOKIE,
        HeaderValue::from_str("ssr=true; SameSite=Lax; Path=/").expect("to create header value"),
    );
    log::trace!("redirect set an ssr cookie");
}

#[cfg(not(feature = "ssr"))]
pub fn consume_ssr_cookie() -> bool {
    let doc = document().unchecked_into::<web_sys::HtmlDocument>();
    let cookie = doc.cookie().unwrap_or_default();
    let result = cookie.contains("ssr=true");
    doc.set_cookie(
        "ssr=deleted; Expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; SameSite=Lax; Path=/",
    )
    .expect("could not delete cookie");
    result
}
