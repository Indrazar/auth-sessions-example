use cfg_if::cfg_if;
use leptos::*;

cfg_if! { if #[cfg(feature = "ssr")] {
    use crate::database::{associate_session, validate_token};
    use axum::{
        http::header::{COOKIE, SET_COOKIE},
        http::HeaderValue,
    };
    use chrono::prelude::*;
    use leptos_axum::RequestParts;
    use uuid::Uuid;
} else {
    use wasm_bindgen::JsCast;
}}

#[cfg(feature = "ssr")]
pub async fn issue_session_cookie(
    cx: Scope,
    user_id: Uuid,
    session_id: String,
) -> Result<(), ServerFnError> {
    let response = match use_context::<leptos_axum::ResponseOptions>(cx) {
        Some(ro) => ro,
        None => {
            return Err(ServerFnError::ServerError(String::from(
                "Login Request failed.",
            )))
        }
    };
    let expire_time: DateTime<Utc> = Utc::now() + chrono::Duration::days(30);
    let date_string: String = expire_time.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
    associate_session(user_id, &session_id, expire_time).await?;
    response.append_header(
        SET_COOKIE,
        HeaderValue::from_str(&format!(
            "SESSIONID={session_id}; Expires={date_string}; Secure; SameSite=Lax; HttpOnly; \
             Path=/"
        ))
        .expect("to create header value"),
    );
    Ok(())
}

#[cfg(feature = "ssr")]
pub async fn validate_session(cx: Scope) -> Result<Option<Uuid>, ServerFnError> {
    // extract request, bailing if there is none
    let http_req = match use_context::<RequestParts>(cx) {
        Some(rp) => rp,          // actual user request
        None => return Ok(None), // no request, building routes in main.rs
    };
    // grab request's session, bailing if there is none
    let unverified_session_id = parse_session_cookie(http_req);
    Ok(validate_token(unverified_session_id).await?)
    // do not renew cookies every time, force logins every 30 days
    //// build header to apply renewed cookie
    //let response = match use_context::<leptos_axum::ResponseOptions>(cx) {
    //    Some(ro) => ro,
    //    None => return,
    //};
    //let expire_time: DateTime<Utc> = Utc::now() + chrono::Duration::days(30);
    //let date_string: String = expire_time.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
    //response.append_header(
    //    SET_COOKIE,
    //    HeaderValue::from_str("ssr=true; SameSite=Lax; Path=/").expect("to create header value"),
    //);
    //log::trace!("valid session renewed: {session_id}");
}

#[cfg(feature = "ssr")]
fn parse_session_cookie(req: RequestParts) -> String {
    for headercookie in req.headers.get_all(COOKIE).iter() {
        match headercookie.to_str() {
            Ok(cookie) => {
                if let Some(session) = get_cookie_value(cookie, "SESSIONID") {
                    return session;
                }
            }
            Err(_) => continue,
        }
    }
    String::default()
}

#[cfg(feature = "ssr")]
pub fn get_cookie_value(cookies: &str, key: &str) -> Option<String> {
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
pub fn set_ssr_cookie(cx: Scope) {
    // if we are in the router then do not attempt to set the ssr cookie
    // build header to apply renewed cookie
    let response = match use_context::<leptos_axum::ResponseOptions>(cx) {
        Some(ro) => ro,
        None => return,
    };
    response.append_header(
        SET_COOKIE,
        HeaderValue::from_str("ssr=true; SameSite=Lax; Path=/")
            .expect("to create header value"),
    );
    log::trace!("redirect set an ssr cookie");
}

/// consume_ssr_cookie requires a mutable reference to the ssr_state
/// this way even if the cookie was already consumed by another component then
/// this component can prevent further wasted server calls.
/// This will only work on single level scoped pages, deeply nested componenets
/// will need to relay this reference down and into it's components
#[cfg(not(feature = "ssr"))]
pub fn consume_ssr_cookie(ssr_state: &mut bool) -> bool {
    match *ssr_state {
        true => return true, /* don't need to do anything, this function already ran and consumed the cookie */
        false => {}          // continue below
    }
    let doc = document().unchecked_into::<web_sys::HtmlDocument>();
    let cookie = doc.cookie().unwrap_or_default();
    let result = cookie.contains("ssr=true");
    match result {
        true => {
            doc.set_cookie(
                "ssr=deleted; Expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; \
                 SameSite=Lax; Path=/",
            )
            .expect("could not delete cookie");
            (*ssr_state) = true;
            true
        }
        false => false,
    }
}
