use cfg_if::cfg_if;

cfg_if! { if #[cfg(feature = "ssr")] {
    use crate::database::{associate_session, validate_token};
    use axum::{
        http::header::{COOKIE, SET_COOKIE},
        http::HeaderValue,
    };
    use chrono::prelude::*;
    use leptos::*;
    use leptos_axum::RequestParts;
    use uuid::Uuid;
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
    validate_token(unverified_session_id).await
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
