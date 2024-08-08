use cfg_if::cfg_if;

cfg_if! { if #[cfg(feature = "ssr")] {
    use crate::database::{associate_session, drop_session, validate_token};
    use crate::defs::{DatabaseError, RouterError, AppError};
    use axum::{
        http::header::{COOKIE, SET_COOKIE},
        http::HeaderValue,
    };
    use chrono::prelude::*;
    use leptos::prelude::*;
    use http::request::Parts;
    use uuid::Uuid;
}}

#[cfg(feature = "ssr")]
pub async fn destroy_session() {
    let response = match use_context::<leptos_axum::ResponseOptions>() {
        Some(rp) => rp, // actual user request
        None => return, // no request, building routes in main.rs
    };
    response.append_header(
        SET_COOKIE,
        HeaderValue::from_str(
            "SESSIONID=deleted; Expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; Secure; \
             SameSite=Lax; HttpOnly; Path=/",
        )
        .expect("to create header value"),
    );
    // grab request, bailing if there is none
    let http_req = match use_context::<Parts>() {
        Some(rp) => rp, // actual user request
        None => return, // no request, building routes in main.rs
    };
    // grab request's session
    let unverified_session_id = parse_session_req_parts_cookie(http_req);
    let _ = drop_session(&unverified_session_id).await;
}

#[cfg(feature = "ssr")]
pub async fn issue_session_cookie(user_id: Uuid, session_id: String) -> Result<(), AppError> {
    let response = match use_context::<leptos_axum::ResponseOptions>() {
        Some(ro) => Ok(ro),
        None => {
            log::error!("issue_session_cookie: no response options available");
            Err(RouterError::HTTPRequestMissing)
        }
    }?;
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
pub async fn validate_session() -> Result<Option<Uuid>, DatabaseError> {
    // grab request, bailing if there is none
    let http_req = match use_context::<Parts>() {
        Some(rp) => rp,          // actual user request
        None => return Ok(None), // no request, building routes in main.rs
    };
    // grab request's session
    let unverified_session_id = parse_session_req_parts_cookie(http_req);
    validate_token(unverified_session_id).await
    // do not renew cookies every time, force logins every 30 days
}

#[cfg(feature = "ssr")]
pub fn parse_session_header_cookie(cookies: &str) -> String {
    if let Some(session) = get_cookie_value(cookies, "SESSIONID") {
        return session;
    }
    String::default()
}

#[cfg(feature = "ssr")]
pub fn parse_session_req_parts_cookie(req: Parts) -> String {
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
