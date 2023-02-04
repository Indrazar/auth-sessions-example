use leptos::*;

#[cfg(feature = "ssr")]
use axum_extra::extract::cookie::Cookie;

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
    use axum::http::header::COOKIE;
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
