use leptos::*;
//use leptos_meta::*;
use leptos_router::*;

#[cfg(feature = "ssr")]
pub fn register_server_functions() -> Result<(), ServerFnError> {
    APICheck::register()?;
    RetrieveSession::register()?;
    //AddTodo::register();
    //DeleteTodo::register();
    Ok(())
}
#[cfg(feature = "ssr")]
use chrono::prelude::*;
#[cfg(feature = "ssr")]
use leptos_axum::{RequestParts, ResponseParts};

#[cfg(feature = "ssr")]
use axum::{
    http::header::{COOKIE, SET_COOKIE},
    http::{HeaderMap, HeaderValue},
};

/// Renders the non-logged in landing page.
#[component]
pub fn LandingPage(cx: Scope) -> impl IntoView {
    #[cfg(feature = "ssr")]
    resolve_session(cx);

    #[cfg(not(feature = "ssr"))]
    let this_session = create_server_action::<RetrieveSession>(cx);
    #[cfg(not(feature = "ssr"))]
    let session_resource = create_resource(
        cx,
        move || (this_session.version().get()),
        move |_| retrieve_session(cx),
    );

    view! { cx,
        <h1>"Auth-Example"</h1>
        <h2>"A Letpos HTTPS Auth Example"</h2>
        <p><BackendCheck/></p>
        <p><Signup/></p>
        <p><Login/></p>
        <h3><a href="/logout">"Click Here to Log Out"</a></h3>
    }
}

/// Renders an animated Sign Up button
#[component]
fn Signup(cx: Scope) -> impl IntoView {
    view! { cx,
        <a href="/register" class="button-white">
            "Sign Up"
        </a>
    }
}

/// Renders an animated Login button
#[component]
fn Login(cx: Scope) -> impl IntoView {
    view! { cx,
        <a href="/login" class="button-blue">
            "Login"
        </a>
    }
}

//debugging tools
#[server(APICheck, "/api")]
pub async fn api_check(cx: Scope) -> Result<String, ServerFnError> {
    // this is just an example of how to access server context injected in the handlers
    let http_req = use_context::<leptos_axum::RequestParts>(cx);
    if let Some(http_req) = http_req {
        //log::debug!("http_req.path: {:#?}", &http_req.path());
        log::debug!(
            "APICheck from client, printing all data from client:\n\
            http_req.version: {:#?}\nhttp_req.method: {:#?}\nhttp_req.uri.path(): {:#?}\nhttp_req.headers: {:#?}\nhttp_req.body: {:#?}",
            &http_req.version,
            &http_req.body,
            &http_req.uri.path(),
            &http_req.headers,
            &http_req.body
        );
        // ResponseOptions are more of an outbox than incoming data
        //log::debug!("resp_opt: {:#?}", use_context::<leptos_actix::ResponseOptions>(cx));
        log::debug!(
            "route_int_ctx: {:#?}",
            use_context::<leptos_router::RouterIntegrationContext>(cx)
        );
        log::debug!(
            "meta_ctx: {:#?}",
            use_context::<leptos_meta::MetaContext>(cx)
        );
        //log::debug!("")
    }

    Ok("It worked".to_string())
}

/// Renders a button that sends a post request to /api
/// On the server side this will print out all the headers provided by the client
#[component]
pub fn BackendCheck(cx: Scope) -> impl IntoView {
    let api_check = create_server_action::<APICheck>(cx);

    view! {
        cx,
        <div>
            <ActionForm action=api_check>
                <input type="submit" value="Check the API"/>
            </ActionForm>
        </div>
    }
}

#[server(RetrieveSession, "/api")]
pub async fn retrieve_session(cx: Scope) -> Result<(), ServerFnError> {
    resolve_session(cx);
    Ok(())
}

#[cfg(feature = "ssr")]
pub fn resolve_session(cx: Scope) {
    let http_req = match use_context::<leptos_axum::RequestParts>(cx) {
        Some(rp) => rp, // actual user request
        None => return, // no request, building routes in main.rs
    };
    let session_id = determine_session_id(http_req);
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
    log::trace!("new cookie generated: {session_id}");
    response_parts.headers = headers;
    response.overwrite(response_parts);
}

#[cfg(feature = "ssr")]
fn determine_session_id(req: RequestParts) -> String {
    let cookies = match req.headers.get(COOKIE) {
        Some(t) => t.to_str().unwrap_or_default(),
        None => return generate_new_session(),
    };

    let unconfirmed_session = match get_cookie_value(cookies, "SESSIONID") {
        Some(t) => t,
        None => return generate_new_session(),
    };

    log::trace!("incoming unconfirmed sessionid: {unconfirmed_session}");
    revalidate_token(unconfirmed_session.as_str()).to_string()
}

#[cfg(feature = "ssr")]
fn generate_new_session() -> String {
    "1".to_string()
}

#[cfg(feature = "ssr")]
fn revalidate_token(suspect_session: &str) -> &str {
    match suspect_session {
        "1" => "2",
        "2" => "3",
        "3" => "4",
        "4" => "5",
        "5" => "6",
        "6" => "7",
        "7" => "8",
        "8" => "1",
        _ => "1",
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
