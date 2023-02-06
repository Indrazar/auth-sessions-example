use cfg_if::cfg_if;
use leptos::*;
use leptos_meta::*;
//use leptos_reactive::*;
use leptos_router::*;
use serde::{Deserialize, Serialize};

mod landingpage;
use landingpage::*;

mod signuppage;
use signuppage::*;

pub mod error_template;

#[cfg(feature = "ssr")]
use axum::{
    http::header::{COOKIE, SET_COOKIE},
    http::{HeaderMap, HeaderValue},
};
#[cfg(feature = "ssr")]
use leptos_axum::*;

#[cfg(feature = "ssr")]
use chrono::prelude::*;

cfg_if! { if #[cfg(feature = "ssr")] {
    pub fn register_server_functions() -> Result<(), ServerFnError> {
        landingpage::register_server_functions()?;
        signuppage::register_server_functions()?;
        RetrieveSession::register()?;
        //AddTodo::register()?;
        //DeleteTodo::register()?;
        Ok(())
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ExampleData {
        id: u16,
        title: String,
        completed: bool,
    }
} else {
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ExampleData {
        id: u16,
        title: String,
        completed: bool,
    }
}}

#[component]
pub fn App(cx: Scope) -> impl IntoView {
    // Provides context that manages stylesheets, titles, meta tags, etc.
    provide_meta_context(cx);
    let this_session = create_server_action::<RetrieveSession>(cx);
    //let session_id = create_resource_with_initial_value(cx, , fetcher)
    let session_resource = create_resource(
        cx,
        move || (this_session.version().get()),
        move |_| retrieve_session(cx),
    );
    let session = move || {
        session_resource
            .read()
            .map(|n| n.ok())
            .flatten()
            .map(|n| n)
            .unwrap_or("".to_string())
    };
    //leptos::log!("{}", session());

    view! {
        cx,

        // injects a stylesheet into the document <head>
        // id=leptos means cargo-leptos will hot-reload this stylesheet
        <Stylesheet id="leptos" href="/pkg/auth_example.css"/>

        // sets the document title
        <Title text="Auth-Example: A Letpos HTTPS Auth Example"/>

        // content for this welcome page
        <Router>
            <main>
                <Routes>
                    <Route path="" view=|cx| view! { cx, <LandingPage/> }/>
                    <Route path="/register" view=|cx| view! {cx, <SignupPage/> }/>
                </Routes>
            </main>
        </Router>
    }
}

#[server(RetrieveSession, "/api")]
pub async fn retrieve_session(cx: Scope) -> Result<String, ServerFnError> {
    // this is just an example of how to access server context injected in the handlers
    //let http_req = use_context::<leptos_axum::RequestParts>(cx);
    //if let Some(http_req) = http_req {
    //    //log::debug!("http_req.path: {:#?}", &http_req.path());
    //    log::debug!(
    //        "RetrieveSession from client, printing all data from client:\n\
    //        http_req.version: {:#?}\nhttp_req.method: {:#?}\nhttp_req.uri.path(): {:#?}\nhttp_req.headers: {:#?}\nhttp_req.body: {:#?}",
    //        &http_req.version,
    //        &http_req.body,
    //        &http_req.uri.path(),
    //        &http_req.headers,
    //        &http_req.body
    //    );
    //    // ResponseOptions are more of an outbox than incoming data
    //    log::debug!(
    //        "resp_opt: {:#?}",
    //        use_context::<leptos_axum::ResponseOptions>(cx)
    //    );
    //    //log::debug!(
    //    //    "route_int_ctx: {:#?}",
    //    //    use_context::<leptos_router::RouterIntegrationContext>(cx)
    //    //);
    //    //log::debug!(
    //    //    "meta_ctx: {:#?}",
    //    //    use_context::<leptos_meta::MetaContext>(cx)
    //    //);
    //    //log::debug!("")
    //}
    let http_req =
        use_context::<leptos_axum::RequestParts>(cx).expect("to have leptos_axum::RequestParts");
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
            "SESSIONID={session_id}; Expires={date_string}; Secure; SameSite=Strict; HttpOnly; Path=/"
        ))
        .expect("to create header value"),
    );
    log::trace!("new cookie generated: {session_id}");
    response_parts.headers = headers;
    response.overwrite(response_parts);
    Ok("Session Retrieved".to_string())
}

#[cfg(feature = "ssr")]
fn determine_session_id(req: RequestParts) -> String {
    let cookies = match req.headers.get(COOKIE) {
        Some(t) => t,
        None => return generate_new_session(),
    };

    let unconfirmed_session =
        match get_cookie_value(cookies.to_str().unwrap_or_default(), "SESSIONID") {
            Some(t) => t,
            None => return generate_new_session(),
        };

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
        _ => "lol",
    }
}

#[cfg(feature = "ssr")]
fn get_cookie_value(cookies: &str, key: &str) -> Option<String> {
    cookies.split(";").find_map(|cookie| {
        let cookie_arr = cookie.split_once("=").unwrap_or_default();
        if cookie_arr.0.trim().eq(key) && !cookie_arr.1.trim().is_empty() {
            Some(cookie_arr.1.to_string())
        } else {
            None
        }
    })
}
