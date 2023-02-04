use cfg_if::cfg_if;
use leptos::*;
use leptos_meta::*;
use leptos_reactive::*;
use leptos_router::*;
//use leptos_axum::*;
use serde::{Deserialize, Serialize};

mod landingpage;
use landingpage::*;

mod signuppage;
use signuppage::*;

pub mod error_template;

cfg_if! { if #[cfg(feature = "ssr")] {
    pub fn register_server_functions() -> Result<(), ServerFnError> {
        _ = landingpage::register_server_functions()?;
        _ = signuppage::register_server_functions()?;
        _ = RetrieveSession::register()?;
        //_ = AddTodo::register();
        //_ = DeleteTodo::register();
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
    let retrieve_token = create_server_action::<RetrieveSession>(cx);

    view! {
        cx,

        // injects a stylesheet into the document <head>
        // id=leptos means cargo-leptos will hot-reload this stylesheet
        <Stylesheet id="leptos" href="/pkg/auth-example.css"/>

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
pub async fn retrieve_session(cx: Scope, session_id: String) -> Result<String, ServerFnError> {
    use axum::{
        http::header::SET_COOKIE,
        http::{HeaderMap, HeaderValue},
    };

    leptos::log!(
        "reached generate_or_use_session(), session_id: {:#?}",
        session_id
    );

    let http_req =
        use_context::<leptos_axum::RequestParts>(cx).expect("to have leptos_axum::RequestParts");
    let response = use_context::<leptos_axum::ResponseOptions>(cx)
        .expect("to have leptos_axum::ResposneParts");
    let mut response_parts = leptos_axum::ResponseParts::default();
    let mut headers = HeaderMap::new();
    headers.insert(
        SET_COOKIE,
        HeaderValue::from_str(&format!(
            "POLYID={session_id}; Secure; SameSite=Strict; HttpOnly; Path=/"
        ))
        .expect("to create header value"),
    );
    response_parts.headers = headers;

    response.overwrite(response_parts);
    Ok(session_id)
}
