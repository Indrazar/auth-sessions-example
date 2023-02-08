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

mod loginpage;
use loginpage::*;

pub mod error_template;

cfg_if! { if #[cfg(feature = "ssr")] {
    use axum::{
        http::header::{SET_COOKIE},
        http::{HeaderMap, HeaderValue},
    };
    use leptos_axum::{ResponseParts};

    pub fn register_server_functions() -> Result<(), ServerFnError> {
        landingpage::register_server_functions()?;
        signuppage::register_server_functions()?;
        //loginpage::register_server_functions()?;
        DestroySession::register()?;
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

    view! {
        cx,

        // injects a stylesheet into the document <head>
        // id=leptos means cargo-leptos will hot-reload this stylesheet
        <Stylesheet id="leptos" href="/pkg/auth_example.css"/>

        // sets the document title
        <Title text="Auth-Example: A Letpos HTTPS Auth Example"/>

        // content for this app
        <Router>
            <main>
                <Routes>
                    <Route path="" view=|cx| view! { cx, <LandingPage/> }/>
                    <Route path="/register" view=|cx| view! { cx, <SignupPage/> }/>
                    <Route path="/login" view=|cx| view! { cx, <LoginPage/> }/>
                    <Route path="/logout" view=|cx| view! { cx, <Logout/> }/>
                </Routes>
            </main>
        </Router>
    }
}

#[component]
pub fn Logout(cx: Scope) -> impl IntoView {
    #[cfg(feature = "ssr")]
    destroy_session(cx);

    #[cfg(not(feature = "ssr"))]
    let this_session = create_server_action::<DestroySession>(cx);
    #[cfg(not(feature = "ssr"))]
    let session_resource = create_resource(
        cx,
        move || (this_session.version().get()),
        move |_| server_destroy_session(cx),
    );

    view! { cx,
        <h1>"Auth-Example"</h1>
        <h2>"You have been logged out."</h2>
        <h3><A href="/">"Click Here to return to the main page"</A></h3>
    }
}

#[server(DestroySession, "/api")]
pub async fn server_destroy_session(cx: Scope) -> Result<(), ServerFnError> {
    destroy_session(cx);
    Ok(())
}

#[cfg(feature = "ssr")]
fn destroy_session(cx: Scope) {
    log::trace!("user logged out");
    let response = match use_context::<leptos_axum::ResponseOptions>(cx) {
        Some(rp) => rp, // actual user request
        None => return, // no request, building routes in main.rs
    };
    let mut response_parts = ResponseParts::default();
    let mut headers = HeaderMap::new();
    headers.insert(
        SET_COOKIE,
        HeaderValue::from_str(&format!(
            "SESSIONID=deleted; Expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; Secure; SameSite=Lax; HttpOnly; Path=/"
        ))
        .expect("to create header value"),
    );
    response_parts.headers = headers;
    response.overwrite(response_parts);
}
