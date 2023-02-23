use leptos::*;
use leptos_meta::*;
use leptos_router::*;

mod landingpage;
use landingpage::*;
mod signuppage;
use signuppage::*;
mod loginpage;
use loginpage::*;
mod logoutpage;
use logoutpage::*;
mod components;
mod homepage;
use homepage::*;

pub mod error_template;

#[cfg(feature = "ssr")]
pub fn register_server_functions() -> Result<(), ServerFnError> {
    signuppage::register_server_functions()?;
    homepage::register_server_functions()?;
    loginpage::register_server_functions()?;
    logoutpage::register_server_functions()?;
    components::register_server_functions()?;
    Ok(())
}

#[cfg(feature = "ssr")]
fn set_headers(cx: Scope) {
    use axum::http::{header::CONTENT_TYPE, HeaderValue};
    let response = match use_context::<leptos_axum::ResponseOptions>(cx) {
        Some(ro) => ro,
        None => return,
    };
    //TODO remove after leptos sets this by default
    response.insert_header(
        CONTENT_TYPE,
        HeaderValue::from_static(mime::TEXT_HTML_UTF_8.as_ref()),
    );
    response.insert_header(
        axum::http::header::X_XSS_PROTECTION,
        HeaderValue::from_static("1; mode=block"),
    );
    response.insert_header(
        axum::http::header::X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY"),
    );
    response.insert_header(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, private"),
    );
    #[cfg(debug_assertions)]
    response.insert_header(
        axum::http::header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            // loading WASM apparently requires 'unsafe-inline' 'unsafe-eval'?
            "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval' 'self'; \
             connect-src 'self' ws://127.0.0.1:3001/",
        ), //media-src example.org example.net; script-src userscripts.example.com; img-src *;
    );
    #[cfg(not(debug_assertions))]
    response.insert_header(
        axum::http::header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            // loading WASM apparently requires 'unsafe-inline' 'unsafe-eval'?
            "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval' 'self'",
        ), //media-src example.org example.net; script-src userscripts.example.com; img-src *;
    );
    response.insert_header(
        axum::http::header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000"),
    )
}

#[component]
pub fn App(cx: Scope) -> impl IntoView {
    // Provides context that manages stylesheets, titles, meta tags, etc.
    provide_meta_context(cx);
    let nonce = "";

    cfg_if::cfg_if! { if #[cfg(feature = "ssr")] {
        // Set correct header for `Content-Type: text/html; charset=UTF-8`, etc.
        set_headers(cx);
    }}

    view! {
        cx,
        // injects a stylesheet into the document <head>
        // id=leptos means cargo-leptos will hot-reload this stylesheet
        <Stylesheet id="leptos" href="/pkg/auth_sessions_example.css"/>
        <Script nonce={nonce}/>

        // sets the document title
        <Title text="Auth-Sessions-Example: A Letpos HTTPS Auth Example"/>

        // content for this app
        <Router>
            <main>
                <Routes>
                    <Route path="" view=|cx| view! { cx, <LandingPage/> } ssr=SsrMode::Async/>
                    <Route path="/landing" view=|cx| view! { cx, <CoreLandingPage/> } ssr=SsrMode::Async/>
                    <Route path="/signup" view=|cx| view! { cx, <SignupPage/> } ssr=SsrMode::Async/>
                    <Route path="/login" view=|cx| view! { cx, <LoginPage/> } ssr=SsrMode::Async/>
                    <Route path="/home" view=|cx| view! { cx, <HomePage/> }/>
                    <Route path="/logout" view=|cx| view! { cx, <LogoutPage/> } ssr=SsrMode::Async/>
                </Routes>
            </main>
        </Router>
    }
}
