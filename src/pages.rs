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
    //landingpage::register_server_functions()?;
    signuppage::register_server_functions()?;
    homepage::register_server_functions()?;
    loginpage::register_server_functions()?;
    logoutpage::register_server_functions()?;
    components::register_server_functions()?;
    Ok(())
}

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
                    <Route path="/landing" view=|cx| view! {cx, <CoreLandingPage/> }/>
                    <Route path="/register" view=|cx| view! { cx, <SignupPage/> }/>
                    <Route path="/login" view=|cx| view! { cx, <LoginPage/> }/>
                    <Route path="/home" view=|cx| view! { cx, <HomePage/> }/>
                    <Route path="/logout" view=|cx| view! {cx, <LogoutPage/> }/>
                </Routes>
            </main>
        </Router>
    }
}
