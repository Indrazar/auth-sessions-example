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

cfg_if! { if #[cfg(feature = "ssr")] {
    pub fn register_server_functions() -> Result<(), ServerFnError> {
        landingpage::register_server_functions()?;
        signuppage::register_server_functions()?;
        //RetrieveSession::register()?;
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
