use crate::pages::components::logheader::*;
use crate::pages::components::redirect::*;
use cfg_if::cfg_if;
use leptos::*;

cfg_if! { if #[cfg(feature = "ssr")] {
    pub fn register_server_functions() -> Result<(), ServerFnError> {
        ProcessLandingPage::register()?;
        Ok(())
    }
}}

/// Renders the non-logged in landing page. Redirects if logged in.
#[component]
pub fn LandingPage(cx: Scope) -> impl IntoView {
    view! { cx,
        <LoggedInRedirect
            success_route=Some("/home".to_string())
            fail_route=None
        />
        <h1>"Auth-Example"</h1>
        <h2>"A Letpos HTTPS Auth Example"</h2>
        <p><LogHeader/></p>
        <p><a href="/register" class="button-white">"Sign Up"</a></p>
        <p><a href="/login" class="button-blue">"Login"</a></p>
    }
}
