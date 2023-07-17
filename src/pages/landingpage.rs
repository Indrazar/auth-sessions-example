use crate::pages::components::{logheader::LogHeader, redirect::LoggedInRedirect};
use leptos::*;

/// Renders the non-logged in landing page. Redirects if logged in.
#[component]
pub fn LandingPage(cx: Scope) -> impl IntoView {
    view! { cx,
        <LoggedInRedirect
            success_route=Some(String::from("/home"))
            fail_route=Some(String::from("/landing"))
        />
        <CoreLandingPage/>
    }
}

#[component]
pub fn CoreLandingPage(cx: Scope) -> impl IntoView {
    view! { cx,
        <h1>"Auth-Sessions-Example"</h1>
        <h2>"A Letpos HTTPS Auth Example"</h2>
        <LogHeader/>
        <p><a href="/signup" class="button-white">"Sign Up"</a></p>
        <p><a href="/login" class="button-blue">"Login"</a></p>
    }
}
