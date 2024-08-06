use cfg_if::cfg_if;
use leptos::{either::Either, prelude::*};
use leptos_reactive::{create_resource, SignalGet};

cfg_if! { if #[cfg(feature = "ssr")] {
    use crate::security::generate_csrf;

}}

/// This component forces SSR to resolve in an async route.
/// This will add a hidden input field to any ActionForm which can be used
/// to mitigate CSRF attacks using a __Host-csrf cookie
#[allow(unused_braces)]
#[component]
pub fn CSRFField() -> impl IntoView {
    let csrf_resource = create_resource(|| (), move |_| issue_csrf());

    view! {
        <Suspense fallback= || { "Loading..." }>
            {move || {
                csrf_resource.get().map(|n| match n {
                    Err(e) => Either::Left(view! {
                        { format!("Page Load Failed: {e}. Please reload the page or try again later.") }
                    }),
                    Ok(csrf_hash) => Either::Right(
                        view! {
                            <input type="hidden" name="csrf" value=csrf_hash/>
                        }
                    ),
                })
            }}
        </Suspense>
    }
}

// #[server(IssueCSRF, "/api")]
#[server]
async fn issue_csrf() -> Result<String, ServerFnError> {
    Ok(generate_csrf())
}
