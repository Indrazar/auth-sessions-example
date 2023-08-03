use cfg_if::cfg_if;
use leptos::*;

cfg_if! { if #[cfg(feature = "ssr")] {
    use crate::security::generate_csrf;
}}

/// This component forces SSR to resolve in an async route.
/// This will add a hidden input field to any ActionForm which can be used
/// to mitigate CSRF attacks using a __Host-csrf cookie
#[allow(unused_braces)]
#[component]
pub fn CSRFField() -> impl IntoView {
    let csrf_resource = create_resource(move || (), move |_| issue_csrf());

    view! {
        <Suspense fallback=move || view! { "Loading..." }>
            {move || {
                csrf_resource.read().map(|n| match n {
                    Err(e) => view! {
                        { format!("Page Load Failed: {e}. Please reload the page or try again later.") }
                    }.into_view(),
                    Ok(csrf_hash) => {
                        view! {
                            <input type="hidden" name="csrf" value=csrf_hash/>}
                        }.into_view()
                    })
                }
            }
        </Suspense>
    }
}

#[server(IssueCSRF, "/api")]
async fn issue_csrf() -> Result<String, ServerFnError> {
    Ok(generate_csrf())
}
