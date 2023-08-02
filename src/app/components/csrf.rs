use cfg_if::cfg_if;
use leptos::*;
use leptos_router::use_location;

cfg_if! { if #[cfg(feature = "ssr")] {
    use crate::security::generate_csrf;
}}

/// This component forces SSR to resolve in an async route.
/// This will add a hidden input field to any ActionForm which can be used
/// to mitigate CSRF attacks using a __Host-csrf cookie
#[allow(unused_braces)]
#[component]
pub fn CSRFField<I: 'static, O: 'static>(submit_action: Action<I, O>) -> impl IntoView {
    let csrf_resource = create_resource(
        move || (), //use_location().search.get()), //submit_action.version().get()),
        move |_| {
            log::trace!("CSRF retriever running fetcher");
            issue_csrf()
        },
    );
    let (csrf, set_csrf) = create_signal(String::default());

    //create_effect(move |_| {
    //    csrf_resource.
    //});

    view! {
        <Suspense fallback=move || view! { "Loading..." }>
            {move || {
                csrf_resource.read().map(|n| match n {
                    Err(e) => view! {
                        { format!("Page Load Failed: {e}. Please reload the page or try again later.") }
                    }.into_view(),
                    Ok(csrf_hash) => {
                        view! {
                            <input name="csrf" dissabled value=csrf_hash/>} //type="hidden"
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
