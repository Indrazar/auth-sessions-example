use cfg_if::cfg_if;
use leptos::*;

cfg_if! { if #[cfg(feature = "ssr")] {
    use crate::security::generate_csrf;
}}

/// This component forces SSR to resolve in an async route.
/// This will add a hidden input field to any ActionForm which can be used
/// to mitigate CSRF attacks using a __Host-csrf cookie
#[component]
pub fn CSRFField(cx: Scope) -> impl IntoView {
    let csrf_action = create_server_action::<IssueCSRF>(cx);
    let csrf_resource = create_resource(
        cx,
        move || (csrf_action.version().get()),
        move |_| {
            log::trace!("CSRF retriever running fetcher");
            issue_csrf(cx)
        },
    );

    view! { cx,
        <Suspense fallback={move || view! {cx, <div>"Loading..."</div>}}>
            {move || {
                csrf_resource.read(cx).map(|n| match n {
                    Err(_) => view! {cx, <div>"Page Load Failed. Please reload the page or try again later."</div>},
                    Ok(csrf) => view! {cx, <div><input type="hidden" name="csrf" value=csrf/></div>},
                })
            }}
        </Suspense>
    }
}

#[server(IssueCSRF, "/api")]
async fn issue_csrf(cx: Scope) -> Result<String, ServerFnError> {
    Ok(generate_csrf(cx))
}
