use cfg_if::cfg_if;
use leptos::*;

cfg_if! { if #[cfg(feature = "ssr")] {
    //use crate::cookies::set_ssr_cookie;
    //use crate::cookies::validate_session;
    use crate::security::generate_csrf;
    //use leptos_axum::redirect;
    //use leptos_axum::ResponseOptions;
}}

/// This component forces SSR to resolve and will leave behind a javascript-
/// enabled session cookie in the header which the WASM will read on load
/// if the cookie is present then the WASM will not double-send
/// if the cookie is not present then WASM will assume it navigated here
/// through the hydration.
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

    // csrf component adds a hidden field to forms to mitigate csrf
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
    //tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    Ok(generate_csrf(cx))
}
