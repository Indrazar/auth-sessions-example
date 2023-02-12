use cfg_if::cfg_if;
use leptos::*;

cfg_if! { if #[cfg(feature = "ssr")] {
    use crate::cookies::set_ssr_cookie;
    //use crate::cookies::validate_session;
    use crate::cookies::generate_csrf;
    use leptos_axum::redirect;
    use leptos_axum::ResponseOptions;
}}

cfg_if! { if #[cfg(not(feature = "ssr"))] {
    use crate::cookies::consume_ssr_cookie;
    use leptos_router::NavigateOptions;
    //use leptos_router::State;
    use std::time::Duration;
}}

/// This component forces SSR to resolve and will leave behind a javascript-
/// enabled session cookie in the header which the WASM will read on load
/// if the cookie is present then the WASM will not double-send
/// if the cookie is not present then WASM will assume it navigated here
/// through the hydration.
#[component]
pub fn CSRFField(cx: Scope /*, ssr_state: &'a mut bool */) -> impl IntoView {
    let csrf_action = create_server_action::<IssueCSRF>(cx);
    let csrf_resource = create_resource(
        cx,
        move || (csrf_action.version().get()),
        move |_| {
            log::trace!("CSRF retriever running fetcher");
            issue_csrf(cx)
        },
    );
    let csrf_string = move || {
        csrf_resource
            .read()
            .map(|n| n.ok())
            .flatten()
            .map(|n| n)
            .unwrap_or(String::default())
    };

    /*#[cfg(feature = "ssr")]
    match use_context::<ResponseOptions>(cx) {
        //todo remove this match statement once it doesn't panic
        Some(_) => {
            log::trace!("generating CSRF cookie and field value");
            csrf_string = generate_csrf(cx);
            set_ssr_cookie(cx);
        }
        None => {}
    }

    #[cfg(not(feature = "ssr"))]
    match consume_ssr_cookie(ssr_state) {
        true => {
            //do nothing, ssr handled it
        }
        false => {
            //ssr did not run, so we query the server

            csrf_action.dispatch(IssueCSRF {});
            create_effect(cx, move |_| {
                match csrf_action.value().get() {
                    //redirect to success_route if present
                    Some(Ok(action_result)) => {
                        csrf_string = action_result;
                        leptos::log!("recieved csrf: {csrf_string}");
                    }
                    _ => {} // still waiting for action to complete
                }
            });
        }
    }*/

    // csrf component add a hidden field to forms
    view! {cx, <input type="hidden" name="csrf" value=csrf_string()/>}
}

#[server(IssueCSRF, "/api")]
async fn issue_csrf(cx: Scope) -> Result<String, ServerFnError> {
    Ok(generate_csrf(cx))
}
