use cfg_if::cfg_if;
use leptos::*;

cfg_if! { if #[cfg(feature = "ssr")] {
    //use crate::cookies::set_ssr_cookie;
    use crate::cookies::validate_session;
    //use leptos_axum::redirect;
}}

cfg_if! { if #[cfg(not(feature = "ssr"))] {
    use leptos_router::NavigateOptions;
}}

/// This component forces SSR to resolve and will leave behind a javascript-
/// enabled session cookie in the header which the WASM will read on load
/// if the cookie is present then the WASM will not double-send
/// if the cookie is not present then WASM will assume it navigated here
/// through the hydration.
#[component]
pub fn LoggedInRedirect(
    cx: Scope,
    success_route: Option<String>,
    fail_route: Option<String>,
) -> impl IntoView {
    #[cfg(not(feature = "ssr"))]
    {
        let redirect_action = create_server_action::<ProcessRedirect>(cx);
        redirect_action.dispatch(ProcessRedirect {});
        create_effect(cx, move |_| {
            match redirect_action.value().get() {
                //redirect to success_route if present
                Some(Ok(true)) => match &success_route {
                    Some(route) => {
                        leptos::log!("session was valid, redirecting to {route}");
                        match leptos_router::use_navigate(cx)(
                            route.as_str(),
                            NavigateOptions::default(),
                        ) {
                            Ok(_) => {}
                            Err(e) => {
                                leptos::log!("{:#?}", e);
                            }
                        }
                    }
                    None => {
                        //if no success_route do nothing
                        leptos::log!("session was valid, no redirect");
                    }
                },
                Some(Ok(false)) => match &fail_route {
                    Some(route) => {
                        //redirect to fail_route if present
                        leptos::log!("session was invalid, redirecting to {route}");
                        match leptos_router::use_navigate(cx)(
                            route.as_str(),
                            NavigateOptions::default(),
                        ) {
                            Ok(_) => {}
                            Err(e) => {
                                leptos::log!("{:#?}", e);
                            }
                        }
                    }
                    None => {
                        //if no fail_route do nothing
                        leptos::log!("session was invalid, no redirect");
                    }
                },
                _ => {} // still waiting for action to complete
            }
        });
    }

    view! {cx, <></>} // redirect is non-visible
}

#[server(ProcessRedirect, "/api")]
async fn process_redirect(cx: Scope) -> Result<bool, ServerFnError> {
    match validate_session(cx).await? {
        None => Ok(false),
        Some(_) => Ok(true),
    }
}
