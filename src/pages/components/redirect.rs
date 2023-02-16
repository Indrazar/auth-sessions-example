use cfg_if::cfg_if;
use leptos::*;

cfg_if! { if #[cfg(feature = "ssr")] {
    use crate::cookies::set_ssr_cookie;
    use crate::cookies::validate_session;
    use leptos_axum::redirect;
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
pub fn LoggedInRedirect<'a>(
    cx: Scope,
    success_route: Option<String>,
    fail_route: Option<String>,
    ssr_state: &'a mut bool,
) -> impl IntoView {
    #[cfg(feature = "ssr")]
    match validate_session(cx) {
        true => {
            match success_route {
                //redirect to success_route if present
                Some(route) => {
                    log::trace!("session was valid, redirecting to {route}");
                    redirect(cx, route.as_str());
                    set_ssr_cookie(cx);
                }
                //if none, set ssr cookie
                None => {
                    log::trace!("session was valid, no redirect");
                    set_ssr_cookie(cx);
                }
            }
        }
        false => {
            match fail_route {
                //redirect to fail_route if present
                Some(route) => {
                    log::trace!("session was invalid, redirecting to {route}");
                    redirect(cx, route.as_str());
                    set_ssr_cookie(cx);
                }
                //if none, set ssr cookie
                None => {
                    log::trace!("session was invalid, no redirect");
                    set_ssr_cookie(cx);
                }
            }
        }
    }

    #[cfg(not(feature = "ssr"))]
    match consume_ssr_cookie(ssr_state) {
        true => {
            //do nothing to the page, ssr handled it
        }
        false => {
            //ssr did not run, so we query the server
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
    }

    view! {cx, <></>} // redirect is non-visible
}

#[server(ProcessRedirect, "/api")]
async fn process_redirect(cx: Scope) -> Result<bool, ServerFnError> {
    Ok(validate_session(cx))
}
