use cfg_if::cfg_if;
use leptos::*;

cfg_if! { if #[cfg(feature = "ssr")] {
    use crate::cookies::set_ssr_cookie;
    use crate::cookies::validate_session;
    use leptos_axum::redirect;
    use leptos_axum::ResponseOptions;
}}

cfg_if! { if #[cfg(not(feature = "ssr"))] {
    use leptos_router::NavigateOptions;
    //use leptos_router::State;
    use crate::cookies::consume_ssr_cookie;
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
    #[cfg(feature = "ssr")]
    match use_context::<ResponseOptions>(cx) {
        //todo remove this match statement once it doesn't panic
        Some(_) => {
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
                            set_ssr_cookie(cx)
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
                            set_ssr_cookie(cx)
                        }
                    }
                }
            }
        }
        None => {}
    }

    #[cfg(not(feature = "ssr"))]
    match consume_ssr_cookie() {
        true => {
            //do nothing, ssr handled it
        }
        false => {
            //ssr did not run, so we query the server
            let redirect_action = create_server_action::<ProcessRedirect>(cx);
            let redirect_result = create_resource(
                cx,
                move || (redirect_action.version().get()),
                move |_| process_redirect(cx),
            );
            //this maps server response failure the same as if you failed the redirect check
            let redirect_check = move || {
                redirect_result
                    .read()
                    .map(|val| val.unwrap_or(false))
                    .unwrap_or(false)
            };
            match redirect_check() {
                //redirect to success_route if present
                true => match success_route {
                    Some(route) => {
                        leptos::log!("session was valid, redirecting to {route}");
                        match leptos_router::use_navigate(cx)(
                            route.as_str(),
                            NavigateOptions::default(),
                        ) {
                            Ok(_) => {}
                            Err(e) => leptos::log!("{:#?}", e),
                        }
                    }
                    None => {
                        leptos::log!("session was valid, no redirect");
                    } //if no success_route do nothing
                }, // if no success_route do nothing
                //redirect to fail_route if present
                false => match fail_route {
                    Some(route) => {
                        leptos::log!("session was invalid, redirecting to {route}");
                        match leptos_router::use_navigate(cx)(
                            route.as_str(),
                            NavigateOptions::default(),
                        ) {
                            Ok(_) => {}
                            Err(e) => leptos::log!("{:#?}", e),
                        }
                    }
                    None => {
                        leptos::log!("session was invalid, no redirect");
                    } //if no fail_route do nothing
                },
            };
        }
    }

    view! {cx, <div>"Redirect Present"</div>}
}

#[server(ProcessRedirect, "/api")]
async fn process_redirect(cx: Scope) -> Result<bool, ServerFnError> {
    Ok(validate_session(cx))
}
