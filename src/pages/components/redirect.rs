#[cfg(not(feature = "ssr"))]
use crate::cookies::consume_ssr_cookie;
#[cfg(feature = "ssr")]
use crate::cookies::set_ssr_cookie;
#[cfg(feature = "ssr")]
use crate::cookies::validate_session;
use leptos::*;
#[cfg(feature = "ssr")]
use leptos_axum::redirect;
#[cfg(feature = "ssr")]
use leptos_axum::ResponseOptions;
#[cfg(not(feature = "ssr"))]
use leptos_router::NavigateOptions;
#[cfg(not(feature = "ssr"))]
use leptos_router::State;

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
                        Some(route) => redirect(cx, route.as_str()),
                        //if none, set ssr cookie
                        None => set_ssr_cookie(cx),
                    }
                }
                false => {
                    match fail_route {
                        //redirect to fail_route if present
                        Some(route) => redirect(cx, route.as_str()),
                        //if none, set ssr cookie
                        None => set_ssr_cookie(cx),
                    }
                }
            }
        }
        None => {}
    }

    #[cfg(not(feature = "ssr"))]
    match consume_ssr_cookie(cx) {
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
            //this maps server response failure the same as if you faild the redirect check
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
                        match leptos_router::use_navigate(cx)(
                            route.as_str(),
                            NavigateOptions {
                                resolve: false,
                                replace: true,
                                scroll: true,
                                state: State(None),
                            },
                        ) {
                            Ok(_) => {}
                            Err(e) => leptos::log!("{:#?}", e),
                        }
                    }
                    None => {} //if no success_route do nothing
                }, // if no success_route do nothing
                //redirect to fail_route if present
                false => match fail_route {
                    Some(route) => {
                        match leptos_router::use_navigate(cx)(
                            route.as_str(),
                            NavigateOptions {
                                resolve: false,
                                replace: true,
                                scroll: true,
                                state: State(None),
                            },
                        ) {
                            Ok(_) => {}
                            Err(e) => leptos::log!("{:#?}", e),
                        }
                    }
                    None => {} //if no fail_route do nothing
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
