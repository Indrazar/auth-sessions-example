use cfg_if::cfg_if;
use leptos::*;

cfg_if! { if #[cfg(feature = "ssr")] {
    use crate::database::pool;
    use crate::cookies::validate_session;
    use leptos_axum::redirect;
}}

cfg_if! { if #[cfg(not(feature = "ssr"))] {
    use leptos_router::NavigateOptions;
}}

/// This component forces SSR to resolve on async ssr routes. If the client
/// has a valid session cookie the client will be redirected to the
/// success_route if one exists. If the client does not have a valid session
/// cookie the client will be redirected to the fail_route if one exists.
#[component]
pub fn LoggedInRedirect(
    cx: Scope,
    success_route: Option<String>,
    fail_route: Option<String>,
) -> impl IntoView {
    let redirect_action = create_server_action::<ProcessRedirect>(cx);
    let redirect_resource = create_resource(
        cx,
        move || (redirect_action.version().get()),
        move |_| {
            log::trace!("redirect retriever running fetcher");
            process_redirect(cx)
        },
    );
    let redirect_result = move || {
        redirect_resource.read(cx).map(|n| {
            match n {
                //redirect to success_route if present
                Ok(true) => match &success_route {
                    Some(route) => {
                        log::trace!("session was valid, redirecting to {route}");

                        #[cfg(feature = "ssr")]
                        redirect(cx, route.as_str());

                        #[cfg(not(feature = "ssr"))]
                        match leptos_router::use_navigate(cx)(
                            route.as_str(),
                            NavigateOptions::default(),
                        ) {
                            Ok(_) => (),
                            Err(e) => {
                                log::error!("{:#?}", e);
                            }
                        }
                    }
                    None => {
                        //if no success_route do nothing
                        log::trace!("session was valid, no redirect");
                    }
                },
                Ok(false) => match &fail_route {
                    Some(route) => {
                        //redirect to fail_route if present
                        log::trace!("session was invalid, redirecting to {route}");

                        #[cfg(feature = "ssr")]
                        redirect(cx, route.as_str());

                        #[cfg(not(feature = "ssr"))]
                        match leptos_router::use_navigate(cx)(
                            route.as_str(),
                            NavigateOptions::default(),
                        ) {
                            Ok(_) => (),
                            Err(e) => {
                                log::error!("{:#?}", e);
                            }
                        }
                    }
                    None => {
                        //if no fail_route do nothing
                        log::trace!("session was invalid, no redirect");
                    }
                },
                Err(e) => match &fail_route {
                    Some(route) => {
                        //redirect to fail_route if present
                        log::trace!("{e}, redirecting to fail_route: {route}");

                        #[cfg(feature = "ssr")]
                        redirect(cx, route.as_str());

                        #[cfg(not(feature = "ssr"))]
                        match leptos_router::use_navigate(cx)(
                            route.as_str(),
                            NavigateOptions::default(),
                        ) {
                            Ok(_) => (),
                            Err(e) => {
                                log::error!("{:#?}", e);
                            }
                        }
                    }
                    None => {
                        //if no fail_route do nothing
                        log::trace!("{e}, no redirect");
                    }
                },
            }
        })
    };

    view! {cx,
        <Suspense fallback={|| view!{cx, <></>}}>
        <>{redirect_result()}</>
        </Suspense>
    } // redirect is non-visible
}

#[server(ProcessRedirect, "/api")]
async fn process_redirect(cx: Scope) -> Result<bool, ServerFnError> {
    let pool = pool(cx)?;
    match validate_session(cx, &pool).await? {
        None => Ok(false),
        Some(_) => Ok(true),
    }
}
