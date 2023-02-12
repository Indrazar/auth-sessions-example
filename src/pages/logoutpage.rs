use crate::pages::components::logheader::{LogHeader, LogHeaderProps};
use cfg_if::cfg_if;
use leptos::*;

cfg_if! { if #[cfg(feature = "ssr")] {
    use crate::cookies::set_ssr_cookie;
    use axum::{
        http::header::SET_COOKIE,
        http::HeaderValue,
    };

    pub fn register_server_functions() -> Result<(), ServerFnError> {
        DestroySession::register()?;
        Ok(())
    }
}}

cfg_if! { if #[cfg(not(feature = "ssr"))] {
    use crate::cookies::consume_ssr_cookie;
}}

#[component]
pub fn LogoutPage(cx: Scope) -> impl IntoView {
    let mut ssr_state: bool = false;
    cfg_if! { if #[cfg(feature = "ssr")] {
        destroy_session(cx);
        set_ssr_cookie(cx);
    }}

    #[cfg(not(feature = "ssr"))]
    match consume_ssr_cookie(&mut ssr_state) {
        true => {
            //do nothing, ssr handled it
        }
        false => {
            //ssr did not run, so we tell the server to expire our httponly cookie
            let destroy_action = create_server_action::<DestroySession>(cx);
            destroy_action.dispatch(DestroySession {});
        }
    }

    view! {cx,
        <h1>"Auth-Example"</h1>
        <h2>"Logout Page"</h2>
        <p><LogHeader/></p>
        <p><a href="/">"Return to Landing Page"</a></p>
        <p><a href="/login">"Login Again"</a></p>
    }
}

#[server(DestroySession, "/api")]
async fn server_destroy_session(cx: Scope) -> Result<(), ServerFnError> {
    destroy_session(cx);
    Ok(())
}

#[cfg(feature = "ssr")]
fn destroy_session(cx: Scope) {
    let response = match use_context::<leptos_axum::ResponseOptions>(cx) {
        Some(rp) => rp, // actual user request
        None => return, // no request, building routes in main.rs
    };
    response.append_header(
        SET_COOKIE,
        HeaderValue::from_str(
            "SESSIONID=deleted; Expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; Secure; SameSite=Lax; HttpOnly; Path=/"
        )
        .expect("to create header value"),
    );
    log::trace!("user logged out");
}
