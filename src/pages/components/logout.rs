use cfg_if::cfg_if;
use leptos::*;
use leptos_router::*;

cfg_if! { if #[cfg(feature = "ssr")] {
    use axum::{
        http::header::{SET_COOKIE},
        http::{HeaderMap, HeaderValue},
    };
    use leptos_axum::{ResponseParts};

}}

#[component]
pub fn LogoutButton(cx: Scope) -> impl IntoView {
    let logout = create_server_action::<DestroySession>(cx);

    view! { cx,
        <ActionForm action=logout>
        //<a href="/">
            <input class="logout-button" type="submit" value="Logout"/>
        //</a>
        </ActionForm>
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
