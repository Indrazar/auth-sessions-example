use crate::pages::{
    components::logheader::{LogHeader, LogHeaderProps},
    components::redirect::{LoggedInRedirect, LoggedInRedirectProps},
};
use cfg_if::cfg_if;
use leptos::*;
use leptos_router::*;

cfg_if! { if #[cfg(feature = "ssr")] {
    use axum::{
        http::header::SET_COOKIE,
        http::HeaderValue,
    };
    use chrono::prelude::*;

    pub fn register_server_functions() -> Result<(), ServerFnError> {
        ForceLogin::register()?;
        Ok(())
    }
}}

/// Renders the non-logged in landing page.
#[component]
pub fn LoginPage(cx: Scope) -> impl IntoView {
    view! { cx,
        <LoggedInRedirect
            success_route=Some("/home".to_string())
            fail_route=None
        />
        <h1>"Auth-Example"</h1>
        <h2>"Login Page"</h2>
        //<button on:click=on_click>"Click Me: " {count}</button>
        <p><LogHeader/></p>
        <p><GenerateSession/></p>
        <p><a href="/home">"Check if session is valid"</a></p>
        <p><a href="/">"Return to landing page"</a></p>
    }
}

/// Renders a button that sends a post request to /api
/// On the server side this will print out all the headers provided by the client
#[component]
pub fn GenerateSession(cx: Scope) -> impl IntoView {
    let generate_valid_session = create_server_action::<ForceLogin>(cx);

    view! {
        cx,
        <div>
            <ActionForm action=generate_valid_session>
                <input type="submit" value="Produce Valid Session Token"/>
            </ActionForm>
        </div>
    }
}

#[server(ForceLogin, "/api")]
pub async fn force_login(cx: Scope) -> Result<(), ServerFnError> {
    force_create_session(cx);
    Ok(())
}

/// delete this TODO REMOVE
#[cfg(feature = "ssr")]
pub fn force_create_session(cx: Scope) {
    let session_id = "10".to_string();
    let response = match use_context::<leptos_axum::ResponseOptions>(cx) {
        Some(ro) => ro,
        None => return,
    };
    let expire_time: DateTime<Utc> = Utc::now() + chrono::Duration::days(30);
    let date_string: String = expire_time.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
    response.append_header(
        SET_COOKIE,
        HeaderValue::from_str(&format!(
            "SESSIONID={session_id}; Expires={date_string}; Secure; SameSite=Lax; HttpOnly; Path=/"
        ))
        .expect("to create header value"),
    );
    log::trace!("new session force generated: {session_id}");
}
