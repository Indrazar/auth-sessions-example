use crate::pages::components::{
    logheader::{LogHeader, LogHeaderProps},
    redirect::{LoggedInRedirect, LoggedInRedirectProps},
};
use cfg_if::cfg_if;
use leptos::*;
use leptos_router::*;

cfg_if! { if #[cfg(feature = "ssr")] {
    use crate::cookies::force_create_session;

    pub fn register_server_functions() -> Result<(), ServerFnError> {
        ForceLogin::register()?;
        Ok(())
    }
}}

/// Renders the non-logged in landing page.
#[component]
pub fn LoginPage(cx: Scope) -> impl IntoView {
    let mut ssr_state: bool = false;
    view! { cx,
        <LoggedInRedirect
            success_route=Some("/home".to_string())
            fail_route=None
            ssr_state=&mut ssr_state
        />
        <h1>"Auth-Example"</h1>
        <h2>"Login Page"</h2>
        //<button on:click=on_click>"Click Me: " {count}</button>
        <LogHeader/>
        <GenerateSession/>
        <p><a href="/home">"Check if session is valid"</a></p>
        <p><a href="/">"Return to landing page"</a></p>
    }
}

/// Renders a button that sends a post request to /api
/// On the server side this will print out all the headers provided by the client
#[component]
pub fn GenerateSession(cx: Scope) -> impl IntoView {
    #[cfg(debug_assertions)]
    let generate_valid_session = create_server_action::<ForceLogin>(cx);

    #[cfg(debug_assertions)]
    view! {
        cx,
        <p>
            <ActionForm action=generate_valid_session>
                <input type="submit" value="Produce Valid Session Token"/>
            </ActionForm>
        </p>
    }
}

#[server(ForceLogin, "/api")]
pub async fn force_login(cx: Scope) -> Result<(), ServerFnError> {
    force_create_session(cx);
    Ok(())
}
