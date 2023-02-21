use crate::pages::components::{
    csrf::{CSRFField, CSRFFieldProps},
    logheader::{LogHeader, LogHeaderProps},
    redirect::{LoggedInRedirect, LoggedInRedirectProps},
};
use cfg_if::cfg_if;
use leptos::*;
use leptos_router::*;

cfg_if! { if #[cfg(feature = "ssr")] {
    use crate::cookies::{force_create_session, issue_session_cookie};
    use crate::security::{validate_login, gen_csprng_session};
    use secrecy::SecretString;
    use leptos_axum::redirect;

    pub fn register_server_functions() -> Result<(), ServerFnError> {
        ForceLogin::register()?;
        Login::register()?;
        Ok(())
    }
}}

/// Renders the non-logged in landing page.
#[component]
pub fn LoginPage(cx: Scope) -> impl IntoView {
    let mut ssr_state: bool = false;
    let login = create_server_action::<Login>(cx);
    let submit_disabled = false;
    //TODO create mutli action after login server action completes
    //TODO create field validation on WASM side

    view! { cx,
        <LoggedInRedirect
            success_route=Some("/home".to_string())
            fail_route=None
            ssr_state=&mut ssr_state
        />
        <h1>"Auth-Sessions-Example"</h1>
        <h2>"Login Page"</h2>
        <LogHeader/>
        <GenerateSession/>
        <ActionForm action=login>
                <CSRFField/>
                <p>
                    <label for="username">"Username:"</label>
                    <input type="text" name="username" required value/>
                </p>
                <p>
                    <label for="password">"Password:"</label>
                    <input type="password" name="password" required value/>
                </p>
                    <input type="submit" disabled=submit_disabled value="Login"/>
            </ActionForm>
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

#[server(Login, "/api")]
pub async fn login(
    cx: Scope,
    csrf: String,
    username: String,
    password: String,
) -> Result<(), ServerFnError> {
    let user_id = validate_login(cx, csrf, username, SecretString::from(password)).await?;
    let session_id = gen_csprng_session();
    issue_session_cookie(cx, user_id, session_id).await?;
    redirect(cx, "/home");
    Ok(())
}
