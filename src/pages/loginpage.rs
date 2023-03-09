use crate::pages::components::{
    csrf::{CSRFField, CSRFFieldProps},
    logheader::{LogHeader, LogHeaderProps},
    redirect::{LoggedInRedirect, LoggedInRedirectProps},
};
use cfg_if::cfg_if;
use leptos::*;
use leptos_router::*;

cfg_if! { if #[cfg(feature = "ssr")] {
    use crate::cookies::issue_session_cookie;
    use crate::database::pool;
    use crate::security::{validate_login, gen_128bit_base64};
    use secrecy::SecretString;
    use leptos_axum::redirect;

    pub fn register_server_functions() -> Result<(), ServerFnError> {
        Login::register()?;
        Ok(())
    }
}}

/// Renders the non-logged in landing page.
#[component]
pub fn LoginPage(cx: Scope) -> impl IntoView {
    let login = create_server_action::<Login>(cx);
    let submit_disabled = false;
    //TODO create field validation on WASM side

    view! { cx,
        <LoggedInRedirect
            success_route=Some("/home".to_string())
            fail_route=None
        />
        <h1>"Auth-Sessions-Example"</h1>
        <h2>"Login Page"</h2>
        <LogHeader/>
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

#[server(Login, "/auth")]
pub async fn login(
    cx: Scope,
    csrf: String,
    username: String,
    password: String,
) -> Result<(), ServerFnError> {
    let pool = pool(cx)?;
    let user_id =
        validate_login(cx, csrf, username, SecretString::from(password), &pool).await?;
    let session_id = gen_128bit_base64();
    issue_session_cookie(cx, user_id, session_id, &pool).await?;
    redirect(cx, "/home");
    Ok(())
}
