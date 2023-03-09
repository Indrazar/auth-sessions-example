#[cfg(feature = "ssr")]
use crate::database::pool;
use crate::pages::components::{
    csrf::{CSRFField, CSRFFieldProps},
    logheader::{LogHeader, LogHeaderProps},
    redirect::{LoggedInRedirect, LoggedInRedirectProps},
};
#[cfg(feature = "ssr")]
use crate::security::validate_registration;
use leptos::*;
#[cfg(feature = "ssr")]
use leptos_axum::redirect;
use leptos_router::*;
#[cfg(feature = "ssr")]
use secrecy::SecretString;

#[cfg(feature = "ssr")]
pub fn register_server_functions() -> Result<(), ServerFnError> {
    SignUp::register()?;
    Ok(())
}

/// Renders the non-logged in signup page
/// uses Double Submit Cookie method to prevent CSRF
/// [https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#double-submit-cookie]
#[component]
pub fn SignupPage(cx: Scope) -> impl IntoView {
    let sign_up = create_server_action::<SignUp>(cx);
    let submit_disabled = false;
    //TODO create field validation on WASM side

    view! { cx,
        <LoggedInRedirect
            success_route=Some("/home".to_string())
            fail_route=None
        />
        <h1>"Auth-Sessions-Example"</h1>
        <LogHeader/>
        <h2>"Sign Up"</h2>
        <p>
            <ActionForm action=sign_up>
                <CSRFField/>
                <p>
                    <label for="username">"Username:"</label>
                    <input type="text" name="username" required value/>
                </p>
                <p>
                    <label for="display">"Display Name:"</label>
                    <input type="text" name="display" required value/>
                </p>
                <p>
                    <label for="email">"E-Mail Address:"</label>
                    <input type="text" name="email" required value/>
                </p>
                <p>
                    <label for="email_confirmation">"E-Mail Address (Confirmation):"</label>
                    <input type="text" name="email_confirmation" required value/>
                </p>
                <p>
                    <label for="password">"Password:"</label>
                    <input type="password" name="password" required value/>
                </p>
                <p>
                    <label for="password_confirmation">"Password (Confirmation):"</label>
                    <input type="password" name="password_confirmation" required value/>
                </p>
                    <input type="submit" disabled=submit_disabled value="Sign Up"/>
            </ActionForm>
        </p>
        <a href="/">"Go Back"</a>
    }
}

#[server(SignUp, "/api")]
pub async fn sign_up(
    cx: Scope,
    csrf: String,
    username: String,
    display: String,
    email: String,
    email_confirmation: String,
    password: String,
    password_confirmation: String,
) -> Result<(), ServerFnError> {
    let pool = pool(cx)?;
    validate_registration(
        cx,
        csrf,
        username,
        display,
        email,
        email_confirmation,
        SecretString::from(password),
        SecretString::from(password_confirmation),
        &pool,
    )
    .await?;
    redirect(cx, "/login");
    Ok(())
}
