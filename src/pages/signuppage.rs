use crate::pages::components::csrf::{CSRFField, CSRFFieldProps};
use crate::pages::components::logheader::{LogHeader, LogHeaderProps};
use crate::pages::components::redirect::{LoggedInRedirect, LoggedInRedirectProps};
use leptos::*;
use leptos_router::*;

#[cfg(feature = "ssr")]
use crate::cookies::validate_csrf;

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
    let mut ssr_state: bool = false;

    //let session = generate_or_use_token(cx);

    //retrieve_token

    view! { cx,
        <LoggedInRedirect
            success_route=Some("/home".to_string())
            fail_route=None
            ssr_state=&mut ssr_state
        />
        <h1>"Auth-Example"</h1>
        <LogHeader/>
        <h2>"Sign Up"</h2>
        <h3>"Not Implemented Yet"</h3>
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
                    <input type="submit" value="Sign Up"/>
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
    let http_req = match use_context::<leptos_axum::RequestParts>(cx) {
        Some(rp) => rp, // actual user request
        None => {
            return Err(ServerFnError::ServerError(String::from(
                "Signup Request was invalid.",
            )))
        } // no request, building routes in main.rs
    };
    validate_csrf(http_req, csrf)?;
    //parse_session_cookie(http_req);
    //validate_token(unverified_session_id.as_str())
    Ok(())
}
