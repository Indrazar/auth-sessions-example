use leptos::*;
use leptos_router::*;

use crate::pages::landingpage::{BackendCheck, BackendCheckProps};

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

    //let session = generate_or_use_token(cx);

    //retrieve_token

    view! { cx,
        <h1>"Auth-Example"</h1>
        <BackendCheck/>
        <h2>"Sign Up"</h2>
        <p>
            <ActionForm action=sign_up>
                //{match retrieve_token.value() {
                //        Err(e) => {
                //            view! { cx, <pre class="error">"Server Error: " {e.to_string()}</pre>}.into_any()
                //        }
                //        Ok(token) => {
                //            view! {cx, <input type="hidden" name="_token" value={token}/>}
                //        }
                //    };
                //}
                <div>
                    <label for="username"><br/>"Username:"</label>
                    <input type="text" name="username" required value/><br/>
                </div>
                <div>
                    <label for="display"><br/>"Display Name:"</label>
                    <input type="text" name="display" required value/>
                </div>
                <div>
                    <label for="email"><br/>"E-Mail Address:"</label>
                    <input type="text" name="email" required value/>
                </div>
                //<div>
                //</div>
            </ActionForm>
        </p>
    }
}

#[server(SignUp, "/register/submit")]
pub async fn sign_up(cx: Scope) -> Result<(), ServerFnError> {
    Ok(())
}
