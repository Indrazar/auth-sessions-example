use crate::pages::components::csrf::{CSRFField, CSRFFieldProps};
use crate::pages::components::logheader::{LogHeader, LogHeaderProps};
use crate::pages::components::redirect::{LoggedInRedirect, LoggedInRedirectProps};
use leptos::*;
use leptos_router::*;

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
                //{match retrieve_token.value() {
                //        Err(e) => {
                //            view! { cx, <pre class="error">"Server Error: " {e.to_string()}</pre>}.into_any()
                //        }
                //        Ok(token) => {
                //            view! {cx, <input type="hidden" name="_token" value={token}/>}
                //        }
                //    };
                //}
                <CSRFField/>
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

#[server(SignUp, "/api")]
pub async fn sign_up(cx: Scope) -> Result<(), ServerFnError> {
    Ok(())
}
