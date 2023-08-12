use cfg_if::cfg_if;
use leptos::*;
use leptos_meta::*;
use leptos_router::*;

mod components;
use components::{csrf::CSRFField, logheader::LogHeader};
mod homepage;
use crate::database::APIUserData;
use crate::defs::*;
use homepage::HomePage;

cfg_if! { if #[cfg(feature = "ssr")] {
    use crate::cookies::{validate_session, issue_session_cookie, destroy_session};
    use crate::security::{validate_login, gen_128bit_base64, validate_registration};
    use crate::defs::WEBSOCKET_DIRECTIVE_URL;
    use axum::{
        http::{HeaderValue, header::CONTENT_TYPE}
    };
    use leptos::nonce::use_nonce;
    use leptos_axum::redirect;
    use secrecy::SecretString;
}}

pub mod error_template;

#[cfg(feature = "ssr")]
fn set_headers() {
    let response = match use_context::<leptos_axum::ResponseOptions>() {
        Some(ro) => ro,
        None => return, // building routes in main.rs
    };
    let nonce = use_nonce().expect("a nonce to be made");
    //TODO remove after leptos sets any of these by default
    response.insert_header(
        CONTENT_TYPE,
        HeaderValue::from_static(mime::TEXT_HTML_UTF_8.as_ref()),
    );
    response.insert_header(
        axum::http::header::X_XSS_PROTECTION,
        HeaderValue::from_static("1; mode=block"),
    );
    response.insert_header(
        axum::http::header::X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY"),
    );
    response.insert_header(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, private"),
    );
    #[cfg(debug_assertions)]
    response.insert_header(
        axum::http::header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(
            // loading WASM requires 'unsafe-inline' 'unsafe-eval'
            // or
            // script-src 'strict-dynamic' 'nonce-{nonce}'
            // for debug we add the cargo leptos websocket:
            //     connect-src ws://127.0.0.1:3001/
            format!(
                "default-src 'self';\
                script-src 'unsafe-eval' 'strict-dynamic' 'nonce-{nonce}';\
                style-src 'nonce-{nonce}' 'self';\
                connect-src 'self' ws://127.0.0.1:3001/ {WEBSOCKET_DIRECTIVE_URL}",
            )
            .as_str(),
        )
        .expect("valid header"), // media-src example.org example.net; script-src userscripts.example.com; img-src *;
    );
    #[cfg(not(debug_assertions))]
    response.insert_header(
        axum::http::header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(
            // loading WASM requires 'unsafe-inline' 'unsafe-eval'
            // or
            // script-src 'strict-dynamic' 'nonce-{nonce}'
            // for debug we remove the cargo leptos websocket:
            //     connect-src ws://127.0.0.1:3001/
            format!(
                "default-src 'self';\
                script-src 'unsafe-eval' 'strict-dynamic' 'nonce-{nonce}';\
                style-src 'nonce-{nonce}' 'self';\
                connect-src 'self' {WEBSOCKET_DIRECTIVE_URL}",
            )
            .as_str(),
        )
        .expect("valid header"), // media-src example.org example.net; script-src userscripts.example.com; img-src *;
    );
    response.insert_header(
        axum::http::header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000"),
    )
}

#[component]
pub fn App() -> impl IntoView {
    let login = create_server_action::<Login>();
    let logout = create_server_action::<Logout>();
    let signup = create_server_action::<Signup>();
    let (is_routing, set_is_routing) = create_signal(false);
    let user_data = create_resource(
        move || {
            (
                // changing these conditions may reduce "get_user_data" server calls
                login.version().get(),
                signup.version().get(),
                logout.version().get(),
            )
        },
        move |_| get_user_data(),
    );

    // Provides context that manages stylesheets, titles, meta tags, etc.
    provide_meta_context();
    //let nonce = "";

    cfg_if::cfg_if! { if #[cfg(feature = "ssr")] {
        // Set correct header for `Content-Type: text/html; charset=UTF-8`, etc.
        set_headers();
    }}

    view! {
        <Link rel="shortcut icon" type_="image/ico" href="/favicon.ico"/>
        // injects a stylesheet into the document <head>
        // id=leptos means cargo-leptos will hot-reload this stylesheet
        <Stylesheet id="leptos" href="/pkg/auth_sessions_example.css"/>
        //<script nonce=use_nonce />

        // sets the document title
        <Title text="Auth-Sessions-Example: A Letpos HTTPS Auth Example"/>

        <Router set_is_routing>
            <header>
                <A href="/"><h1>"Auth-Sessions-Example"</h1></A>
                <h2>"A Letpos HTTPS Auth Example"</h2>
                <LogHeader/>
                <Transition
                    fallback=move || view! { <span>"Loading..."</span> }
                >
                {move || {
                    user_data.get().map(|user| match user {
                        Err(e) => view! {
                            <A href="/signup">"Signup"</A>", "
                            <A href="/login">"Login"</A>
                            <br />
                            <span>{format!("Login error: {}", e)}</span>
                        }.into_view(),
                        Ok(None) => view! {
                            <A href="/signup">"Signup"</A>", "
                            <A href="/login">"Login"</A>
                            <br />
                            <span>"Logged out"</span>
                        }.into_view(),
                        Ok(Some(user)) => view! {
                            <A href="/">"Home"</A>", "
                            <A href="/settings">"Settings"</A>
                            <br />
                            <span>{format!("Logged in as: {}", user.display_name)}</span>
                        }.into_view()
                    })
                }}
                </Transition>
            </header>
            <div/>
            <main>
            <Routes>
                <Route path="" view=move || view! {
                    <HomePage user_data />
                }/>
                <Route path="signup" ssr=SsrMode::Async view=move || view! {
                    <Signup action=signup is_routing />
                }/>
                <Route path="login" ssr=SsrMode::Async view=move || view! {
                    <Login action=login is_routing />
                }/>
                <ProtectedRoute
                    path="settings"
                    redirect_path="/"
                    condition=move || {
                        match user_data.get() {
                            None => false,
                            Some(Err(_)) => false,
                            Some(Ok(None)) => false,
                            Some(Ok(Some(_))) => true,
                        }
                    }
                    view=move || view! {
                        <h1>"Settings"</h1>
                        <Logout action=logout />
                }/>
            </Routes>
            </main>
        </Router>
    }
}

#[server(GetUserData, "/api")]
pub async fn get_user_data() -> Result<Option<APIUserData>, ServerFnError> {
    match validate_session().await? {
        Some(id) => Ok(Some(crate::database::user_data(id).await?)),
        None => Ok(None),
    }
}

/// Renders the non-logged in landing page.
#[component]
pub fn Login(
    action: Action<Login, Result<String, ServerFnError>>,
    is_routing: ReadSignal<bool>,
) -> impl IntoView {
    let submit_disabled = false;
    //TODO create field validation on WASM side

    let (login_result, set_login_result) = create_signal(" ".to_string());

    create_effect(move |_| {
        action.version().get();
        match action.value().get() {
            Some(Ok(val)) => set_login_result.set(val),
            Some(Err(ServerFnError::ServerError(e))) => set_login_result.set(e.to_string()),
            _ => return,
        };
    });

    create_effect(move |_| {
        is_routing.get();
        set_login_result.set(String::default());
    });

    view! {
        <ActionForm action=action>
                <CSRFField/>
                <div>
                    <label>"Username: "
                        <input type="text" maxlength=USERNAME_MAX_LEN_STR minlength=USERNAME_MIN_LEN_STR name="username" required value/>
                    </label>
                </div>
                <div>
                    <label>"Password: "
                        <input type="password" maxlength=PASSWORD_MAX_LEN_STR minlength=PASSWORD_MIN_LEN_STR name="password" required value/>
                    </label>
                </div>
                    <button type="submit" disabled=submit_disabled value="Login">"Login"</button>
                <div>
                    {login_result}
                </div>
            </ActionForm>
        <p><a href="/">"Return to landing page"</a></p>
    }
}

#[server(Login, "/api")]
pub async fn login(
    csrf: String,
    username: String,
    password: String,
) -> Result<String, ServerFnError> {
    let user_id = match validate_login(csrf, username, SecretString::from(password)).await {
        Ok(id) => id,
        Err(e) => return Ok(format!("{}", e)),
    };
    let session_id = gen_128bit_base64();
    issue_session_cookie(user_id, session_id).await?;
    redirect("/");
    Ok(String::from("Login Successful"))
}

/// Renders the non-logged in signup page
/// uses Double Submit Cookie method to prevent CSRF
/// [https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#double-submit-cookie]
#[component]
pub fn Signup(
    action: Action<Signup, Result<String, ServerFnError>>,
    is_routing: ReadSignal<bool>,
) -> impl IntoView {
    let submit_disabled = false;
    //TODO create field validation on WASM side

    let (signup_result, set_signup_result) = create_signal(String::default());

    create_effect(move |_| match action.value().get() {
        Some(Ok(res)) => set_signup_result.set(res),
        Some(Err(e)) => set_signup_result.set(format!("Error processing request: {e}")),
        None => {}
    });

    create_effect(move |_| {
        is_routing.get();
        set_signup_result.set(String::default());
    });

    view! {
        <h2>"Sign Up"</h2>
        <p>
            <ActionForm action=action>
                    <CSRFField/>
                <div>
                    <label>"Username: "
                        <input type="text" maxlength=USERNAME_MAX_LEN_STR minlength=USERNAME_MIN_LEN_STR name="username" required class="auth-input"/>
                    </label>
                </div>
                <div>
                    <label>"Display Name: "
                        <input type="text" maxlength=DISPLAY_NAME_MAX_LEN minlength=DISPLAY_NAME_MIN_LEN name="display" required/>
                    </label>
                </div>
                <div>
                    <label>"E-Mail Address: "
                        <input type="email" name="email" required/>
                    </label>
                </div>
                <div>
                    <label>"E-Mail Address (Confirmation): "
                        <input type="email" name="email_confirmation" required/>
                    </label>
                </div>
                <div>
                    <label>"Password: "
                        <input type="password" maxlength=PASSWORD_MAX_LEN_STR minlength=PASSWORD_MIN_LEN_STR name="password" required class="auth-input"/>
                    </label>
                </div>
                <div>
                    <label>"Password (Confirmation): "
                        <input type="password" maxlength=PASSWORD_MAX_LEN_STR minlength=PASSWORD_MIN_LEN_STR name="password_confirmation" required/>
                    </label>
                </div>
                    <button type="submit" disabled=submit_disabled>"Sign Up"</button>
                <div>
                    {signup_result}
                </div>
            </ActionForm>
        </p>
        <p>

        </p>
        <a href="/">"Go Back"</a>
    }
}

#[server(Signup, "/api")]
pub async fn signup(
    csrf: String,
    username: String,
    display: String,
    email: String,
    email_confirmation: String,
    password: String,
    password_confirmation: String,
) -> Result<String, ServerFnError> {
    let user_id = match validate_registration(
        csrf,
        username,
        display,
        email,
        email_confirmation,
        SecretString::from(password),
        SecretString::from(password_confirmation),
    )
    .await
    {
        Ok(id) => id,
        Err(e) => {
            return Ok(format!("{e}"));
        }
    };
    let session_id = gen_128bit_base64();
    issue_session_cookie(user_id, session_id).await?;
    redirect("/");
    Ok(String::from("Registration Successful"))
}

#[component]
pub fn Logout(action: Action<Logout, Result<(), ServerFnError>>) -> impl IntoView {
    view! {
        <div id="loginbox">
            <ActionForm action=action>
                <button type="submit" class="button">"Log Out"</button>
            </ActionForm>
        </div>
    }
}

#[server(Logout, "/api")]
async fn logout() -> Result<(), ServerFnError> {
    destroy_session().await;
    redirect("/");
    Ok(())
}
