use cfg_if::cfg_if;
use leptos::*;
use leptos_meta::*;
use leptos_router::*;

mod components;
use components::{csrf::CSRFField, logheader::LogHeader};
mod homepage;
use crate::database::UserData;
use homepage::HomePage;

cfg_if! { if #[cfg(feature = "ssr")] {
    use crate::cookies::{validate_session, issue_session_cookie, destroy_session};
    use crate::security::{validate_login, gen_128bit_base64, validate_registration};
    use axum::{
        //body::{boxed, Body, BoxBody},
        //extract::Extension,
        //response::IntoResponse,
        //http::{Request, Response, HeaderMap, header::ACCEPT_ENCODING, HeaderValue, header::CONTENT_TYPE, StatusCode, Uri},
        http::{HeaderValue, header::CONTENT_TYPE}
    };
    //use axum::response::Response as AxumResponse;
    //use futures::StreamExt;
    use leptos_axum::redirect;
    use secrecy::SecretString;
}}

pub mod error_template;

#[cfg(feature = "ssr")]
fn set_headers() {
    let response = match use_context::<leptos_axum::ResponseOptions>() {
        Some(ro) => ro,
        None => return,
    };
    //TODO remove after leptos sets this by default
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
        HeaderValue::from_static(
            // loading WASM requires 'unsafe-inline' 'unsafe-eval'
            "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval' 'self'; connect-src 'self' ws://127.0.0.1:3001/ ws://127.0.0.1:3000/",
        ), // media-src example.org example.net; script-src userscripts.example.com; img-src *;
    );
    #[cfg(not(debug_assertions))]
    response.insert_header(
        axum::http::header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            // loading WASM requires 'unsafe-inline' 'unsafe-eval'
            "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval' 'self'; connect-src 'self' ws://127.0.0.1:3000/",
        ), // media-src example.org example.net; script-src userscripts.example.com; img-src *;
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
    //let (is_routing, set_is_routing) = create_signal(false);
    let userdata = create_resource(
        move || {
            (
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
        //<Script nonce={nonce}/>

        // sets the document title
        <Title text="Auth-Sessions-Example: A Letpos HTTPS Auth Example"/>

        // content for this app
        <Router> //set_is_routing>
            <header>
                <A href="/"><h1>"Auth-Sessions-Example"</h1></A>
                <h2>"A Letpos HTTPS Auth Example"</h2>
                <LogHeader/>
                <Transition
                    fallback=move || view! { <span>"Loading..."</span> }
                >
                {move || {
                    userdata.read().map(|user| match user {
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
                <Route path="" view=move || view! {<HomePage /> }/> //Route
                <Route path="signup" ssr=SsrMode::Async view=move || view! {
                    <Signup action=signup />
                }/>
                <Route path="login" ssr=SsrMode::Async view=move || view! {
                    <Login action=login />
                }/>
                <Route path="settings" view=move || view! {
                    <h1>"Settings"</h1>
                    <Logout action=logout />
                }/>
            </Routes>
            </main>
        </Router>
    }
}

#[server(GetUserData, "/api")]
pub async fn get_user_data() -> Result<Option<UserData>, ServerFnError> {
    match validate_session().await {
        Some(id) => Ok(crate::database::user_data(id).await),
        None => Ok(None),
    }
}

/// Renders the non-logged in landing page.
#[component]
pub fn Login(action: Action<Login, Result<(), ServerFnError>>) -> impl IntoView {
    let submit_disabled = false;
    //TODO create field validation on WASM side

    let (login_result, set_login_result) = create_signal(" ".to_string());

    create_effect(move |_| {
        action.version().get();
        match action.value().get() {
            Some(Err(ServerFnError::ServerError(e))) => set_login_result.set(e.to_string()),
            _ => return,
        };
    });

    view! {
        <ActionForm action=action>
                <CSRFField/>
                <p>
                    <label for="username">"Username:"</label>
                    <input type="text" maxlength="32" name="username" required value/>
                </p>
                <p>
                    <label for="password">"Password:"</label>
                    <input type="password" name="password" required value/>
                </p>
                    <input type="submit" disabled=submit_disabled value="Login"/>
                <p>
                    {login_result}
                </p>
            </ActionForm>
        <p><a href="/">"Return to landing page"</a></p>
    }
}

#[server(Login, "/api")]
pub async fn login(
    csrf: String,
    username: String,
    password: String,
) -> Result<(), ServerFnError> {
    let user_id = validate_login(csrf, username, SecretString::from(password)).await?;
    let session_id = gen_128bit_base64();
    issue_session_cookie(user_id, session_id).await?;
    redirect("/");
    Ok(())
}

/// Renders the non-logged in signup page
/// uses Double Submit Cookie method to prevent CSRF
/// [https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#double-submit-cookie]
#[component]
pub fn Signup(action: Action<Signup, Result<String, ServerFnError>>) -> impl IntoView {
    let submit_disabled = false;
    //TODO create field validation on WASM side

    view! {
        <h2>"Sign Up"</h2>
        <p>
            <ActionForm action=action>
                <p>
                    <CSRFField/>
                </p>
                <p>
                    <label for="username">"Username:"</label>
                    <input type="text" maxlength="32" name="username" required class="auth-input"/>
                </p>
                <p>
                    <label for="display">"Display Name:"</label>
                    <input type="text" maxlength="16" name="display" required/>
                </p>
                <p>
                    <label for="email">"E-Mail Address:"</label>
                    <input type="text" name="email" required/>
                </p>
                <p>
                    <label for="email_confirmation">"E-Mail Address (Confirmation):"</label>
                    <input type="text" name="email_confirmation" required/>
                </p>
                <p>
                    <label for="password">"Password:"</label>
                    <input type="password" name="password" required class="auth-input"/>
                </p>
                <p>
                    <label for="password_confirmation">"Password (Confirmation):"</label>
                    <input type="password" name="password_confirmation" required/>
                </p>
                    <input type="submit" disabled=submit_disabled value="Sign Up"/>
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
