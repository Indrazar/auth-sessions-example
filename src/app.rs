use cfg_if::cfg_if;
use leptos::{either::Either, prelude::*};
use leptos_router::{
    components::{Redirect, Route, Router, Routes, A},
    SsrMode, StaticSegment,
};
mod components;
use components::{csrf::CSRFField, logheader::LogHeader};
mod homepage;
use crate::database::APIUserData;
use crate::defs::*;
use leptos_meta::{provide_meta_context, Meta, MetaTags};

use homepage::HomePage;

use leptos_meta::{Link, Stylesheet, Title};

cfg_if! { if #[cfg(feature = "ssr")] {
    use crate::cookies::{destroy_session, issue_session_cookie, validate_session};
    use crate::security::{gen_128bit_base64, validate_login, validate_registration};
    //use leptos_meta::{Meta, MetaTags};
    use axum::http::{header::CONTENT_TYPE, HeaderValue};
    use leptos_axum::redirect as axum_redirect;
    use secrecy::SecretString;
    use leptos::nonce::use_nonce;
}}

pub mod error_template;

pub fn shell(options: LeptosOptions) -> impl IntoView {
    #[cfg(feature = "ssr")]
    set_headers();

    view! {
            <!DOCTYPE html>
            <html lang="en">
                <head>
    /*                 <Meta
                    http_equiv="Content-Security-Policy"
                    content=move || {
                        // this will insert the CSP with nonce on the server, be empty on client
                        use_nonce()
                            .map(|nonce| {
                                format!(
                                    "default-src 'self';\
                                    script-src 'unsafe-eval' 'strict-dynamic' 'nonce-{nonce}' 'self';\
                                    style-src 'nonce-{nonce}' 'self';\
                                    connect-src 'self' ws://localhost:3001/ ws://127.0.0.1:3001/ {WEBSOCKET_DIRECTIVE_URL};"
                                )
                            })
                            .unwrap_or_default()
                    }
                    /> */
                    <meta charset="utf-8"/>
                    <meta name="viewport" content="width=device-width, initial-scale=1"/>
                    <AutoReload options=options.clone() />
                    <HydrationScripts options/>
                    <Link rel="shortcut icon" type_="image/ico" href="/favicon.ico"/>
                    // injects a stylesheet into the document <head>
                    // id=leptos means cargo-leptos will hot-reload this stylesheet
                    <Stylesheet id="leptos" href="/pkg/auth_sessions_example.css"/>
                    // sets the document title
                    <Title text="Auth-Sessions-Example: A Letpos HTTPS Auth Example"/>
                    <MetaTags/>
                </head>
                <body>
                    <App/>
                </body>
            </html>
        }
}

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
            // bad? version
            format!(
                "script-src 'unsafe-inline' 'unsafe-eval' 'self';\
                connect-src 'self' ws://localhost:3001/ ws://127.0.0.1:3001/ {WEBSOCKET_DIRECTIVE_URL};",
            )
            ////good version
            //format!(
            //    "default-src 'self';\
            //    script-src 'unsafe-eval' 'strict-dynamic' 'nonce-{nonce}' 'self';\
            //    style-src 'nonce-{nonce}' 'self';\
            //    connect-src 'self' ws://localhost:3001/ ws://127.0.0.1:3001/ {WEBSOCKET_DIRECTIVE_URL};",
            //)
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
            // bad? version
            format!(
                "script-src 'unsafe-inline' 'unsafe-eval' 'self';\
                connect-src 'self' {WEBSOCKET_DIRECTIVE_URL};",
            )
            ////good version
            //format!(
            //    "default-src 'self';\
            //    script-src 'unsafe-eval' 'strict-dynamic' 'nonce-{nonce}';\
            //    style-src 'nonce-{nonce}' 'self';\
            //    connect-src 'self' {WEBSOCKET_DIRECTIVE_URL};",
            //)
            .as_str(),
        )
        .expect("valid header"), // media-src example.org example.net; script-src userscripts.example.com; img-src *;
    );
    response.insert_header(
        axum::http::header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000"),
    )
}

// returns false if still waiting for resolution
fn is_logged_in(user_data: Option<Result<Option<APIUserData>, ServerFnError>>) -> bool {
    match user_data {
        None => false,
        Some(Err(_)) => false,
        Some(Ok(None)) => false,
        Some(Ok(Some(_))) => true,
    }
}

//returns false if still waiting for resolution
fn is_not_logged_in(user_data: Option<Result<Option<APIUserData>, ServerFnError>>) -> bool {
    match user_data {
        None => false,
        Some(Err(_)) => false,
        Some(Ok(None)) => true,
        Some(Ok(Some(_))) => false,
    }
}

#[component]
pub fn App() -> impl IntoView {
    // Provides context that manages stylesheets, titles, meta tags, etc.
    provide_meta_context();

    let login = ServerAction::<Login>::new();
    let logout = ServerAction::<Logout>::new();
    let signup = ServerAction::<Signup>::new();
    let (is_routing, set_is_routing) = signal(false);
    let user_data = Resource::new(
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

    //cfg_if::cfg_if! { if #[cfg(feature = "ssr")] {
    //    // Set correct header for `Content-Type: text/html; charset=UTF-8`, etc.
    //    set_headers();
    //}}

    view! {
        <Router set_is_routing>
            <nav>
                <A href="/"><h1>"Auth-Sessions-Example"</h1></A>
                <h2>"A Letpos HTTPS Auth Example"</h2>
                <LogHeader/>
                <Suspense
                    fallback=move || view! { <span>"Loading..."</span> }
                >
                { move || {
                    user_data.get().map(|user| match user {
                        Err(e) => Either::Left(view! {
                            <A href="/signup">"Signup"</A>", "
                            <A href="/login">"Login"</A>
                            <br />
                            <span>{format!("Login error: {}", e)}</span>
                        }),
                        Ok(inner) => Either::Right(
                            match inner {
                                None => Either::Left(view! {
                                    <A href="/signup">"Signup"</A>", "
                                    <A href="/login">"Login"</A>
                                    <br />
                                    <span>"Logged out"</span>
                                }),
                                Some(user) => Either::Right(view! {
                                    <A href="/">"Home"</A>", "
                                    <A href="/settings">"Settings"</A>
                                    <br />
                                    <span>{format!("Logged in as: {}", user.display_name)}</span>
                                }),
                            }
                        )
                    })
                }}
                </Suspense>
            </nav>
            <div/>
            <main>
            <Routes fallback=|| "Not Found.">
                <Route path=StaticSegment("/") view=move || view! {
                    <HomePage user_data/> // user_data
                }/>
                <Route path=StaticSegment("/signup") ssr=SsrMode::Async view=move || view! {
                    <Signup action=signup is_routing />
                }/>
                <Route path=StaticSegment("/login") ssr=SsrMode::Async view=move || view! {
                    <Login action=login is_routing />
                }/>
                <Route path=StaticSegment("/settings") ssr=SsrMode::Async view=move || view! {
                    <Suspense>
                        <Show when=move || is_not_logged_in(user_data.get())>
                            <Redirect path="/" />
                        </Show>
                    </Suspense>
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
pub fn Login(action: ServerAction<Login>, is_routing: ReadSignal<bool>) -> impl IntoView {
    let submit_disabled = false;
    //TODO create field validation on WASM side

    let (login_result, set_login_result) = signal(" ".to_string());

    Effect::new(move |_| {
        action.version().get();
        match action.value().get() {
            Some(Ok(val)) => set_login_result.set(val),
            Some(Err(ServerFnError::ServerError(e))) => set_login_result.set(e.to_string()),
            _ => return,
        };
    });

    Effect::new(move |_| {
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

#[server]
pub async fn login(
    csrf: String,
    username: String,
    password: String,
) -> Result<String, ServerFnError> {
    let user_id = match validate_login(csrf, username, SecretString::from(password)).await {
        Ok(id) => id,
        Err(e) => return Ok(format!("{:?}", e)),
    };
    let session_id = gen_128bit_base64();
    issue_session_cookie(user_id, session_id).await?;
    axum_redirect("/");
    Ok(String::from("Login Successful"))
}

/// Renders the non-logged in signup page
/// uses Double Submit Cookie method to prevent CSRF
/// [https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#double-submit-cookie]
#[component]
pub fn Signup(action: ServerAction<Signup>, is_routing: ReadSignal<bool>) -> impl IntoView {
    let submit_disabled = false;
    //TODO create field validation on WASM side

    let (signup_result, set_signup_result) = signal(String::default());

    Effect::new(move |_| match action.value().get() {
        Some(Ok(res)) => set_signup_result.set(res),
        Some(Err(e)) => set_signup_result.set(format!("Error processing request: {e}")),
        None => {}
    });

    Effect::new(move |_| {
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
            return Ok(format!("{:?}", e));
        }
    };
    let session_id = gen_128bit_base64();
    issue_session_cookie(user_id, session_id).await?;
    axum_redirect("/");
    Ok(String::from("Registration Successful"))
}

#[component]
pub fn Logout(action: ServerAction<Logout>) -> impl IntoView {
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
    axum_redirect("/");
    Ok(())
}
