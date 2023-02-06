use leptos::*;
//use leptos_meta::*;
use leptos_router::*;

#[cfg(feature = "ssr")]
pub fn register_server_functions() -> Result<(), ServerFnError> {
    APICheck::register()?;
    //AddTodo::register();
    //DeleteTodo::register();
    Ok(())
}

/// Renders the non-logged in landing page.
#[component]
pub fn LandingPage(cx: Scope) -> impl IntoView {
    // Creates a reactive value to update the button
    //let (count, set_count) = create_signal(cx, 0);
    //let on_click = move |_| set_count.update(|count| *count += 1);
    //log::debug!("cx_rc: {:#?}", use_context::<RouteContext>(cx));
    //let http_req = use_context::<leptos_axum::RequestParts>(cx);
    //let router_ctx = use_context::<leptos_router::RouterContext>(cx).unwrap();
    //log::debug!("http_req: {:#?}", http_req);
    //log::debug!("router_ctx: {:#?}", router_ctx);

    view! { cx,
        <h1>"Auth-Example"</h1>
        <h2>"A Letpos HTTPS Auth Example"</h2>
        //<button on:click=on_click>"Click Me: " {count}</button>
        <p><BackendCheck/></p>
        <p><Signup/></p>
        <p><Login/></p>
    }
}

/// Renders an animated Sign Up button
#[component]
fn Signup(cx: Scope) -> impl IntoView {
    view! { cx,
        <a href="/register" class="button-white">
            "Sign Up"
        </a>
    }
}

/// Renders an animated Login button
#[component]
fn Login(cx: Scope) -> impl IntoView {
    view! { cx,
        <a href="/login" class="button-blue">
            "Login"
        </a>
    }
}

//debugging tools

#[server(APICheck, "/api")]
pub async fn api_check(cx: Scope) -> Result<String, ServerFnError> {
    // this is just an example of how to access server context injected in the handlers
    let http_req = use_context::<leptos_axum::RequestParts>(cx);
    if let Some(http_req) = http_req {
        //log::debug!("http_req.path: {:#?}", &http_req.path());
        log::debug!(
            "APICheck from client, printing all data from client:\n\
            http_req.version: {:#?}\nhttp_req.method: {:#?}\nhttp_req.uri.path(): {:#?}\nhttp_req.headers: {:#?}\nhttp_req.body: {:#?}",
            &http_req.version,
            &http_req.body,
            &http_req.uri.path(),
            &http_req.headers,
            &http_req.body
        );
        // ResponseOptions are more of an outbox than incoming data
        //log::debug!("resp_opt: {:#?}", use_context::<leptos_actix::ResponseOptions>(cx));
        log::debug!(
            "route_int_ctx: {:#?}",
            use_context::<leptos_router::RouterIntegrationContext>(cx)
        );
        log::debug!(
            "meta_ctx: {:#?}",
            use_context::<leptos_meta::MetaContext>(cx)
        );
        //log::debug!("")
    }

    Ok("It worked".to_string())
}

/// Renders a button that sends a post request to /api
/// On the server side this will print out all the headers provided by the client
#[component]
pub fn BackendCheck(cx: Scope) -> impl IntoView {
    let api_check = create_server_action::<APICheck>(cx);

    view! {
        cx,
        <div>
            <ActionForm action=api_check>
                <input type="submit" value="Check the API"/>
            </ActionForm>
        </div>
    }
}
