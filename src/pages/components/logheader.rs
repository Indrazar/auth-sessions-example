use leptos::*;
#[cfg(debug_assertions)]
use leptos_router::ActionForm;

/// Renders a button that sends a post request to /api
/// On the server side this will print out all the headers provided by the client
#[component]
pub fn LogHeader(cx: Scope) -> impl IntoView {
    #[cfg(debug_assertions)]
    let log_header = create_server_action::<LogClientHeader>(cx);

    #[cfg(debug_assertions)]
    view! {
        cx,
        <p>
            <ActionForm action=log_header>
                <input class="log_header" type="submit" value="Log Current Headers"/>
            </ActionForm>
        </p>
    }
}

//debugging tool
#[server(LogClientHeader, "/api")]
async fn log_client_headers(cx: Scope) -> Result<String, ServerFnError> {
    // this is just an example of how to access server context injected in the handlers
    let http_req = use_context::<leptos_axum::RequestParts>(cx);
    if let Some(http_req) = http_req {
        log::debug!(
            "Client pressed LogHeader, printing all data from client:\nhttp_req.version: \
             {:#?}\nhttp_req.method: {:#?}\nhttp_req.uri.path(): {:#?}\nhttp_req.headers: \
             {:#?}\nhttp_req.body: {:#?}",
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
    }

    Ok("It worked".to_string())
}
