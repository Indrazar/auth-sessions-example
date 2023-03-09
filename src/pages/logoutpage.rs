use crate::pages::components::logheader::{LogHeader, LogHeaderProps};
use cfg_if::cfg_if;
use leptos::*;

cfg_if! { if #[cfg(feature = "ssr")] {
    use crate::cookies::destroy_session;
    pub fn register_server_functions() -> Result<(), ServerFnError> {
        DestroySession::register()?;
        Ok(())
    }
}}

#[component]
pub fn LogoutPage(cx: Scope) -> impl IntoView {
    let destroy_action = create_server_action::<DestroySession>(cx);
    let destroy_resource = create_resource(
        cx,
        move || (destroy_action.version().get()),
        move |_| {
            log::trace!("session destroy running fetcher");
            server_destroy_session(cx)
        },
    );
    let destroy_result = move || {
        destroy_resource.read(cx).map(|n| match n {
            Ok(()) => {}
            Err(e) => log::error!("{:#?}", e),
        })
    };
    view! {cx,
        <h1>"Auth-Sessions-Example"</h1>
        <h2>"Logout Page"</h2>
        <LogHeader/>
        <p><a href="/">"Return to Landing Page"</a></p>
        <p><a href="/login">"Login Again"</a></p>
        <Suspense fallback={|| view!{cx, <></>}}>
        <>{destroy_result()}</>
        </Suspense>
    }
}

#[server(DestroySession, "/api")]
async fn server_destroy_session(cx: Scope) -> Result<(), ServerFnError> {
    destroy_session(cx).await;
    Ok(())
}
