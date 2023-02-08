use leptos::*;
//use leptos_meta::*;
use leptos_router::*;

use crate::pages::landingpage::*;

//#[cfg(feature = "ssr")]
//pub fn register_server_functions() -> Result<(), ServerFnError> {
//AddTodo::register();
//DeleteTodo::register();
//Ok(())
//}

/// Renders the non-logged in landing page.
#[component]
pub fn LoginPage(cx: Scope) -> impl IntoView {
    #[cfg(feature = "ssr")]
    resolve_session(cx);

    #[cfg(not(feature = "ssr"))]
    let this_session = create_server_action::<RetrieveSession>(cx);
    #[cfg(not(feature = "ssr"))]
    let session_resource = create_resource(
        cx,
        move || (this_session.version().get()),
        move |_| retrieve_session(cx),
    );

    view! { cx,
        <h1>"Auth-Example"</h1>
        <h2>"Login Page"</h2>
        //<button on:click=on_click>"Click Me: " {count}</button>
        <p><BackendCheck/></p>
        <p><GenerateSession/></p>
        <p><a href="/">"Return to landing page"</a></p>
    }
}

/// Renders a button that sends a post request to /api
/// On the server side this will print out all the headers provided by the client
#[component]
pub fn GenerateSession(cx: Scope) -> impl IntoView {
    let generate_valid_session = create_server_action::<RetrieveSession>(cx);

    view! {
        cx,
        <div>
            <ActionForm action=generate_valid_session>
                <input type="submit" value="Produce Valid Session Token"/>
            </ActionForm>
        </div>
    }
}
