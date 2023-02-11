#[cfg(feature = "ssr")]
use crate::cookies::validate_session;
use crate::pages::components::logheader::{LogHeader, LogHeaderProps};
use crate::pages::components::logoutbutton::{LogoutButton, LogoutButtonProps};
use crate::pages::components::redirect::{LoggedInRedirect, LoggedInRedirectProps};
use leptos::*;

#[cfg(feature = "ssr")]
pub fn register_server_functions() -> Result<(), ServerFnError> {
    GetHomePage::register()?;
    Ok(())
}

#[component]
pub fn HomePage(cx: Scope) -> impl IntoView {
    let page_data_action = create_server_action::<GetHomePage>(cx);
    let page_data_resource = create_resource(
        cx,
        move || (page_data_action.version().get()),
        move |_| get_home_page(cx),
    );
    let page_data = move || {
        page_data_resource
            .read()
            .map(|val| val.unwrap_or(String::default()))
            .unwrap_or(String::default())
    };

    view! { cx,
        <LoggedInRedirect
            success_route=None
            fail_route=Some("/landing".to_string())
        />
        <h1>"Auth-Example"</h1>
        <h2>"Logged In Homepage"</h2>
        <p>"Hello! "{page_data}</p>
        <p><LogHeader/></p>
        <p><LogoutButton/></p>
    }
}

#[server(GetHomePage, "/api")]
pub async fn get_home_page(cx: Scope) -> Result<String, ServerFnError> {
    let session_valid = validate_session(cx);
    match session_valid {
        true => Ok(String::from("You are logged in!")),
        false => Ok(String::from("You are not logged in!")),
    }
}
