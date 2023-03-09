#[cfg(feature = "ssr")]
use crate::cookies::validate_session;
#[cfg(feature = "ssr")]
use crate::database::user_display_name;
use crate::pages::components::{
    logheader::{LogHeader, LogHeaderProps},
    logoutbutton::{LogoutButton, LogoutButtonProps},
    redirect::{LoggedInRedirect, LoggedInRedirectProps},
};
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
            .read(cx)
            .map(|val| val.unwrap_or(String::default()))
            .unwrap_or(String::default())
    };

    view! { cx,
        <LoggedInRedirect
            success_route=None
            fail_route=Some("/landing".to_string())
        />
        <h1>"Auth-Sessions-Example"</h1>
        <h2>"Logged In Homepage"</h2>
        <p>"Hello! "{page_data}</p>
        <LogHeader/>
        <p><LogoutButton/></p>
    }
}

#[server(GetHomePage, "/api")]
pub async fn get_home_page(cx: Scope) -> Result<String, ServerFnError> {
    let session_valid = validate_session(cx).await?;
    match session_valid {
        Some(id) => {
            let display_name = user_display_name(cx, id).await?;
            Ok(format!("You are logged in {display_name}!"))
        }
        None => Ok(String::from("You are not logged in")),
    }
}
