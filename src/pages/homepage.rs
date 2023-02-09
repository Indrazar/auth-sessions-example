use crate::pages::components::logheader::*;
use crate::pages::components::redirect::*;
use leptos::*;

#[cfg(feature = "ssr")]
pub fn register_server_functions() -> Result<(), ServerFnError> {
    GetHomePage::register()?;
    Ok(())
}

#[component]
pub fn HomePage(cx: Scope) -> impl IntoView {
    let page_data = create_server_action::<GetHomePage>(cx);
    let _ = create_resource(
        cx,
        move || (page_data.version().get()),
        move |_| get_home_page(cx),
    );

    view! { cx,
        <LoggedInRedirect
            success_route=None
            fail_route=Some("/".to_string())
        />
        <p><LogHeader/></p>
    }
}

#[server(GetHomePage, "/api")]
pub async fn get_home_page(cx: Scope) -> Result<(), ServerFnError> {
    let session_valid = validate_session(cx)?;
    match session_valid {
        true => todo!(),
        false => todo!(),
    }
}
