use leptos::*;

use crate::pages::{get_userdata, Login, Logout, Signup};

#[component]
pub fn HomePage(
    action1: Action<Login, Result<(), ServerFnError>>,
    action2: Action<Signup, Result<String, ServerFnError>>,
    action3: Action<Logout, Result<(), ServerFnError>>,
) -> impl IntoView {
    let user_resource = create_resource(
        move || {
            (
                action1.version().get(),
                action2.version().get(),
                action3.version().get(),
            )
        },
        move |_| get_userdata(),
    );

    view! {
        <Transition
            fallback=move || view! {<p>"Loading..."</p>}
        >
        {move || {
            user_resource.read().map(|data| match data {
                Err(e) => view! {
                    <p>"There was an error loading the page."</p>
                    <span>{format!("error: {}", e)}</span>
                }.into_view(),
                Ok(None) => view! {
                    <></>
                }.into_view(),
                Ok(Some(userdata)) => view! {
                    <div class="main-text">
                        <p>"Hello! This is your home page " {userdata.display_name.clone()} </p>
                        <p>"More information could be put here if we wanted. So far all we have is: " {format!("{:?}", userdata.clone())}</p>
                    </div>
                }.into_view(),
            })
        }}
        </Transition>
    }
}
