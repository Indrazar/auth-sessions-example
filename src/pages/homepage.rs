use leptos::*;

use crate::pages::{get_userdata, Login, Logout, Signup};

#[component]
pub fn HomePage(
    cx: Scope,
    action1: Action<Login, Result<(), ServerFnError>>,
    action2: Action<Signup, Result<String, ServerFnError>>,
    action3: Action<Logout, Result<(), ServerFnError>>,
) -> impl IntoView {
    let user_resource = create_resource(
        cx,
        move || {
            (
                action1.version().get(),
                action2.version().get(),
                action3.version().get(),
            )
        },
        move |_| get_userdata(cx),
    );

    view! { cx,
        <Transition
            fallback=move || view! {cx, <p>"Loading..."</p>}
        >
        {move || {
            user_resource.read(cx).map(|data| match data {
                Err(e) => view! {cx,
                    <p>"There was an error loading the page."</p>
                    <span>{format!("error: {}", e)}</span>
                }.into_view(cx),
                Ok(None) => view! {cx,
                    <></>
                }.into_view(cx),
                Ok(Some(userdata)) => view! {cx,
                    <div class="main-text">
                        <p>"Hello! This is your home page " {userdata.display_name.clone()} </p>
                        <p>"More information could be put here if we wanted. So far all we have is: " {format!("{:?}", userdata.clone())}</p>
                    </div>
                }.into_view(cx),
            })
        }}
        </Transition>
    }
}
