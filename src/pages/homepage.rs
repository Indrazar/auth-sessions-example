use crate::pages::get_user_data;
use leptos::*;

#[component]
pub fn HomePage() -> impl IntoView {
    let user_data = create_resource(move || (), move |_| get_user_data());

    view! {
        <Transition
            fallback=move || view! {<p>"Loading..."</p>}
        >
        {move || {
            user_data.read().map(|data| match data {
                Err(e) => view! {
                    <p>"There was an error loading the page."</p>
                    <span>{format!("error: {}", e)}</span>
                }.into_view(),
                Ok(None) => view! {
                    <></>
                }.into_view(),
                Ok(Some(userdata)) => view! {
                    <div class="main-text">
                        <p>"Hello! This is your home page " {userdata.display_name.clone()} "."</p>
                        <p>"More information could be put here if we wanted. So far all we have is: " {format!("{:?}", userdata.clone())}</p>
                    </div>
                }.into_view(),
            })
        }}
        </Transition>
    }
}
