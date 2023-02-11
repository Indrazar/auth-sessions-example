use leptos::*;

#[component]
pub fn LogoutButton(cx: Scope) -> impl IntoView {
    //let logout = create_server_action::<DestroySession>(cx);

    view! { cx,
        <a href="/logout">
            <input class="logout-button" type="submit" value="Logout"/>
        </a>
    }
}
