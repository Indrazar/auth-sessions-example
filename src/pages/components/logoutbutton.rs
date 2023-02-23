use leptos::*;

#[component]
pub fn LogoutButton(cx: Scope) -> impl IntoView {
    view! { cx,
        <a href="/logout">
            <input class="logout-button" type="submit" value="Logout"/>
        </a>
    }
}
