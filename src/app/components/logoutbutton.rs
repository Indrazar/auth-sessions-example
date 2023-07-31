use leptos::*;

#[component]
pub fn LogoutButton() -> impl IntoView {
    view! {
        <a href="/logout">
            <input class="logout-button" type="submit" value="Logout"/>
        </a>
    }
}
