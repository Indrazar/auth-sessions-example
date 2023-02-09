pub mod cookies;
pub mod fileserv;
pub mod pages;

use cfg_if::cfg_if;
cfg_if! { if #[cfg(feature = "hydrate")] {
    use wasm_bindgen::prelude::wasm_bindgen;

    #[wasm_bindgen]
    pub fn hydrate() {

        use pages::*;
        use leptos::*;

        console_error_panic_hook::set_once();
        _ = console_log::init_with_level(log::Level::Debug);
        console_error_panic_hook::set_once();

        leptos::mount_to_body(|cx| {
            view! { cx, <App/> }
        });
    }
}}
