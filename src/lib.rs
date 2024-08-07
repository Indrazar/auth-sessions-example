pub mod app;
pub mod cookies;
pub mod database;
pub mod defs;
pub mod fileserv;
pub mod security;
pub mod websocket;

use cfg_if::cfg_if;
cfg_if! { if #[cfg(feature = "hydrate")] {
    #[wasm_bindgen::prelude::wasm_bindgen]
    pub fn hydrate() {

        use app::*;
        //use leptos::prelude::*;

        _ = console_log::init_with_level(log::Level::Debug);
        console_error_panic_hook::set_once();

        leptos::mount::hydrate_body(App);
    }
}}
