pub mod logheader;
pub mod logoutbutton;
pub mod redirect;
use cfg_if::cfg_if;

cfg_if! { if #[cfg(feature = "ssr")] {
    use leptos::*;

    pub fn register_server_functions() -> Result<(), ServerFnError> {
        logheader::LogClientHeader::register()?;
        redirect::ProcessRedirect::register()?;
        Ok(())
    }
}}
