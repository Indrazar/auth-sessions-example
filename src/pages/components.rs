pub mod logheader;
pub mod logout;
pub mod redirect;
use cfg_if::cfg_if;

cfg_if! { if #[cfg(feature = "ssr")] {
    use leptos::*;

    pub fn register_server_functions() -> Result<(), ServerFnError> {
        logout::DestroySession::register()?;
        logheader::LogClientHeader::register()?;
        redirect::ProcessRedirect::register()?;
        Ok(())
    }
}}
