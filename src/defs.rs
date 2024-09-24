use const_format::formatcp;
//use std::fmt;

// site domain name
pub const SITE_DOMAIN: &str = dotenvy_macro::dotenv!("SITE_DOMAIN");
// site websocket location
// websocket code requires wss:// with /ws on the end
pub const WEBSOCKET_URL: &str = formatcp!("wss://{SITE_DOMAIN}/ws");
// directive must be ws:// without /ws on the end
pub const WEBSOCKET_DIRECTIVE_URL: &str = formatcp!("ws://{SITE_DOMAIN}/");

/// Username max length limit
pub const USERNAME_MAX_LEN: usize = 32;
pub const USERNAME_MAX_LEN_STR: &str = formatcp!("{USERNAME_MAX_LEN}");

/// Username min length limit
pub const USERNAME_MIN_LEN: usize = 3;
pub const USERNAME_MIN_LEN_STR: &str = formatcp!("{USERNAME_MIN_LEN}");

/// Display Name max length limit
pub const DISPLAY_NAME_MAX_LEN: usize = 16;
pub const DISPLAY_NAME_MAX_LEN_STR: &str = formatcp!("{DISPLAY_NAME_MAX_LEN}");

/// Display Name min length limit
pub const DISPLAY_NAME_MIN_LEN: usize = 3;
pub const DISPLAY_NAME_MIN_LEN_STR: &str = formatcp!("{DISPLAY_NAME_MIN_LEN}");

/// Display Name valid characters
pub const DISPLAY_NAME_VALID_CHARACTERS: &str =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_ ()[]{}<>^+-/";

/// Password max length limit
pub const PASSWORD_MAX_LEN: usize = 65_536;
pub const PASSWORD_MAX_LEN_STR: &str = formatcp!("{PASSWORD_MAX_LEN}");

/// Password min length limit
pub const PASSWORD_MIN_LEN: usize = 15;
pub const PASSWORD_MIN_LEN_STR: &str = formatcp!("{PASSWORD_MIN_LEN}");

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "ssr")] {
        use leptos::prelude::*;
        use sqlx::SqlitePool;
        use axum::extract::FromRef;
        use leptos_axum::AxumRouteListing;

        #[derive(Debug, Clone, Copy)]
        pub struct ServerVars {
            pub csrf_server: u128,
        }

        #[derive(FromRef, Debug, Clone)]
        pub struct AppState {
            pub leptos_options: LeptosOptions,
            pub pool: SqlitePool,
            pub routes: Vec<AxumRouteListing>,
            pub vars: ServerVars,
        }
    }
}

#[cfg(feature = "ssr")]
#[derive(Debug)]
pub enum AppError {
    Router(RouterError),
    Registration(RegistrationError),
    Login(LoginError),
    Database(DatabaseError),
    CSRF(CsrfError),
    Argon2Failure,
    TokioFailure,
}

#[cfg(feature = "ssr")]
impl From<AppError> for ServerFnError {
    fn from(item: AppError) -> Self {
        ServerFnError::ServerError(format!("{}", item))
    }
}

#[cfg(feature = "ssr")]
#[derive(Debug)]
pub enum RouterError {
    HTTPRequestMissing,
}

#[cfg(feature = "ssr")]
impl From<RouterError> for AppError {
    fn from(item: RouterError) -> Self {
        AppError::Router(item)
    }
}

#[cfg(feature = "ssr")]
impl From<RouterError> for ServerFnError {
    fn from(item: RouterError) -> Self {
        ServerFnError::ServerError(format!("{}", item))
    }
}

#[cfg(feature = "ssr")]
#[derive(Debug)]
pub enum RegistrationError {
    EmailNotMatching,
    InvalidEmail,
    PasswordNotMatching,
    UsernameLength,
    DisplayNameLength,
    PasswordLength,
    DisplayNameInvalidCharacters,
    UniqueUsername,
    UniqueDisplayName,
}

#[cfg(feature = "ssr")]
impl From<RegistrationError> for AppError {
    fn from(item: RegistrationError) -> Self {
        AppError::Registration(item)
    }
}

#[cfg(feature = "ssr")]
impl From<RegistrationError> for ServerFnError {
    fn from(item: RegistrationError) -> Self {
        ServerFnError::ServerError(format!("{}", item))
    }
}

#[cfg(feature = "ssr")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CsrfError {
    MultipleCookies,
    NoMatchingCookie,
    ServerValMissing,
}

#[cfg(feature = "ssr")]
impl From<CsrfError> for AppError {
    fn from(item: CsrfError) -> Self {
        AppError::CSRF(item)
    }
}

#[cfg(feature = "ssr")]
impl From<CsrfError> for ServerFnError {
    fn from(item: CsrfError) -> Self {
        ServerFnError::ServerError(format!("{}", item))
    }
}

#[cfg(feature = "ssr")]
#[derive(Debug)]
pub enum DatabaseError {
    CouldNotFindPool,
    QueryFailed,
    NoEntries,
    IncorrectRowsAffected,
}

#[cfg(feature = "ssr")]
impl From<DatabaseError> for AppError {
    fn from(item: DatabaseError) -> Self {
        AppError::Database(item)
    }
}

#[cfg(feature = "ssr")]
impl From<DatabaseError> for ServerFnError {
    fn from(item: DatabaseError) -> Self {
        ServerFnError::ServerError(format!("{}", item))
    }
}

#[cfg(feature = "ssr")]
#[derive(Debug)]
pub enum LoginError {
    IncorrectCredentials,
}

#[cfg(feature = "ssr")]
impl From<LoginError> for AppError {
    fn from(item: LoginError) -> Self {
        AppError::Login(item)
    }
}

#[cfg(feature = "ssr")]
impl From<LoginError> for ServerFnError {
    fn from(item: LoginError) -> Self {
        ServerFnError::ServerError(format!("{}", item))
    }
}

#[cfg(feature = "ssr")]
impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::Router(x) => {
                write!(f, "{}", x)
            }
            AppError::Registration(x) => {
                write!(f, "{}", x)
            }
            AppError::CSRF(x) => {
                write!(f, "{}", x)
            }
            AppError::Login(x) => {
                write!(f, "{}", x)
            }
            AppError::Database(x) => {
                write!(f, "{}", x)
            }
            AppError::Argon2Failure => {
                write!(f, "Internal Server Error")
            }
            AppError::TokioFailure => {
                write!(f, "Internal Server Error")
            }
        }
    }
}

#[cfg(feature = "ssr")]
impl std::fmt::Display for RouterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouterError::HTTPRequestMissing => {
                write!(f, "Please try again in a few minutes after a page refresh.")
            }
        }
    }
}

#[cfg(feature = "ssr")]
impl std::fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistrationError::EmailNotMatching => {
                write!(f, "Emails do not match.")
            }
            RegistrationError::InvalidEmail => {
                write!(f, "Email was invalid.")
            }
            RegistrationError::PasswordNotMatching => {
                write!(f, "Passwords do not match.")
            }
            RegistrationError::PasswordLength => {
                write!(f, "Password does not meet the length requirement.")
            }
            RegistrationError::UsernameLength => {
                write!(f, "Username does not meet the length requirement.")
            }
            RegistrationError::DisplayNameLength => {
                write!(f, "Username does not meet the length requirement.")
            }
            RegistrationError::DisplayNameInvalidCharacters => {
                write!(f, "Display name contains disallowed characters.")
            }
            RegistrationError::UniqueUsername => {
                write!(f, "Username is already taken.")
            }
            RegistrationError::UniqueDisplayName => {
                write!(f, "Display name is already taken.")
            }
        }
    }
}

#[cfg(feature = "ssr")]
impl std::fmt::Display for CsrfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CsrfError::MultipleCookies => {
                write!(f, "Please try again in a few minutes after a page refresh. If this error occurs again please clear your cookies for this website.")
            }
            CsrfError::NoMatchingCookie => {
                write!(f, "Please try again in a few minutes after a page refresh. Please make sure cookies are enabled.")
            }
            CsrfError::ServerValMissing => {
                write!(f, "Internal Server Error.")
            }
        }
    }
}

#[cfg(feature = "ssr")]
impl std::fmt::Display for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoginError::IncorrectCredentials => write!(f, "Login Request was invalid."),
        }
    }
}

#[cfg(feature = "ssr")]
impl std::fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DatabaseError::CouldNotFindPool => {
                write!(f, "Please try again in a few minutes after a page refresh.")
            }
            DatabaseError::QueryFailed => {
                write!(f, "Please try again in a few minutes after a page refresh.")
            }
            DatabaseError::NoEntries => {
                write!(f, "Please try again in a few minutes after a page refresh.")
            }
            DatabaseError::IncorrectRowsAffected => {
                write!(f, "Please try again in a few minutes after a page refresh.")
            }
        }
    }
}
