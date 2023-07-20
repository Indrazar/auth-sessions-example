use cfg_if::cfg_if;

cfg_if! { if #[cfg(feature = "ssr")] {
    use crate::security::RegistrationError;
    use chrono::prelude::*;
    use leptos::*;
    use secrecy::SecretString;
    use sqlx::SqlitePool;
    use uuid::Uuid;
}}
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserData {
    pub display_name: String,
    pub button_presses: i64,
}

#[cfg(feature = "ssr")]
#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
struct UserDataForPage {
    display_name: String,
    button_presses: i64,
}

#[cfg(feature = "ssr")]
pub fn pool() -> Result<SqlitePool, ServerFnError> {
    use_context::<SqlitePool>()
        .ok_or("Pool missing.")
        .map_err(|e| ServerFnError::ServerError(e.to_string()))
}

#[cfg(feature = "ssr")]
pub async fn userdata(id: Uuid) -> Result<UserData, ServerFnError> {
    let pool = pool()?;
    let row = sqlx::query_as!(
        UserDataForPage,
        r#"SELECT display_name, button_presses FROM users WHERE user_id = ?"#,
        id
    )
    .fetch_one(&pool)
    .await;
    let (display_name, button_presses): (String, i64) = match row {
        Ok(res) => (res.display_name, res.button_presses),
        Err(e) => match e {
            sqlx::Error::RowNotFound => {
                return Err(ServerFnError::ServerError(String::from(
                    "User ID not found",
                )));
            }
            _ => {
                log::trace!("database lookup for display name failed: {e}");
                return Err(ServerFnError::ServerError(String::from(
                    "Information retrieval failed",
                )));
            }
        },
    };
    Ok(UserData {
        display_name: display_name,
        button_presses: button_presses,
    })
}

#[cfg(feature = "ssr")]
pub async fn register_user(
    username: String,
    display_name: String,
    email: String,
    password_hash: String,
) -> Result<Uuid, ServerFnError> {
    let pool = pool()?;
    let id = Uuid::now_v7();
    let query_res = sqlx::query!(
        "INSERT INTO users (user_id, username, display_name, email, verified, password_hash, button_presses) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
        id,
        username,
        display_name,
        email,
        false,
        password_hash,
        0,
    )
    .execute(&pool)
    .await;
    match query_res {
        Ok(val) => {
            if val.rows_affected() != 1 {
                log::error!(
                    "database error when registering user, rows !=1, val: {:#?}",
                    val
                );
                return Err(ServerFnError::ServerError(String::from(
                    "Signup Request failed.",
                )));
            }
        }
        Err(e) => {
            log::error!("database error when registering user: {e}");
            return Err(ServerFnError::ServerError(String::from(
                "Signup Request failed.",
            )));
        }
    };
    Ok(id)
}

#[cfg(feature = "ssr")]
pub async fn associate_session(
    user_id: Uuid,
    session_id: &String,
    expire_time: DateTime<Utc>,
) -> Result<(), ServerFnError> {
    let pool = pool()?;
    let query_res = sqlx::query!(
        "INSERT INTO active_sesssions (session_id, user_id, expiry) VALUES (?, ?, ?)",
        session_id,
        user_id,
        expire_time
    )
    .execute(&pool)
    .await;
    match query_res {
        Ok(val) => {
            if val.rows_affected() != 1 {
                return Err(ServerFnError::ServerError(String::from(
                    "Signup Request failed.",
                )));
            }
        }
        Err(_) => {
            return Err(ServerFnError::ServerError(String::from(
                "Signup Request failed.",
            )));
        }
    };
    Ok(())
}

#[cfg(feature = "ssr")]
pub async fn drop_session(session_id: &String) {
    let pool = match pool() {
        Ok(pool) => pool,
        Err(e) => {
            log::error!("could not retrieve pool in drop_session: {e}");
            return;
        }
    };
    let remove_res = sqlx::query!(
        "DELETE FROM active_sesssions WHERE session_id = ?",
        session_id
    )
    .execute(&pool)
    .await;
    match remove_res {
        Ok(val) => {
            if val.rows_affected() != 1 {
                log::trace!(
                    "removal of session from database failed, rows_affected: {}",
                    val.rows_affected()
                );
                return;
            }
            log::trace!("session_id: {session_id} logged out: {:#?}", val);
            return;
        }
        Err(e) => {
            log::error!("removal of session from database failed: {e}");
            return;
        }
    };
}

#[cfg(feature = "ssr")]
#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
struct ValidateSession {
    user_id: Uuid,
    expiry: DateTime<Utc>,
}

#[cfg(feature = "ssr")]
pub async fn validate_token(
    untrusted_session: String,
) -> Result<Option<uuid::Uuid>, ServerFnError> {
    let pool = pool()?;
    let row = sqlx::query_as!(
        ValidateSession,
        r#"SELECT user_id AS "user_id: Uuid", expiry AS "expiry: DateTime<Utc>" FROM active_sesssions WHERE session_id = ?"#,
        untrusted_session
    )
    .fetch_one(&pool)
    .await;
    let (true_uuid, expiry): (Uuid, DateTime<Utc>) = match row {
        Ok(cred) => (cred.user_id, cred.expiry),
        Err(e) => match e {
            sqlx::Error::RowNotFound => {
                return Ok(None);
            }
            _ => {
                log::debug!("invalid session provided with error: {e}");
                return Err(ServerFnError::ServerError(String::from(
                    "Session retrieval failed",
                )));
            }
        },
    };
    //validate NOT expired
    if expiry < Utc::now() {
        drop_session(&untrusted_session).await;
        Ok(None)
    } else {
        Ok(Some(true_uuid))
    }
}

#[cfg(feature = "ssr")]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
struct ValidateCredential {
    user_id: Uuid,
    password_hash: String,
}

#[cfg(feature = "ssr")]
pub async fn retrieve_credentials(
    username: &String,
) -> Result<Option<(Uuid, SecretString)>, ServerFnError> {
    let pool = pool()?;
    let row = sqlx::query_as!(
        ValidateCredential,
        r#"SELECT user_id AS "user_id: Uuid", password_hash FROM users WHERE username = ?"#,
        username
    )
    .fetch_one(&pool)
    .await;
    match row {
        Ok(cred) => Ok(Some((cred.user_id, SecretString::from(cred.password_hash)))),
        Err(e) => match e {
            sqlx::Error::RowNotFound => Ok(None),
            _ => {
                log::trace!("failed login on username: {username} with error {e}");
                return Err(ServerFnError::ServerError(String::from(
                    "Login Request failed.",
                )));
            }
        },
    }
}

#[cfg(feature = "ssr")]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UniqueCredential {
    Username(String),
    DisplayName(String),
    //Email(String),
}

#[cfg(feature = "ssr")]
pub async fn unique_cred_check(input: UniqueCredential) -> Result<(), RegistrationError> {
    // we won't require usernames =/= display names
    //
    // we will require both usernames and display names both do not already exist
    // but we should also restrict how many times people can check for unique
    // usernames to prevent user enumeration
    //
    // the anti-bot id could be restricted to 10 username lookups/25 min?
    // TODO: Actually implement anti-bot and anti-"username-enumeration"
    //
    // display name enumeration should be fine since you can see those while signed in
    // and display names are not used for sign in, only for displaying to other users
    match input {
        UniqueCredential::Username(username) => username_check(username).await,
        UniqueCredential::DisplayName(display_name) => display_name_check(display_name).await,
        /* UniqueCredential::Email(email) => email_check(email).await, */
    }
}

#[cfg(feature = "ssr")]
async fn username_check(username: String) -> Result<(), RegistrationError> {
    let pool = pool()?;
    let user_exists =
        match sqlx::query!("SELECT username FROM users WHERE username = ?", username)
            .fetch_one(&pool)
            .await
        {
            Ok(_) => true, //username.eq(&row.username)
            Err(e) => match e {
                // row not found is returned as error, but it is not actually an error
                sqlx::Error::RowNotFound => false,
                _ => {
                    log::error!("possible database error: {e}");
                    return Err(RegistrationError::ServerError(ServerFnError::ServerError(
                        String::from("Signup Request failed."),
                    )));
                }
            },
        };
    if user_exists {
        //TODO prevent user enumeration
        Err(RegistrationError::UniqueUsername)
    } else {
        Ok(())
    }
}

#[cfg(feature = "ssr")]
async fn display_name_check(display_name: String) -> Result<(), RegistrationError> {
    let pool = pool()?;
    let display_exists = match sqlx::query!(
        "SELECT display_name FROM users WHERE display_name = ?",
        display_name
    )
    .fetch_one(&pool)
    .await
    {
        Ok(_) => true, //display_name.eq(&row.display_name)
        Err(e) => match e {
            // row not found is returned as error, but it is not actually an error
            sqlx::Error::RowNotFound => false,
            _ => {
                log::error!("possible database error: {e}");
                return Err(RegistrationError::ServerError(ServerFnError::ServerError(
                    String::from("Signup Request failed."),
                )));
            }
        },
    };
    if display_exists {
        Err(RegistrationError::UniqueDisplayName)
    } else {
        Ok(())
    }
}

/*#[cfg(feature = "ssr")]
async fn email_check(email: String) -> Result<(), ServerFnError> {
    let pool = pool()?;
    let email_exists = match sqlx::query!("SELECT email FROM users WHERE email = ?", email)
        .fetch_one(&pool)
        .await
    {
        Ok(_) => true, //email.eq(&row.email)
        Err(e) => match e {
            // row not found is returned as error, but it is not actually an error
            sqlx::Error::RowNotFound => false,
            _ => {
                log::error!("possible database error: {e}");
                return Err(ServerFnError::ServerError(String::from(
                    "Signup Request failed.",
                )));
            }
        },
    };
    if email_exists {
        //TODO prevent user email enumeration
        return Err(ServerFnError::ServerError(String::from(
            "Email already in use. Signup Request failed.",
        )));
    } else {
        Ok(())
    }
}*/
