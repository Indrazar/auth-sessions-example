#[cfg(feature = "ssr")]
use leptos::ServerFnError;
#[cfg(feature = "ssr")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "ssr")]
use sqlx::{Connection, SqliteConnection};
#[cfg(feature = "ssr")]
use uuid::Uuid;

#[cfg(feature = "ssr")]
pub async fn db() -> Result<SqliteConnection, ServerFnError> {
    SqliteConnection::connect("sqlite:auth-example.db")
        .await
        .map_err(|e| ServerFnError::ServerError(e.to_string()))
}

#[cfg(feature = "ssr")]
pub async fn register_user(
    username: String,
    displayname: String,
    email: String,
    password_hash: String,
) -> Result<Uuid, ServerFnError> {
    let id = Uuid::now_v7();
    let mut conn = match db().await {
        Ok(res) => res,
        Err(e) => {
            log::error!("failed to connect to database in validate_credentials: {e}");
            return Err(ServerFnError::ServerError(String::from(
                "Signin Request failed.",
            )));
        }
    };
    let query_res = sqlx::query!(
        "INSERT INTO users (user_id, username, displayname, email, verified, password_hash) \
         VALUES (?, ?, ?, ?, ?, ?)",
        id,
        username,
        displayname,
        email,
        false,
        password_hash,
    )
    .execute(&mut conn)
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
    Ok(id)
}

#[cfg(feature = "ssr")]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UniqueCredential {
    Username(String),
    DisplayName(String),
    //Email(String),
}

#[cfg(feature = "ssr")]
pub async fn unique_cred_check(input: UniqueCredential) -> Result<(), ServerFnError> {
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
        UniqueCredential::DisplayName(displayname) => displayname_check(displayname).await,
        //UniqueCredential::Email(email) => email_check(email).await,
    }
}

#[cfg(feature = "ssr")]
async fn username_check(username: String) -> Result<(), ServerFnError> {
    let mut conn = match db().await {
        Ok(res) => res,
        Err(e) => {
            log::error!("failed to connect to database in username_check: {e}");
            return Err(ServerFnError::ServerError(String::from(
                "Signup Request failed.",
            )));
        }
    };
    let user_exists =
        match sqlx::query!("SELECT username FROM users WHERE username = ?", username)
            .fetch_one(&mut conn)
            .await
        {
            Ok(_) => true, //username.eq(&row.username)
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
    if user_exists {
        //TODO prevent user enumeration
        Err(ServerFnError::ServerError(String::from(
            "Username already in use. Signup Request failed.",
        )))
    } else {
        Ok(())
    }
}

#[cfg(feature = "ssr")]
async fn displayname_check(displayname: String) -> Result<(), ServerFnError> {
    let mut conn = match db().await {
        Ok(res) => res,
        Err(e) => {
            log::error!("failed to connect to database in displayname_check: {e}");
            return Err(ServerFnError::ServerError(String::from(
                "Signup Request failed.",
            )));
        }
    };
    let display_exists = match sqlx::query!(
        "SELECT displayname FROM users WHERE displayname = ?",
        displayname
    )
    .fetch_one(&mut conn)
    .await
    {
        Ok(_) => true, //displayname.eq(&row.displayname)
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
    if display_exists {
        Err(ServerFnError::ServerError(String::from(
            "Displayname already in use. Signup Request failed.",
        )))
    } else {
        Ok(())
    }
}

/*#[cfg(feature = "ssr")]
async fn email_check(email: String) -> Result<(), ServerFnError> {
    let mut conn = match db().await {
        Ok(res) => res,
        Err(e) => {
            log::error!("failed to connect to database in email_check: {e}");
            return Err(ServerFnError::ServerError(String::from(
                "Signup Request failed.",
            )));
        }
    };
    let email_exists = match sqlx::query!("SELECT email FROM users WHERE email = ?", email)
        .fetch_one(&mut conn)
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
