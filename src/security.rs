use cfg_if::cfg_if;

cfg_if! { if #[cfg(feature = "ssr")] {
    use crate::cookies::get_cookie_value;
    use crate::database::{db, register_user, unique_cred_check, UniqueCredential};
    use argon2::{
        password_hash::{PasswordVerifier, SaltString},
        Argon2, PasswordHash, PasswordHasher,
    };
    use axum::http::{
        header::{COOKIE, SET_COOKIE},
        HeaderValue,
    };
    use email_address::EmailAddress;
    use leptos::*;
    use leptos_axum::RequestParts;
    use secrecy::{ExposeSecret, SecretString};
    use serde::{Deserialize, Serialize};
    use std::str::FromStr;
    use uuid::Uuid;
}}

#[cfg(feature = "ssr")]
pub fn generate_csrf(cx: Scope) -> String {
    let response = match use_context::<leptos_axum::ResponseOptions>(cx) {
        Some(ro) => ro,
        None => return String::default(),
    };
    //TODO use a CSPRNG here
    let csrf_string = String::from("valid");
    response.append_header(
        SET_COOKIE,
        HeaderValue::from_str(
            format!("__Host-csrf={csrf_string}; Secure; HttpOnly; SameSite=Lax; Path=/")
                .as_str(),
        )
        .expect("to create header value"),
    );
    log::trace!("provided a csrf cookie");
    csrf_string
}

#[cfg(feature = "ssr")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CsrfError {
    MultipleCookies,
    NoMatchingCookie,
}

#[cfg(feature = "ssr")]
pub fn validate_csrf(req: RequestParts, csrf_token: String) -> Result<(), CsrfError> {
    let mut only_one = 0;
    let mut cookie_value = String::default();
    for headercookie in req.headers.get_all(COOKIE).iter() {
        match headercookie.to_str() {
            Ok(cookie) => {
                if let Some(csrf_cookie) = get_cookie_value(cookie, "__Host-csrf") {
                    only_one += 1;
                    if only_one > 1 {
                        // multiple cookies with the same value is an out
                        // of date browser or some other fixation attack
                        return Err(CsrfError::MultipleCookies);
                    }
                    cookie_value = csrf_cookie;
                }
            }
            Err(_) => continue,
        }
    }
    if cookie_value.eq(&csrf_token) {
        log::trace!("csrf cookie+token was validated");
        Ok(())
    } else {
        Err(CsrfError::NoMatchingCookie)
    }
}

#[cfg(feature = "ssr")]
pub async fn validate_registration(
    cx: Scope,
    csrf: String,
    username: String,
    displayname: String,
    email: String,
    email_confirmation: String,
    password: SecretString,
    password_confirmation: SecretString,
) -> Result<(), ServerFnError> {
    let http_req = match use_context::<leptos_axum::RequestParts>(cx) {
        None => {
            log::error!("signup: could not retrieve RequestParts");
            return Err(ServerFnError::ServerError(String::from(
                "Signup Request failed.",
            )));
        }
        Some(rp) => rp,
    };
    //validate token matches cookie
    validate_csrf(http_req, csrf).map_err(|e| match e {
        CsrfError::MultipleCookies => {
            log::trace!("signup: multiple cookies present on client request");
            ServerFnError::ServerError(String::from("Signup Request was invalid."))
        }
        CsrfError::NoMatchingCookie => {
            log::trace!("signup: csrf did not match cookie");
            ServerFnError::ServerError(String::from("Signup Request was invalid."))
        }
    })?;
    //validate email matches in both fields
    match email_confirmation.eq(&email) {
        false => {
            return Err(ServerFnError::ServerError(String::from(
                "Provided emails do not match. Signup Request was invalid.",
            )));
        }
        true => {}
    };
    //validate password matches in both fields
    match password_confirmation
        .expose_secret()
        .eq(password.expose_secret())
    {
        false => {
            return Err(ServerFnError::ServerError(String::from(
                "Provided passwords do not match. Signup Request was invalid.",
            )));
        }
        true => {}
    };
    //validate password meets minimum length requirement
    if password.expose_secret().len() < 14 {
        return Err(ServerFnError::ServerError(String::from(
            "Provided password does not meet the length requirement. Signup Request was \
             invalid.",
        )));
    }
    //validate email is correct format
    if EmailAddress::from_str(email.as_str()).is_err() {
        return Err(ServerFnError::ServerError(String::from(
            "Signup Request was invalid.",
        )));
    }
    unique_cred_check(UniqueCredential::Username(username.clone())).await?;
    unique_cred_check(UniqueCredential::DisplayName(displayname.clone())).await?;
    //unique_cred_check(UniqueCredential::Email(email)).await?;
    let password_hash = gen_hash(password)?;
    log::trace!("signup: successful registration for user: {username}, name: {displayname}");
    register_user(username, displayname, email, password_hash).await?;
    log::trace!("signup: db write succeeded for new user");
    Ok(())
}

#[cfg(feature = "ssr")]
pub async fn validate_login(
    cx: Scope,
    csrf: String,
    username: String,
    password: SecretString,
) -> Result<(), ServerFnError> {
    let http_req = match use_context::<leptos_axum::RequestParts>(cx) {
        None => {
            log::error!("login: could not retrieve RequestParts");
            return Err(ServerFnError::ServerError(String::from(
                "Login Request failed.",
            )));
        }
        Some(rp) => rp,
    };
    //validate token matches cookie
    validate_csrf(http_req, csrf).map_err(|e| match e {
        CsrfError::MultipleCookies => {
            log::trace!("login: multiple cookies present on client request");
            ServerFnError::ServerError(String::from("Login Request was invalid."))
        }
        CsrfError::NoMatchingCookie => {
            log::trace!("login: csrf did not match cookie");
            ServerFnError::ServerError(String::from("Login Request was invalid."))
        }
    })?;
    validate_credentials(username.clone(), password).await?;
    log::trace!("login: successful login for user: {username}");
    Ok(())
}

#[cfg(feature = "ssr")]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
struct ValidateCredential {
    user_id: Uuid,
    password_hash: String,
}

#[cfg(feature = "ssr")]
enum ValidateHashError {
    DatabaseError(argon2::password_hash::Error),
    VerifyError(argon2::password_hash::Error),
}

#[cfg(feature = "ssr")]
pub async fn validate_credentials(
    username: String,
    untrusted_password: SecretString,
) -> Result<uuid::Uuid, leptos_server::ServerFnError> {
    //TODO consider moving some of this to database.rs
    let mut conn = match db().await {
        Ok(res) => res,
        Err(e) => {
            log::error!("failed to connect to database in validate_credentials: {e}");
            return Err(ServerFnError::ServerError(String::from(
                "Login Request failed.",
            )));
        }
    };
    //let row = sqlx::query_as::<_, ValidateCredential>(
    //    "SELECT user_id, password_hash FROM users WHERE username = $1",
    //)
    let row = sqlx::query_as!(
        ValidateCredential,
        r#"SELECT user_id AS "user_id: Uuid", password_hash FROM users WHERE username = ?"#,
        username
    )
    .fetch_one(&mut conn)
    .await;

    let (true_uuid, stored_phc): (Uuid, SecretString) = match row {
        Ok(cred) => (cred.user_id, SecretString::from(cred.password_hash)),
        Err(e) => {
            //execute some time wasting to prevent username enumeration
            let _task =
                tokio::task::spawn_blocking(move || spin_hash(untrusted_password)).await;
            log::trace!("invalid login on username: {username} with error {e}");
            return Err(ServerFnError::ServerError(String::from(
                "Login Request was invalid.",
            )));
        }
    };
    let task =
        tokio::task::spawn_blocking(move || verify_hash(stored_phc, untrusted_password)).await;
    match task {
        Ok(Ok(_)) => Ok(true_uuid),
        Ok(Err(ValidateHashError::DatabaseError(e))) => {
            //database is possibly corrupted
            log::error!("could not parse PHC for {username} with error {e}");
            Err(ServerFnError::ServerError(String::from(
                "Login Request failed.",
            )))
        }
        Ok(Err(ValidateHashError::VerifyError(e))) => {
            log::trace!("invalid password attempt for {username} with error {e}");
            Err(ServerFnError::ServerError(String::from(
                "Login Request was invalid.",
            )))
        }
        Err(tokio_err) => {
            log::error!("failed to spawn blocking tokio task: {tokio_err}");
            Err(ServerFnError::ServerError(String::from(
                "Login Request failed.",
            )))
        }
    }
}

#[cfg(feature = "ssr")]
fn gen_hash(input: SecretString) -> Result<String, ServerFnError> {
    // forever TODO: improve salt and complextity of hashing as computers get better
    // and as people buy more PS5s and shove them in underwater hashing factories
    let salt = SaltString::generate(&mut rand::thread_rng());
    match Argon2::default().hash_password(input.expose_secret().as_bytes(), &salt) {
        Ok(hash) => Ok(hash.to_string()),
        Err(err) => {
            log::trace!("failed to produce hash of password in gen_hash: {err}");
            Err(ServerFnError::ServerError(String::from(
                "Signup Request failed.",
            )))
        }
    }
}

#[cfg(feature = "ssr")]
fn verify_hash(
    stored_password_hash: SecretString,
    password_candidate: SecretString,
) -> Result<(), ValidateHashError> {
    let expected_password_hash = match PasswordHash::new(stored_password_hash.expose_secret())
    {
        Ok(hash) => hash,
        Err(e) => {
            //database is possibly corrupted
            return Err(ValidateHashError::DatabaseError(e));
        }
    };

    Argon2::default()
        .verify_password(
            password_candidate.expose_secret().as_bytes(),
            &expected_password_hash,
        )
        .map_err(ValidateHashError::VerifyError)
}

#[cfg(feature = "ssr")]
#[allow(unused_must_use)]
fn spin_hash(untrusted_password: SecretString) {
    // forever TODO: update this hash as we improve the gen_hash
    // notes about this hash: it is not a real hash, just to waste time using the same algo.
    // This hash is NOT a secret. This function returns NOTHING, only wastes time.
    let static_hash = PasswordHash::new(
        "$argon2id$v=19$m=4096,t=3,p=1$tKyUZbQxabvC3XB323vWmw$mMtsEupAXrnh00lI/\
         6kPHNpIGntadmxH/Hlr3i29CH0",
    )
    .unwrap();

    Argon2::default()
        .verify_password(untrusted_password.expose_secret().as_bytes(), &static_hash)
        .map_err(ValidateHashError::VerifyError);
}
