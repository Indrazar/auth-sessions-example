use cfg_if::cfg_if;

cfg_if! { if #[cfg(feature = "ssr")] {
    use crate::cookies::get_cookie_value;
    use crate::database::{register_user, unique_cred_check, retrieve_credentials, UniqueCredential};
    use crate::defs::*;
    use argon2::{
        password_hash::{PasswordVerifier, SaltString},
        Argon2, PasswordHash, PasswordHasher,
    };
    use axum::http::{
        header::{COOKIE, SET_COOKIE},
        HeaderValue,
    };
    use blake2::{Blake2s256, Digest};
    use email_address::EmailAddress;
    use leptos::prelude::*;
    use http::request::Parts;
    use secrecy::{ExposeSecret, SecretString};
    use std::str::FromStr;
    use uuid::Uuid;
}}

#[cfg(feature = "ssr")]
pub fn generate_csrf() -> String {
    let response = match use_context::<leptos_axum::ResponseOptions>() {
        Some(ro) => ro,
        None => return String::default(),
    };
    let csrf_cookie = gen_128bit_base64();
    let csrf_server = match use_context::<ServerVars>() {
        Some(data) => stringify_u128_base64(data.csrf_server),
        None => return String::default(),
    };
    response.append_header(
        SET_COOKIE,
        HeaderValue::from_str(
            format!("__Host-csrf={csrf_cookie}; Secure; SameSite=Lax; HttpOnly; Path=/")
                .as_str(),
        )
        .expect("to create header value"),
    );
    log::trace!("provided a csrf cookie");
    gen_easy_hash(csrf_cookie, csrf_server)
}

#[cfg(feature = "ssr")]
pub fn validate_csrf(req: Parts, csrf_token: String) -> Result<(), CsrfError> {
    let csrf_server = match use_context::<ServerVars>() {
        Some(data) => stringify_u128_base64(data.csrf_server),
        None => {
            log::error!("could not retrieve servervars");
            return Err(CsrfError::ServerValMissing);
        }
    };
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
    if verify_easy_hash(cookie_value, csrf_server, csrf_token) {
        log::trace!("csrf cookie+token was validated");
        Ok(())
    } else {
        Err(CsrfError::NoMatchingCookie)
    }
}

#[cfg(feature = "ssr")]
pub async fn validate_registration(
    csrf: String,
    username: String,
    display_name: String,
    email: String,
    email_confirmation: String,
    password: SecretString,
    password_confirmation: SecretString,
) -> Result<Uuid, AppError> {
    let http_req = match use_context::<Parts>() {
        None => {
            log::error!("validate_registration: could not retrieve RequestParts");
            return Err(RouterError::HTTPRequestMissing.into());
        }
        Some(rp) => rp,
    };
    //validate token matches cookie
    match validate_csrf(http_req, csrf) {
        Err(CsrfError::MultipleCookies) => {
            log::trace!(
                "validate_registration: multiple csrf cookies present on client request"
            );
            return Err(CsrfError::MultipleCookies.into());
        }
        Err(CsrfError::NoMatchingCookie) => {
            log::trace!("validate_registration: csrf did not match cookie");
            return Err(CsrfError::NoMatchingCookie.into());
        }
        Err(CsrfError::ServerValMissing) => {
            log::trace!("validate_registration: csrf server value could not be retrieved");
            return Err(CsrfError::ServerValMissing.into());
        }
        Ok(_) => {}
    };
    //validate email matches in both fields
    match email_confirmation.eq(&email) {
        false => {
            return Err(RegistrationError::EmailNotMatching.into());
        }
        true => {}
    };
    //validate password matches in both fields
    match password_confirmation
        .expose_secret()
        .eq(password.expose_secret())
    {
        false => {
            return Err(RegistrationError::PasswordNotMatching.into());
        }
        true => {}
    };
    //validate password is within length requirements
    if password.expose_secret().len() < PASSWORD_MIN_LEN - 1
        || password.expose_secret().len() > PASSWORD_MAX_LEN
    {
        return Err(RegistrationError::PasswordLength.into());
    }
    //validate username is within length requirements
    if username.len() < USERNAME_MIN_LEN - 1 || username.len() > USERNAME_MAX_LEN {
        return Err(RegistrationError::UsernameLength.into());
    }
    //validate display_name is within length requirements
    if display_name.len() < DISPLAY_NAME_MIN_LEN - 1
        || display_name.len() > DISPLAY_NAME_MAX_LEN
    {
        return Err(RegistrationError::DisplayNameLength.into());
    }
    //validate display_name meets the character restrictions
    for c in display_name.chars() {
        if !DISPLAY_NAME_VALID_CHARACTERS.contains(c) {
            return Err(RegistrationError::DisplayNameInvalidCharacters.into());
        }
    }
    //validate email is correct format
    if EmailAddress::from_str(email.as_str()).is_err() {
        return Err(RegistrationError::InvalidEmail.into());
    }
    unique_cred_check(UniqueCredential::Username(username.clone())).await?;
    unique_cred_check(UniqueCredential::DisplayName(display_name.clone())).await?;
    //unique_cred_check(UniqueCredential::Email(email)).await?;
    let password_hash = gen_hash(password)?;
    log::trace!(
        "signup: successful registration for username: {username}, display_name: \
         {display_name}"
    );
    let id = register_user(username, display_name, email, password_hash).await?;
    log::trace!("signup: db write succeeded for new user");
    Ok(id)
}

#[cfg(feature = "ssr")]
pub async fn validate_login(
    csrf: String,
    username: String,
    password: SecretString,
) -> Result<Uuid, AppError> {
    let http_req = match use_context::<Parts>() {
        None => {
            log::error!("login: could not retrieve RequestParts");
            Err(RouterError::HTTPRequestMissing)
        }
        Some(rp) => Ok(rp),
    }?;
    //validate token matches cookie
    match validate_csrf(http_req, csrf) {
        Err(CsrfError::MultipleCookies) => {
            log::trace!("login: multiple cookies present on client request");
            Err(CsrfError::MultipleCookies)
        }
        Err(CsrfError::NoMatchingCookie) => {
            log::trace!("login: csrf did not match cookie");
            Err(CsrfError::NoMatchingCookie)
        }
        Err(CsrfError::ServerValMissing) => {
            log::trace!("login: servervars are not available");
            Err(CsrfError::ServerValMissing)
        }
        Ok(_) => Ok(()),
    }?;
    //validate password is within length requirements
    if password.expose_secret().len() < PASSWORD_MIN_LEN - 1
        || password.expose_secret().len() > PASSWORD_MAX_LEN
    {
        return Err(RegistrationError::PasswordLength.into());
    }
    //validate username is within length requirements
    if username.len() < USERNAME_MIN_LEN - 1 || username.len() > USERNAME_MAX_LEN {
        return Err(RegistrationError::UsernameLength.into());
    }
    let id = validate_credentials(username.clone(), password).await?;
    log::trace!("login: successful login for user: {username}");
    Ok(id)
}

#[cfg(feature = "ssr")]
pub fn gen_128bit_base64() -> String {
    // this will issue a CSPRNG created 128 bits of entropy in base 64
    // This function only generates the CSPRNG value.
    //
    // For session cookies alternate implementations would deliver AES encrypted
    // data to the user to prevent addtional DB load on each API request including
    // the session cookie.
    //
    // for now we will only use the full random ID and hit the database with each request
    // this is an easy place to improve performance later if it is needed with high DB load
    const CUSTOM_ENGINE: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::general_purpose::NO_PAD,
    );
    base64::Engine::encode(&CUSTOM_ENGINE, Uuid::new_v4().as_bytes())
}

#[cfg(feature = "ssr")]
pub fn gen_128bit() -> u128 {
    // this will issue a CSPRNG created 128 bits of entropy.
    // This function only generates the CSPRNG value.
    //
    // For session cookies alternate implementations would deliver AES encrypted
    // data to the user to prevent addtional DB load on each API request including
    // the session cookie.
    //
    // for now we will only use the full random ID and hit the database with each request
    // this is an easy place to improve performance later if it is needed with high DB load
    Uuid::new_v4().as_u128()
}

#[cfg(feature = "ssr")]
pub fn stringify_u128_base64(input: u128) -> String {
    const CUSTOM_ENGINE: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::general_purpose::NO_PAD,
    );

    base64::Engine::encode(&CUSTOM_ENGINE, input.to_be_bytes())
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
) -> Result<uuid::Uuid, AppError> {
    let (true_uuid, stored_phc): (Uuid, SecretString) =
        match retrieve_credentials(&username).await {
            Ok(Some(x)) => Ok(x),
            Ok(None) => {
                let untrusted_password = untrusted_password.clone();
                //execute some time wasting to prevent username enumeration
                let _task =
                    tokio::task::spawn_blocking(move || spin_hash(untrusted_password)).await;
                log::trace!("invalid login attempt on unregistered {username}");
                Err(LoginError::IncorrectCredentials.into())
            }
            Err(e) => Err(e),
        }?;
    let task =
        tokio::task::spawn_blocking(move || verify_hash(stored_phc, untrusted_password)).await;
    match task {
        Ok(Ok(())) => Ok(true_uuid),
        Ok(Err(ValidateHashError::DatabaseError(e))) => {
            //database is possibly corrupted
            log::error!("could not parse PHC for {username} with error {e}");
            Err(AppError::Argon2Failure)
        }
        Ok(Err(ValidateHashError::VerifyError(e))) => {
            log::trace!("invalid password attempt for {username} with error {e}");
            Err(LoginError::IncorrectCredentials.into())
        }
        Err(tokio_err) => {
            log::error!("failed to spawn blocking tokio task: {tokio_err}");
            Err(AppError::TokioFailure)
        }
    }
}

#[cfg(feature = "ssr")]
// hash that does not use salt and not for passwords
fn gen_easy_hash(input1: String, input2: String) -> String {
    // forever TODO: watch for updates regarding blake2
    // <https://github.com/RustCrypto/hashes#supported-algorithms>
    let mut hasher = Blake2s256::new();
    hasher.update(format!("{input1}!{input2}").as_bytes());
    let res = hasher.finalize();
    const CUSTOM_ENGINE: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::general_purpose::NO_PAD,
    );
    base64::Engine::encode(&CUSTOM_ENGINE, res)
}

#[cfg(feature = "ssr")]
// hash that does not use salt and not for passwords
fn verify_easy_hash(input1: String, input2: String, expected_result: String) -> bool {
    let mut hasher = Blake2s256::new();
    hasher.update(format!("{input1}!{input2}").as_bytes());
    let res = hasher.finalize();
    const CUSTOM_ENGINE: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::general_purpose::NO_PAD,
    );

    expected_result.eq(&base64::Engine::encode(&CUSTOM_ENGINE, res))
}

#[cfg(feature = "ssr")]
fn gen_hash(input: SecretString) -> Result<String, AppError> {
    // forever TODO: improve salt and complextity of hashing as computers get better
    // and as people buy more PS5s and shove them in underwater hashing factories
    // reference this article:
    // <https://argon2-cffi.readthedocs.io/en/stable/parameters.html>
    // archive:
    // <https://web.archive.org/web/20230111040733/https://argon2-cffi.readthedocs.io/en/stable/parameters.html>
    let salt = SaltString::generate(&mut rand::thread_rng());
    Ok(
        match Argon2::default().hash_password(input.expose_secret().as_bytes(), &salt) {
            Ok(hash) => Ok(hash.to_string()),
            Err(err) => {
                log::error!("failed to produce hash of password in gen_hash: {err}");
                Err(AppError::Argon2Failure)
            }
        }?,
    )
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
fn spin_hash(untrusted_password: SecretString) -> Result<(), ValidateHashError> {
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
        .map_err(ValidateHashError::VerifyError)
}
