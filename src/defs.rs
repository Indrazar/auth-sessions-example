use const_format::formatcp;

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
