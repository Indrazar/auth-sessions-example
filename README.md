# Notes about Spam
Opening this to the greater internet is likey a VERY BAD idea unless you at a minimum implement recaptcha (just an example, not a recommendation) and/or other bot mitigations.
The bots will arrive and they will sell you uggs.

# Leptos Auth-Sessions-Example

This project is made with the [Leptos](https://github.com/leptos-rs/leptos) web framework and the [cargo-leptos](https://github.com/leptos-rs/cargo-leptos) tool using [Axum](https://github.com/tokio-rs/axum) but without using [axum-sessions](https://github.com/maxcountryman/axum-sessions).

### Sidenote:
This project is not using  `axum-sessions` due to the way its dependency `async-session` incorrectly implements clone in one of the core interfaces. This [issue is tracked here](https://github.com/http-rs/async-session/pull/57).

## Installing cargo-leptos

```bash
cargo install cargo-leptos
```

## Installing Additional Tools

In the past `Leptos` used `nightly` Rust as default, but now `stable` is the default.
This project follows `stable`.
`cargo-leptos` uses `cargo-generate` and `sass`. If you run into any trouble, you may need to install one or more of these tools.

1. `rustup target add wasm32-unknown-unknown` - add the ability to compile Rust to WebAssembly
2. `cargo install cargo-generate` - to install `cargo-generate`
3. `cargo install sqlx-cli` - to install `sqlx`
4. `npm install -g sass` - to install `dart-sass`

## Installing OpenSSL on Windows

[Guide from here](https://github.com/sfackler/rust-openssl/tree/5948898e54882c0bedd12d87569eb4dbee5bbca7#windows-msvc) (which has since been removed), but has been recently checked as working as recently as 2/12/2023. Instead of 1.x.x this was tested with the most recent 3.x.x and it did work at the time. The updated but far less detailed [guide is here](https://docs.rs/openssl/latest/openssl/#automatic). If you get OpenSSL installed some other way and have the environment variables the way rust openssl expects then jump to [Acquiring Root Certificates](#acquiring-root-certificates).

### Installing OpenSSL using precompiled binaries

The easiest way to do get OpenSSL working is to download [precompiled binaries](https://slproweb.com/products/Win32OpenSSL.html) and install them on your system. Compiling it yourself is left as an exercise for the reader. Currently it's recommended to install the newest (non-light) installation. Please be aware that this basically means you are trusting SLPROWEB with _all_ your cryptography built using that binary. [Chocolatey.org](https://community.chocolatey.org/packages/OpenSSL) [trusts it](https://github.com/chtof/chocolatey-packages/blob/master/automatic/openssl/tools/chocolateyinstall.ps1) so maybe it's fine (see the git repo ps1 file url).

Once a precompiled binary is installed you must update your user or system environment variable to the installed directory. As an example:

```
set OPENSSL_DIR=C:\OpenSSL-Win64
```

During the installation process if you select "Copy OpenSSL DLLs to: The OpenSSL binaries (/bin) directory", you will need to add them to the `PATH` environment variable as well:

```
set PATH=%PATH%;C:\OpenSSL-Win64\bin
```

Now you will need to install root certificates.

### Acquiring Root Certificates

Neither of the above OpenSSL distributions ship with any root certificates. So to make requests to servers on the internet, you have to install them manually. Download the cacert.pem file [from curl's documentation](https://curl.se/docs/caextract.html), copy it somewhere (`C:\OpenSSL-Win64\certs` as an example), and point the `SSL_CERT_FILE` environment variable there:

```
set SSL_CERT_FILE=C:\OpenSSL-Win64\certs\cacert[date].pem
```

After that, `cargo build` should stop falling over at OpenSSL.

## Generating a self signed cert

You will need a self signed cert for TLS for Dev purposes. The command when using openssl is listed below:

```bash
openssl req -newkey rsa:2048 -nodes -keyout self_signed_certs/key.pem -x509 -days 365 -out self_signed_certs/certificate.pem
```

## Environment Setup

Copy `.env.example` into `.env` and make sure the settings are correct.

## Running in dev mode

```bash
cargo leptos watch
```

## Running in prod mode

First update the `Cargo.toml` setting: `env = "PROD"` for Production mode
Then ensure the `.env` settings are correct for production.
You may want to tune the `[profile.server-release]` and `[profile.wasm-release]` in `Cargo.toml` to meet your needs.
Please note that `codegen-units = 1` may produce faster code but it takes much longer to compile. 16 is default for Rust's release builds.

```bash
cargo leptos serve --release
```

## Executing on a Remote Machine Without the Rust Toolchain
1. Update the `Cargo.toml` setting: `env = "PROD"` for Production mode
2. Run `cargo leptos build --release` on the build machine.
3. Prepare:
    1. Server binary located in `target/server/server-release`
    2. `site` directory and all files within located in `target/site`
    3. `.env` file with all the environment variables or the environment variables set.
        note: `LIVE_HTTP_REDIRECT` and `LEPTOS_SITE_ADDR` highly depend on where and how you are deploying the server.
4. Copy these files to your remote server. The directory structure should be:
```text
.env
auth-sessions-example
site/
```
5. The code supports individually `gzip`-ing all files within the `site` directory ahead of running the binary.
6. Copy `.env.example` into `.env` and make sure the settings are correct.
7. Finally, run the server binary.
