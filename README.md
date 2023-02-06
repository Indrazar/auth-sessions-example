# Does This Work?
No. It's mostly a learning experience and I have no idea what I am doing. This section will disappear once it is a more serious template.

# Leptos Auth-Example

This project is made with the [Leptos](https://github.com/leptos-rs/leptos) web framework and the [cargo-leptos](https://github.com/akesson/cargo-leptos) tool using [Axum](https://github.com/tokio-rs/axum).

## Installing cargo-leptos

```bash
cargo install cargo-leptos
```

## Installing Additional Tools

By default, `cargo-leptos` uses `nightly` Rust, `cargo-generate`, and `sass`. If you run into any trouble, you may need to install one or more of these tools.


1. `rustup toolchain install nightly` - make sure you have Rust nightly
2. `rustup default nightly` - setup nightly as default for ease-of-use, remember to switch back to `rustup default stable` when you're done
3. `rustup target add wasm32-unknown-unknown` - add the ability to compile Rust to WebAssembly
4. `cargo install cargo-generate` - install `cargo-generate`
5. `npm install -g sass` - install `dart-sass`

## Installing OpenSSL on Windows

[Guide from here](https://github.com/sfackler/rust-openssl/tree/5948898e54882c0bedd12d87569eb4dbee5bbca7#windows-msvc) (which has since been removed), but has been recently checked as working as recently as 12/15/2022. Instead of 1.x.x this was tested with the most recent 3.x.x and it did work at the time.

### Installing OpenSSL using precompiled binaries

The easiest way to do get OpenSSL working is to download [precompiled binaries](https://slproweb.com/products/Win32OpenSSL.html) and install them on your system. Compiling it yourself is left as an exercise for the reader. Currently it's recommended to install the newest (non-light) installation. Please be aware that this basically means you are trusting SLPROWEB with _all_ your cryptography built using that binary. [Chocolatey.org](https://community.chocolatey.org/packages/OpenSSL.Light) trusts it so maybe it's fine (check the "Software Site" link).

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


## Running in dev mode

```bash
cargo leptos watch
```

## Running in prod mode

First update the `Cargo.toml` setting: `env = "PROD"` for Production mode

```bash
cargo leptos serve --release
```

## Executing on a Remote Machine Without the Toolchain
After running a `cargo leptos build --release` the minimum files needed are:

1. The server binary located in `target/server/release`
2. The `site` directory and all files within located in `target/site`

Copy these files to your remote server. The directory structure should be:
```text
auth-example
site/
```
Set the following enviornment variables (updating as needed):
```text
LEPTOS_OUTPUT_NAME="auth-example"
LEPTOS_SITE_ROOT="site"
LEPTOS_SITE_PKG_DIR="pkg"
LEPTOS_SITE_ADDR="127.0.0.1:3000"
LEPTOS_RELOAD_PORT="3001"
```
Finally, run the server binary.