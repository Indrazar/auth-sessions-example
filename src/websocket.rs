#![cfg_attr(feature = "ssr", allow(unused_variables, dead_code))]

use default_struct_builder::DefaultBuilder;
use leptos::{leptos_dom::helpers::TimeoutHandle, prelude::*};
use std::{
    fmt::{self, Debug},
    rc::Rc,
};
use web_sys::{CloseEvent, Event, WebSocket as WebSysWebSocket};

cfg_if::cfg_if! { if #[cfg(feature = "ssr")] {
    use crate::database::{validate_token_with_pool, user_data_with_pool};
    use crate::cookies::parse_session_header_cookie;
    use crate::defs::AppState;
    use axum::{
        extract::{
            State,
            ws::{Message, WebSocket as AxumWebSocket, WebSocketUpgrade as AxumWebSocketUpgrade},
            //Request,
            connect_info::ConnectInfo,
        },
        response::IntoResponse,
        http::{StatusCode, header::HeaderMap},
    };
    use std::{ops::ControlFlow, net::SocketAddr};
    //allows to split the websocket stream into separate TX and RX branches
    use futures::{sink::SinkExt, stream::StreamExt};
} else {
    use web_sys::{BinaryType, MessageEvent};
    use js_sys::Array;
    use std::time::Duration;
    use wasm_bindgen::{prelude::*, JsCast, JsValue};
}}

pub trait CloneFn<Arg>: FnOnce(Arg) {
    fn clone_box(&self) -> Box<dyn CloneFn<Arg>>;
}

impl<F, Arg> CloneFn<Arg> for F
where
    F: FnOnce(Arg) + Clone + 'static,
{
    fn clone_box(&self) -> Box<dyn CloneFn<Arg>> {
        Box::new(self.clone())
    }
}

impl<Arg> Clone for Box<dyn CloneFn<Arg>> {
    fn clone(&self) -> Self {
        (**self).clone_box()
    }
}

impl<Arg> Default for Box<dyn CloneFn<Arg>> {
    fn default() -> Self {
        Box::new(|_| {})
    }
}

impl<Arg> Debug for Box<dyn CloneFn<Arg>> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Box<dyn CloneFn<{}>>", std::any::type_name::<Arg>())
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum WebSysWebSocketReadyState {
    Connecting,
    Open,
    Closing,
    Closed,
    Uninitialized,
}

impl fmt::Display for WebSysWebSocketReadyState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            WebSysWebSocketReadyState::Connecting => write!(f, "Connecting"),
            WebSysWebSocketReadyState::Open => write!(f, "Open"),
            WebSysWebSocketReadyState::Closing => write!(f, "Closing"),
            WebSysWebSocketReadyState::Closed => write!(f, "Closed"),
            WebSysWebSocketReadyState::Uninitialized => write!(f, "Uninitialized"),
        }
    }
}

#[derive(DefaultBuilder)]
pub struct WebSysWebSocketOptions {
    /// `WebSysWebSocket` connect callback.
    on_open: Box<dyn CloneFn<Event>>,
    /// `WebSysWebSocket` message callback for text.
    on_message: Box<dyn CloneFn<String>>,
    /// `WebSysWebSocket` message callback for binary.
    on_message_bytes: Box<dyn CloneFn<Vec<u8>>>,
    /// `WebSysWebSocket` error callback.
    on_error: Box<dyn CloneFn<Event>>,
    /// `WebSysWebSocket` close callback.
    on_close: Box<dyn CloneFn<CloseEvent>>,
    /// Retry times.
    reconnect_limit: u64,
    /// Retry interval(ms).
    reconnect_interval: u64,
    /// If `true` the `WebSocket` connection will immediately be opened when calling this function.
    /// If `false` you have to manually call the `open` function.
    /// Defaults to `true`.
    immediate: bool,
    /// Sub protocols
    protocols: Option<Vec<String>>,
}

impl Default for WebSysWebSocketOptions {
    fn default() -> Self {
        Self {
            on_open: Box::new(|_| {}),
            on_message: Box::new(|_| {}),
            on_message_bytes: Box::new(|_| {}),
            on_error: Box::new(|_| {}),
            on_close: Box::new(|_| {}),
            reconnect_limit: 3,
            reconnect_interval: 3000,
            immediate: false,
            protocols: Default::default(),
        }
    }
}

#[derive(Clone)]
pub struct WebSysWebsocketReturn<OpenFn, CloseFn, SendFn, SendBytesFn>
where
    OpenFn: Fn() + Clone + 'static,
    CloseFn: Fn(u16, String) + Clone + 'static,
    SendFn: Fn(String) + Clone + 'static,
    SendBytesFn: Fn(Vec<u8>) + Clone + 'static,
{
    /// The current state of the `WebSysWebSocket` connection.
    pub ready_state: ReadSignal<WebSysWebSocketReadyState>,
    /// Latest text message received from `WebSysWebSocket`.
    pub message: ReadSignal<Option<String>>,
    /// Latest binary message received from `WebSysWebSocket`.
    pub message_bytes: ReadSignal<Option<Vec<u8>>>,
    /// The `WebSysWebSocket` instance.
    pub ws: Option<WebSysWebSocket>,
    /// Opens the `WebSysWebSocket` connection
    pub open: OpenFn,
    /// Closes the `WebSysWebSocket` connection
    pub close: CloseFn,
    /// Sends `text` (string) based data
    pub send: SendFn,
    /// Sends binary data
    pub send_bytes: SendBytesFn,
}

pub fn web_sys_websocket(
    url: &str,
    options: WebSysWebSocketOptions,
) -> WebSysWebsocketReturn<
    impl Fn() + Clone + 'static,
    impl Fn(u16, String) + Clone + 'static,
    impl Fn(String) + Clone + 'static,
    impl Fn(Vec<u8>) + Clone,
> {
    let url = url.to_string();

    let (state, set_state) = signal(WebSysWebSocketReadyState::Uninitialized);
    let (message, set_message) = signal(None);
    let (message_bytes, set_message_bytes) = signal(None);
    let ws_ref: StoredValue<Option<WebSysWebSocket>, LocalStorage> =
        StoredValue::new_local(None);

    let reconnect_limit = options.reconnect_limit;

    let reconnect_timer_ref: StoredValue<Option<TimeoutHandle>, LocalStorage> =
        StoredValue::new_local(None);
    let immediate = options.immediate;

    let reconnect_times_ref: StoredValue<u64, LocalStorage> = StoredValue::new_local(0);
    let unmounted_ref = StoredValue::new_local(false);

    let connect_ref: StoredValue<Option<Rc<dyn Fn()>>, LocalStorage> =
        StoredValue::new_local(None);

    cfg_if::cfg_if! { if #[cfg(not(feature = "ssr"))] {
        let on_open_ref = StoredValue::new_local(options.on_open);
        let on_message_ref = StoredValue::new_local(options.on_message);
        let on_message_bytes_ref = StoredValue::new_local(options.on_message_bytes);
        let on_error_ref = StoredValue::new_local(options.on_error);
        let on_close_ref = StoredValue::new_local(options.on_close);

        let reconnect_interval = options.reconnect_interval;
        let protocols = options.protocols;

        let reconnect_ref: StoredValue<Option<Rc<dyn Fn()>>, LocalStorage> = StoredValue::new_local(None);
        reconnect_ref.set_value({
            let ws = ws_ref.get_value();
            Some(Rc::new(move || {
                if reconnect_times_ref.get_value() < reconnect_limit
                    && ws
                        .clone()
                        .map_or(false, |ws: WebSysWebSocket| ws.ready_state() != WebSysWebSocket::OPEN)
                {
                    reconnect_timer_ref.set_value(
                        set_timeout_with_handle(
                            move || {
                                if let Some(connect) = connect_ref.get_value() {
                                    connect();
                                    reconnect_times_ref.update_value(|current| *current += 1);
                                }
                            },
                            Duration::from_millis(reconnect_interval),
                        )
                        .ok(),
                    );
                }
            }))
        });

        connect_ref.set_value({
            let ws = ws_ref.get_value();
            let url = url;

            Some(Rc::new(move || {
                reconnect_timer_ref.set_value(None);
                {
                    if let Some(web_socket) = &ws {
                        let _ = web_socket.close();
                    }
                }

                let web_socket = {
                    protocols.as_ref().map_or_else(
                        || WebSysWebSocket::new(&url).unwrap_throw(),
                        |protocols| {
                            let array = protocols
                                .iter()
                                .map(|p| JsValue::from(p.clone()))
                                .collect::<Array>();
                            WebSysWebSocket::new_with_str_sequence(&url, &JsValue::from(&array))
                                .unwrap_throw()
                        },
                    )
                };
                web_socket.set_binary_type(BinaryType::Arraybuffer);
                set_state.set(WebSysWebSocketReadyState::Connecting);

                // onopen handler
                {
                    let onopen_closure = Closure::wrap(Box::new(move |e: Event| {
                        if unmounted_ref.get_value() {
                            return;
                        }

                        let callback = on_open_ref.get_value();
                        callback(e);

                        set_state.set(WebSysWebSocketReadyState::Open);
                    }) as Box<dyn FnMut(Event)>);
                    web_socket.set_onopen(Some(onopen_closure.as_ref().unchecked_ref()));
                    // Forget the closure to keep it alive
                    onopen_closure.forget();
                }

                // onmessage handler
                {
                    let onmessage_closure = Closure::wrap(Box::new(move |e: MessageEvent| {
                        if unmounted_ref.get_value() {
                            return;
                        }

                        e.data().dyn_into::<js_sys::ArrayBuffer>().map_or_else(
                            |_| {
                                e.data().dyn_into::<js_sys::JsString>().map_or_else(
                                    |_| {
                                        unreachable!("message event, received Unknown: {:?}", e.data());
                                    },
                                    |txt| {
                                        let txt = String::from(&txt);
                                        let callback = on_message_ref.get_value();
                                        callback(txt.clone());

                                        set_message.set(Some(txt));
                                    },
                                );
                            },
                            |array_buffer| {
                                let array = js_sys::Uint8Array::new(&array_buffer);
                                let array = array.to_vec();
                                let callback = on_message_bytes_ref.get_value();
                                callback(array.clone());

                                set_message_bytes.set(Some(array));
                            },
                        );
                    })
                        as Box<dyn FnMut(MessageEvent)>);
                    web_socket.set_onmessage(Some(onmessage_closure.as_ref().unchecked_ref()));
                    onmessage_closure.forget();
                }

                // onerror handler
                {
                    let onerror_closure = Closure::wrap(Box::new(move |e: Event| {
                        if unmounted_ref.get_value() {
                            return;
                        }

                        if let Some(reconnect) = &reconnect_ref.get_value() {
                            reconnect();
                        }

                        let callback = on_error_ref.get_value();
                        callback(e);

                        set_state.set(WebSysWebSocketReadyState::Closed);
                    }) as Box<dyn FnMut(Event)>);
                    web_socket.set_onerror(Some(onerror_closure.as_ref().unchecked_ref()));
                    onerror_closure.forget();
                }

                // onclose handler
                {
                    let onclose_closure = Closure::wrap(Box::new(move |e: CloseEvent| {
                        // there is a possiblity that we navigated off the page and so the on_close was called
                        // in this case we should use try_get_value because we might not have a valid ref anymore
                        // in the above handlers we SHOULD have a valid ref and it SHOULD panic
                        // but here we could be in this post-navigation state.
                        // For the post-navigation state:
                        //     try_get_value shall eval to true in the if block if there is no valid ref
                        if unmounted_ref.try_get_value().unwrap_or(true) {
                            return;
                        }

                        if let Some(Some(reconnect)) = &reconnect_ref.try_get_value() {
                            reconnect();
                        }

                        let callback = on_close_ref.get_value();
                        callback(e);

                        set_state.set(WebSysWebSocketReadyState::Closed);
                    })
                        as Box<dyn FnMut(CloseEvent)>);
                    web_socket.set_onclose(Some(onclose_closure.as_ref().unchecked_ref()));
                    onclose_closure.forget();
                }

                ws_ref.set_value(Some(web_socket));
            }))
        });
    }}

    // Send text (String)
    let send = {
        Box::new(move |data: String| {
            if state.get() == WebSysWebSocketReadyState::Open {
                if let Some(Some(web_socket)) = ws_ref.try_get_value() {
                    let _ = web_socket.send_with_str(&data);
                }
            }
        })
    };

    // Send bytes
    let send_bytes = move |data: Vec<u8>| {
        if state.get() == WebSysWebSocketReadyState::Open {
            if let Some(Some(web_socket)) = ws_ref.try_get_value() {
                let _ = web_socket.send_with_u8_array(&data);
            }
        }
    };

    // Open connection
    let open = move || {
        reconnect_times_ref.set_value(0);
        if let Some(Some(connect)) = connect_ref.try_get_value() {
            connect();
        }
    };

    // Close connection with code and reason
    let close = {
        reconnect_timer_ref.set_value(None);

        move |code, reason: String| {
            reconnect_times_ref.set_value(reconnect_limit);
            if let Some(Some(web_socket)) = ws_ref.try_get_value() {
                let _ = web_socket.close_with_code_and_reason(code, reason.as_str());
            }
        }
    };

    Effect::new(move |_| {
        // immediately set websocket as initilized since we are now WASM loaded
        set_state.set(WebSysWebSocketReadyState::Closed);

        // Open connection (not called if option `immediate` is false)
        if immediate {
            open();
        }
    });

    // clean up (unmount)
    on_cleanup(move || {
        unmounted_ref.set_value(true);
        close(4001, "user navigated off websocket page".to_string());
        //log!("leaving websocket pages")
    });

    WebSysWebsocketReturn {
        ready_state: state,
        message,
        message_bytes,
        ws: ws_ref.get_value(),
        open,
        close,
        send,
        send_bytes,
    }
}

/// The handler for the HTTP request (this gets called when the HTTP GET lands at the start
/// of websocket negotiation). After this completes, the actual switching from HTTP to
/// websocket protocol will occur.
/// This is the last point where we can extract TCP/IP metadata such as IP address of the client
/// as well as things from HTTP headers such as user-agent of the browser etc.
#[cfg(feature = "ssr")]
pub async fn axum_ws_handler(
    ws: AxumWebSocketUpgrade,
    headers: HeaderMap,
    State(app_state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    //user_agent: Option<TypedHeader<http::request::UserAgent>>,
    //origin: Option<TypedHeader<http::request::Origin>>,
    //header_cookies: Option<TypedHeader<http::headers::Cookie>>,
    let user_agent = match headers.get(http::header::USER_AGENT) {
        Some(thing) => match thing.to_str() {
            Ok(agent) => agent,
            Err(_) => "INVALID USER_AGENT ASCII",
        },
        None => "No USER_AGENT",
    };
    let origin = match headers.get(http::header::ORIGIN) {
        Some(thing) => match thing.to_str() {
            Ok(origin) => origin,
            Err(e) => "INVALID ORIGIN ASCII",
        },
        None => "No ORIGIN",
    };
    let site_url = format!("https://{}", app_state.leptos_options.site_addr.to_string());
    // validate origin header
    if origin != site_url {
        log::debug!(
            "`{user_agent}` from {addr} with origin {origin} websocket rejected due to \
             invalid origin."
        );
        return (
            StatusCode::FORBIDDEN,
            format!("this websocket can only be accessed via {site_url}"),
        )
            .into_response();
    }
    let cookies_raw = match headers.get(http::header::COOKIE) {
        Some(thing) => match thing.to_str() {
            Ok(cookie_raw_string) => cookie_raw_string,
            Err(e) => {
                log::debug!(
                    "`{user_agent}` from {addr} wtih invalid cookie_raw_string rejected."
                );
                return (StatusCode::UNAUTHORIZED, "please sign in first").into_response();
            }
        },
        None => {
            log::debug!(
                "`{user_agent}` from {addr} wtih no cookies websocket rejected due to no \
                 cookies."
            );
            return (StatusCode::UNAUTHORIZED, "please sign in first").into_response();
        }
    };
    // validate Uuid and pass into handler
    let unverified_session_id = parse_session_header_cookie(cookies_raw);
    let user_uuid =
        match validate_token_with_pool(unverified_session_id, app_state.pool.clone()).await {
            Ok(Some(id)) => id,
            Ok(None) => {
                log::debug!(
                    "`{user_agent}` from {addr} wtih cookies {:#?} websocket rejected due to \
                 invalid session.",
                    cookies_raw
                );
                return (StatusCode::UNAUTHORIZED, "please sign in first").into_response();
            }
            Err(e) => match e {
                crate::defs::DatabaseError::CouldNotFindPool => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, "try again later")
                        .into_response()
                }
                crate::defs::DatabaseError::QueryFailed => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, "try again later")
                        .into_response()
                }
                crate::defs::DatabaseError::NoEntries => {
                    return (StatusCode::UNAUTHORIZED, "please sign in first").into_response()
                }
                crate::defs::DatabaseError::IncorrectRowsAffected => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, "try again later")
                        .into_response()
                }
            },
        };
    log::trace!("`{user_agent}` from {addr} websocket request is valid for uuid {user_uuid}.");
    let display_name = match user_data_with_pool(user_uuid, app_state.pool).await {
        Ok(data) => data.display_name,
        Err(e) => match e {
            crate::defs::DatabaseError::CouldNotFindPool => {
                return (StatusCode::INTERNAL_SERVER_ERROR, "try again later").into_response()
            }
            crate::defs::DatabaseError::QueryFailed => {
                return (StatusCode::INTERNAL_SERVER_ERROR, "try again later").into_response()
            }
            crate::defs::DatabaseError::NoEntries => {
                return (StatusCode::INTERNAL_SERVER_ERROR, "try again later").into_response()
            }
            crate::defs::DatabaseError::IncorrectRowsAffected => {
                return (StatusCode::INTERNAL_SERVER_ERROR, "try again later").into_response()
            }
        },
    };
    log::trace!(
        "{user_uuid} is correctly identified as {display_name} and websocket request accepted"
    );
    // finalize the upgrade process by returning upgrade callback.
    // we can customize the callback by sending additional info such as address.
    ws.on_upgrade(move |socket| handle_socket(socket, addr, display_name))
}

#[cfg(feature = "ssr")]
/// Actual websocket statemachine (one will be spawned per connection)
async fn handle_socket(mut socket: AxumWebSocket, who: SocketAddr, display_name: String) {
    //send a ping (unsupported by some browsers) just to kick things off and get a response
    if socket.send(Message::Ping(vec![1, 2, 3])).await.is_ok() {
        log::trace!("Pinged {display_name}->{who}...");
    } else {
        log::trace!("Could not send ping {display_name}->{who}!");
        // no Error here since the only thing we can do is to close the connection.
        // If we can not send messages, there is no way to salvage the statemachine anyway.
        return;
    }

    // receive single message from a client (we can either receive or send with socket).
    // this will likely be the Pong for our Ping or a hello message from client.
    // waiting for message from a client will block this task, but will not block other client's
    // connections.
    if let Some(msg) = socket.recv().await {
        if let Ok(msg) = msg {
            if process_message(msg, who, &display_name).is_break() {
                return;
            }
        } else {
            log::trace!("client {display_name}->{who} abruptly disconnected");
            return;
        }
    }

    // Since each client gets individual statemachine, we can pause handling
    // when necessary to wait for some external event (in this case illustrated by sleeping).
    // Waiting for this client to finish getting its greetings does not prevent other clients from
    // connecting to server and receiving their greetings.
    for i in 1..5 {
        if socket
            .send(Message::Text(format!("Hi {display_name} {i} times!")))
            .await
            .is_err()
        {
            log::trace!("client {display_name}->{who} abruptly disconnected");
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    // By splitting socket we can send and receive at the same time. In this example we will send
    // unsolicited messages to client based on some sort of server's internal event (i.e .timer).
    let (mut sender, mut receiver) = socket.split();

    // Spawn a task that will push several messages to the client (does not matter what client does)
    let mut send_task = tokio::spawn(async move {
        let n_msg = 20;
        for i in 0..n_msg {
            // In case of any websocket error, we exit.
            if sender
                .send(Message::Text(format!("Server message {i} ...")))
                .await
                .is_err()
            {
                return i;
            }

            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        }

        /*log::trace!("Sending close to {who}...");
        if let Err(e) = sender
            .send(Message::Close(Some(CloseFrame {
                code: axum::extract::ws::close_code::NORMAL,
                reason: Cow::from("Goodbye"),
            })))
            .await
        {
            log::trace!("Could not send Close due to {}, probably it is ok?", e);
        }*/
        n_msg
    });

    // This second task will receive messages from client and print them on server console
    let display_name_cloned = display_name.clone();
    let mut recv_task = tokio::spawn(async move {
        let mut cnt = 0;
        while let Some(Ok(msg)) = receiver.next().await {
            cnt += 1;
            // print message and break if instructed to do so
            if process_message(msg, who, &display_name_cloned).is_break() {
                break;
            }
        }
        cnt
    });

    // If any one of the tasks exit, abort the other.
    tokio::select! {
        rv_a = (&mut send_task) => {
            match rv_a {
                Ok(a) => log::trace!("{a} messages sent to {display_name}->{who}"),
                Err(a) => log::error!("Error sending messages {:?}", a)
            }
            //log::trace!("send_task caused abort");
            recv_task.abort();
        },
        rv_b = (&mut recv_task) => {
            match rv_b {
                Ok(b) => log::trace!("Received {b} messages"),
                Err(b) => log::error!("Error receiving messages {:?}", b)
            }
            //log::trace!("recv_task caused abort");
            send_task.abort();
        }
    }

    // returning from the handler closes the websocket connection
    log::trace!("Websocket context {display_name}->{who} destroyed");
}

#[cfg(feature = "ssr")]
/// helper to print contents of messages to stdout. Has special treatment for Close.
fn process_message(
    msg: Message,
    who: SocketAddr,
    display_name: &String,
) -> ControlFlow<(), ()> {
    match msg {
        Message::Text(t) => {
            log::trace!(">>> {display_name}->{who} sent str: {:?}", t);
        }
        Message::Binary(d) => {
            log::trace!(">>> {display_name}->{who} sent {} bytes: {:?}", d.len(), d);
        }
        Message::Close(c) => {
            if let Some(cf) = c {
                log::trace!(
                    ">>> {display_name}->{who} sent close with code {} and reason `{}`",
                    cf.code,
                    cf.reason
                );
            } else {
                log::trace!(">>> {display_name}->{who} sent close message without CloseFrame");
            }
            return ControlFlow::Break(());
        }

        Message::Pong(v) => {
            log::trace!(">>> {} sent pong with {:?}", who, v);
        }
        // You should never need to manually handle Message::Ping, as axum's websocket library
        // will do so for you automagically by replying with Pong and copying the v according to
        // spec. But if you need the contents of the pings you can see them here.
        Message::Ping(v) => {
            log::trace!(">>> {} sent ping with {:?}", who, v);
        }
    }
    ControlFlow::Continue(())
}
