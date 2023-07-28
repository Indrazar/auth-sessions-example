#![cfg_attr(feature = "ssr", allow(unused_variables, dead_code))]

use default_struct_builder::DefaultBuilder;
use leptos::{leptos_dom::helpers::TimeoutHandle, *};
use std::{
    fmt::{self, Debug},
    rc::Rc,
};
use web_sys::{CloseEvent, Event, WebSocket as WebSysWebSocket};

cfg_if::cfg_if! { if #[cfg(feature = "ssr")] {
    use crate::{cookies::parse_session_header_cookie, database::validate_token_with_pool};
    use axum::{
        extract::{
            Extension,
            ws::{CloseFrame, Message, WebSocket as AxumWebSocket, WebSocketUpgrade as AxumWebSocketUpgrade},
            TypedHeader,
            connect_info::ConnectInfo,
        },
        response::IntoResponse,
        http::StatusCode,
    };
    use std::{borrow::Cow, ops::ControlFlow, net::SocketAddr, sync::Arc};
    //allows to split the websocket stream into separate TX and RX branches
    use futures::{sink::SinkExt, stream::StreamExt};
    //needed to extract the pool from the axum request
    use sqlx::SqlitePool;
    use uuid::Uuid;
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
}

impl fmt::Display for WebSysWebSocketReadyState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            WebSysWebSocketReadyState::Connecting => write!(f, "Connecting"),
            WebSysWebSocketReadyState::Open => write!(f, "Open"),
            WebSysWebSocketReadyState::Closing => write!(f, "Closing"),
            WebSysWebSocketReadyState::Closed => write!(f, "Closed"),
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
    reconnect_limit: Option<u64>,
    /// Retry interval(ms).
    reconnect_interval: Option<u64>,
    /// Manually starts connection
    manual: bool,
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
            reconnect_limit: Some(3),
            reconnect_interval: Some(3 * 1000),
            manual: false,
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
    url: String,
    options: WebSysWebSocketOptions,
) -> WebSysWebsocketReturn<
    impl Fn() + Clone + 'static,
    impl Fn(u16, String) + Clone + 'static,
    impl Fn(String) + Clone + 'static,
    impl Fn(Vec<u8>) + Clone,
> {
    let (state, set_state) = create_signal(WebSysWebSocketReadyState::Closed);
    let (message, set_message) = create_signal(None);
    let (message_bytes, set_message_bytes) = create_signal(None);
    let ws_ref: StoredValue<Option<WebSysWebSocket>> = store_value(None);

    let reconnect_limit = options.reconnect_limit.unwrap_or(3);

    let reconnect_timer_ref: StoredValue<Option<TimeoutHandle>> = store_value(None);
    let manual = options.manual;

    let reconnect_times_ref: StoredValue<u64> = store_value(0);
    let unmounted_ref = store_value(false);

    let connect_ref: StoredValue<Option<Rc<dyn Fn()>>> = store_value(None);

    cfg_if::cfg_if! { if #[cfg(not(feature = "ssr"))] {
        let on_open_ref = store_value(options.on_open);
        let on_message_ref = store_value(options.on_message);
        let on_message_bytes_ref = store_value(options.on_message_bytes);
        let on_error_ref = store_value(options.on_error);
        let on_close_ref = store_value(options.on_close);

        let reconnect_interval = options.reconnect_interval.unwrap_or(3 * 1000);
        let protocols = options.protocols;

        let reconnect_ref: StoredValue<Option<Rc<dyn Fn()>>> = store_value(None);
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
                        if unmounted_ref.get_value() {
                            return;
                        }

                        if let Some(reconnect) = &reconnect_ref.get_value() {
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
                if let Some(web_socket) = ws_ref.get_value() {
                    let _ = web_socket.send_with_str(&data);
                }
            }
        })
    };

    // Send bytes
    let send_bytes = move |data: Vec<u8>| {
        if state.get() == WebSysWebSocketReadyState::Open {
            if let Some(web_socket) = ws_ref.get_value() {
                let _ = web_socket.send_with_u8_array(&data);
            }
        }
    };

    // Open connection
    let open = move || {
        reconnect_times_ref.set_value(0);
        if let Some(connect) = connect_ref.get_value() {
            connect();
        }
    };

    // Close connection with code and reason
    let close = {
        reconnect_timer_ref.set_value(None);

        move |code, reason: String| {
            reconnect_times_ref.set_value(reconnect_limit);
            if let Some(web_socket) = ws_ref.get_value() {
                let _ = web_socket.close_with_code_and_reason(code, reason.as_str());
            }
        }
    };

    // Open connection (not called if option `manual` is true)
    create_effect(move |_| {
        if !manual {
            open();
        }
    });

    // clean up (unmount)
    on_cleanup(move || {
        unmounted_ref.set_value(true);
        close(4001, "user navigated off websocket page".to_string());
        log!("leaving websocket pages")
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
    user_agent: Option<TypedHeader<axum::headers::UserAgent>>,
    origin: Option<TypedHeader<axum::headers::Origin>>,
    header_cookies: Option<TypedHeader<axum::headers::Cookie>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(options): Extension<Arc<LeptosOptions>>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {
    let user_agent = if let Some(TypedHeader(user_agent)) = user_agent {
        user_agent.to_string()
    } else {
        String::from("Unknown browser")
    };
    let origin = if let Some(TypedHeader(origin)) = origin {
        origin.to_string()
    } else {
        String::from("Unknown origin")
    };
    let site_url = format!("https://{}", (*options).site_addr.to_string());
    // validate origin header
    if origin != site_url {
        log::trace!(
            "`{user_agent}` from {addr} with origin {origin} websocket rejected due to \
             invalid origin."
        );
        return (
            StatusCode::FORBIDDEN,
            format!("this websocket can only be accessed via {site_url}"),
        )
            .into_response();
    }
    let cookies = match header_cookies {
        Some(TypedHeader(cookies)) => cookies,
        None => {
            log::trace!(
                "`{user_agent}` from {addr} wtih no cookies websocket rejected due to no \
                 cookies."
            );
            return (StatusCode::UNAUTHORIZED, "please sign in first").into_response();
        }
    };
    // validate Uuid and pass into handler
    let unverified_session_id = parse_session_header_cookie(&cookies);
    let user_uuid = match validate_token_with_pool(unverified_session_id, pool).await {
        Some(id) => id,
        None => {
            log::trace!(
                "`{user_agent}` from {addr} wtih cookies {:#?} websocket rejected due to \
                 invalid session.",
                cookies
            );
            return (StatusCode::UNAUTHORIZED, "please sign in first").into_response();
        }
    };
    log::trace!("`{user_agent}` from {addr} websocket request accepted for uuid {user_uuid}.");
    // finalize the upgrade process by returning upgrade callback.
    // we can customize the callback by sending additional info such as address.
    ws.on_upgrade(move |socket| handle_socket(socket, addr, user_uuid))
}

#[cfg(feature = "ssr")]
/// Actual websocket statemachine (one will be spawned per connection)
async fn handle_socket(mut socket: AxumWebSocket, who: SocketAddr, user: Uuid) {
    //send a ping (unsupported by some browsers) just to kick things off and get a response
    if socket.send(Message::Ping(vec![1, 2, 3])).await.is_ok() {
        log::trace!("Pinged {}...", who);
    } else {
        log::trace!("Could not send ping {}!", who);
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
            if process_message(msg, who).is_break() {
                return;
            }
        } else {
            log::trace!("client {who} abruptly disconnected");
            return;
        }
    }

    // Since each client gets individual statemachine, we can pause handling
    // when necessary to wait for some external event (in this case illustrated by sleeping).
    // Waiting for this client to finish getting its greetings does not prevent other clients from
    // connecting to server and receiving their greetings.
    for i in 1..5 {
        if socket
            .send(Message::Text(format!("Hi {i} times!")))
            .await
            .is_err()
        {
            log::trace!("client {who} abruptly disconnected");
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

        log::trace!("Sending close to {who}...");
        if let Err(e) = sender
            .send(Message::Close(Some(CloseFrame {
                code: axum::extract::ws::close_code::NORMAL,
                reason: Cow::from("Goodbye"),
            })))
            .await
        {
            log::trace!("Could not send Close due to {}, probably it is ok?", e);
        }
        n_msg
    });

    // This second task will receive messages from client and print them on server console
    let mut recv_task = tokio::spawn(async move {
        let mut cnt = 0;
        while let Some(Ok(msg)) = receiver.next().await {
            cnt += 1;
            // print message and break if instructed to do so
            if process_message(msg, who).is_break() {
                break;
            }
        }
        cnt
    });

    // If any one of the tasks exit, abort the other.
    tokio::select! {
        rv_a = (&mut send_task) => {
            match rv_a {
                Ok(a) => log::trace!("{} messages sent to {}", a, who),
                Err(a) => log::trace!("Error sending messages {:?}", a)
            }
            //log::trace!("send_task caused abort");
            recv_task.abort();
        },
        rv_b = (&mut recv_task) => {
            match rv_b {
                Ok(b) => log::trace!("Received {} messages", b),
                Err(b) => log::trace!("Error receiving messages {:?}", b)
            }
            //log::trace!("recv_task caused abort");
            send_task.abort();
        }
    }

    // returning from the handler closes the websocket connection
    log::trace!("Websocket context {} destroyed", who);
}

#[cfg(feature = "ssr")]
/// helper to print contents of messages to stdout. Has special treatment for Close.
fn process_message(msg: Message, who: SocketAddr) -> ControlFlow<(), ()> {
    match msg {
        Message::Text(t) => {
            log::trace!(">>> {} sent str: {:?}", who, t);
        }
        Message::Binary(d) => {
            log::trace!(">>> {} sent {} bytes: {:?}", who, d.len(), d);
        }
        Message::Close(c) => {
            if let Some(cf) = c {
                log::trace!(
                    ">>> {} sent close with code {} and reason `{}`",
                    who,
                    cf.code,
                    cf.reason
                );
            } else {
                log::trace!(">>> {} sent close message without CloseFrame", who);
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
