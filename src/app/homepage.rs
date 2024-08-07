use crate::{
    database::APIUserData,
    defs::WEBSOCKET_URL,
    websocket::{
        web_sys_websocket, WebSysWebSocketOptions, WebSysWebSocketReadyState,
        WebSysWebsocketReturn,
    },
};
use leptos::{either::Either, prelude::*};
use web_sys::{CloseEvent, Event}; //WebSocket as WebSysWebSocket};

#[component]
pub fn HomePage(
    user_data: Resource<Result<Option<APIUserData>, ServerFnError>>,
) -> impl IntoView {
    view! {
        <Suspense fallback=|| view! {<p>"Loading..."</p>}>
            { move || {
                match user_data.get() {
                    Some(inner) => Either::Left(match inner {
                        Err(e) => Either::Left(
                            view! {
                                <p>"There was an error loading the page."</p>
                                <span>{format!("error: {}", e)}</span>
                            }
                        ),
                        Ok(user) => Either::Right({match user {
                            None => Either::Left(view! {""}),
                            Some(user_data) => Either::Right(
                                view! {
                                    <div class="main-text">
                                        <HomepageLoggedIn user_data/>
                                    </div>
                                }
                            )
                        }})
                    }),
                    None => Either::Right(view! {
                        <p>"Loading..."</p>
                    }),
                }
            }}
        </Suspense>
    }
}

#[component]
pub fn HomepageLoggedIn(user_data: APIUserData) -> impl IntoView {
    let (history, set_history) = signal(vec![]);

    fn update_history(&history: &WriteSignal<Vec<String>>, message: String) {
        let _ = &history.update(|history: &mut Vec<_>| history.push(message));
    }

    let on_open_callback = move |e: Event| {
        set_history.update(|history: &mut Vec<_>| {
            history.push(format! {"[on_open]: event {:?}", e.type_()})
        });
    };

    let on_close_callback = move |e: CloseEvent| {
        set_history.update(|history: &mut Vec<_>| {
            history.push(format! {"[on_close]: event {:?}", e.type_()})
        });
    };

    let on_error_callback = move |e: Event| {
        set_history.update(|history: &mut Vec<_>| {
            history.push(format! {"[on_error]: event {:?}", e.type_()})
        });
    };

    let on_message_callback = move |m: String| {
        set_history
            .update(|history: &mut Vec<_>| history.push(format! {"[on_message]: {:?}", m}));
    };

    let on_message_bytes_callback = move |m: Vec<u8>| {
        set_history.update(|history: &mut Vec<_>| {
            history.push(format! {"[on_message_bytes]: {:?}", m})
        });
    };

    let WebSysWebsocketReturn {
        ready_state,
        send,
        send_bytes,
        open,
        close,
        message,
        message_bytes,
        ..
        //ws not needed
    } = web_sys_websocket(
        WEBSOCKET_URL,
        WebSysWebSocketOptions::default()
            .immediate(false)
            .on_open(on_open_callback.clone())
            .on_close(on_close_callback.clone())
            .on_error(on_error_callback.clone())
            .on_message(on_message_callback.clone())
            .on_message_bytes(on_message_bytes_callback.clone()),
    );

    let open_connection = move |_| {
        open();
    };
    let close_connection = move |_| {
        close(4000, "user requested close".to_string());
    };

    let send_message = move |_| {
        let message = "Hello, websocket!".to_string();
        send(message.clone());
        update_history(&set_history, format! {"[send]: {:?}", message});
    };

    let send_byte_message = move |_| {
        let m = b"Hello, websocket!\r\n".to_vec();
        send_bytes(m.clone());
        update_history(&set_history, format! {"[send_bytes]: {:?}", m});
    };

    let status = move || ready_state.get().to_string();

    Effect::new(move |_| {
        if let Some(m) = message.get() {
            update_history(&set_history, format! {"[message]: {:?}", m});
        };
    });

    Effect::new(move |_| {
        if let Some(m) = message_bytes.get() {
            update_history(&set_history, format! {"[message_bytes]: {:?}", m});
        };
    });

    let connected = move || ready_state.get() == WebSysWebSocketReadyState::Open;
    let disable_all_buttons =
        move || ready_state.get() == WebSysWebSocketReadyState::Uninitialized;

    view! {
    <div class="main-text">
        <p>"Hello! This is your home page " {user_data.display_name.clone()} "."</p>
        <p>"More information could be put here if we wanted. So far all we have is: " {format!("{:?}", user_data.clone())}</p>
        <p>"Websocket status: " {status}</p>
        <p>"Websocket buttons:"</p>
        <button on:click=open_connection disabled=move || {connected() || disable_all_buttons()}>"Connect"</button>
        <button on:click=send_message disabled=move || {!connected() || disable_all_buttons()}>"Send"</button>
        <button on:click=send_byte_message disabled=move || {!connected() || disable_all_buttons()}>"Send bytes"</button>
        <button on:click=close_connection disabled=move || {!connected()|| disable_all_buttons()}>"Disconnect"</button>
        <button on:click=move |_| set_history.set(vec![]) disabled=move || history.get().len() <= 0>"Clear"</button>
        <p>"Websocket history:"</p>
        //alternate method:
        //{ move || {
        //    history.get().into_iter()
        //        .map(|n| view! { <div>{n}</div> })
        //        .collect::<Vec<_>>()
        //}}
        <For
            each=move || history.get().into_iter().enumerate()
            key=|(index, _)| *index
            children=move |(_, message)| {
                view! { <div>{message}</div> }
            }
        />
        //<TheButton/>
    </div>
    }
}
