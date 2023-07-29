use crate::{
    database::UserData,
    pages::get_user_data,
    websocket::{
        web_sys_websocket, WebSysWebSocketOptions, WebSysWebSocketReadyState,
        WebSysWebsocketReturn,
    },
};
use leptos::*;
use web_sys::{CloseEvent, Event}; //WebSocket as WebSysWebSocket};

#[component]
pub fn HomePage() -> impl IntoView {
    let user_data = create_resource(move || (), move |_| get_user_data());

    view! {
        <Transition
            fallback=move || view! {<p>"Loading..."</p>}
        >
        {move || {
            user_data.read().map(|data| match data {
                Err(e) => view! {
                    <p>"There was an error loading the page."</p>
                    <span>{format!("error: {}", e)}</span>
                }.into_view(),
                Ok(None) => view! {
                    ""
                }.into_view(),
                Ok(Some(user_data)) => view! {
                    <div class="main-text">
                        <HomepageLoggedIn user_data/>
                    </div>
                }.into_view(),
            })
        }}
        </Transition>
    }
}

#[component]
pub fn HomepageLoggedIn(user_data: UserData) -> impl IntoView {
    let (history, set_history) = create_signal(vec![]);

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
        dotenvy_macro::dotenv!("WEBSOCKET_URL"),
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

    create_effect(move |_| {
        if let Some(m) = message.get() {
            update_history(&set_history, format! {"[message]: {:?}", m});
        };
    });

    create_effect(move |_| {
        if let Some(m) = message_bytes.get() {
            update_history(&set_history, format! {"[message_bytes]: {:?}", m});
        };
    });

    let connected = move || ready_state.get() == WebSysWebSocketReadyState::Open;

    view! {
    <div class="main-text">
        <p>"Hello! This is your home page " {user_data.display_name.clone()} "."</p>
        <p>"More information could be put here if we wanted. So far all we have is: " {format!("{:?}", user_data.clone())}</p>
        <p>"Websocket status: " {status}</p>
        <p>"Websocket buttons:"</p>
        <button on:click=open_connection disabled=connected>"Connect"</button>
        <button on:click=send_message disabled=move || !connected()>"Send"</button>
        <button on:click=send_byte_message disabled=move || !connected()>"Send bytes"</button>
        <button on:click=close_connection disabled=move || !connected()>"Disconnect"</button>
        <button on:click=move |_| set_history.set(vec![]) disabled=move || history.get().len() <= 0>"Clear"</button>
        <p>"Websocket history:"</p>
        <For
            each=move || history.get().into_iter().enumerate()
            key=|(index, _)| *index
            view=move |(_, message)| {
                view! { <div>{message}</div> }
            }
        />
        //<TheButton/>
    </div>
    }
}
