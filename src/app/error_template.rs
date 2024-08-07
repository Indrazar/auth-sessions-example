use http::status::StatusCode;
use leptos::prelude::*;
#[cfg(feature = "ssr")]
use leptos_axum::ResponseOptions;
use leptos_meta::Stylesheet;
use thiserror::Error as ThisError;

#[derive(Debug, Clone, PartialEq, Eq, ThisError)]
pub enum AppError {
    #[error("Not Found")]
    NotFound,
    #[error("Internal Server Error")]
    InternalServerError,
}

impl AppError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

// A basic function to display errors served by the error boundaries.
// Feel free to do more complicated things here than just displaying the error.
#[component]
pub fn ErrorTemplate(#[prop(into)] errors: MaybeSignal<Errors>) -> impl IntoView {
    // Get Errors from Signal
    // Downcast lets us take a type that implements `std::error::Error`
    let errors = Memo::new(move |_| {
        let res = errors
            .get_untracked()
            .iter()
            .filter_map(|(_, v)| v.downcast_ref::<AppError>().cloned())
            .collect::<Vec<_>>();
        log!("res: {:?}", res);
        res
    });
    log!("Errors: {:#?}", &*errors.read_untracked());

    // Only the response code for the first error is actually sent from the server
    // this may be customized by the specific application
    #[cfg(feature = "ssr")]
    {
        let response = use_context::<ResponseOptions>();
        if let Some(response) = response {
            if errors.read_untracked().len() > 0 {
                response.set_status(errors.read_untracked()[0].status_code());
            } else {
                response.set_status(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    }

    view! {
        <head>
            <Stylesheet id="leptos" href="/pkg/auth_sessions_example.css"/>
        </head>
        <body>
        <h1>"Auth-Sessions-Example"</h1>
        <h1>{move || {
            if errors.read().len() > 1 {
                "Errors"
            } else {
                "Error"
            }}}
        </h1>
        {move || {
            errors.get()
                .into_iter()
                .map(|error| {
                    let error_string = error.to_string();
                    let error_code= error.status_code();
                    view! {
                        <h2>{error_code.to_string()}</h2>
                        <p>"Error: " {error_string}</p>
                    }
                })
                .collect_view()
        }}
        </body>
    }
}
