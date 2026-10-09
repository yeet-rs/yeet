use std::fmt::Display;

use axum::http::StatusCode;

impl<T, E: Display> WithStatusCode<T> for Result<T, E> {
    fn with_code(self, status_code: StatusCode) -> Result<T, (StatusCode, String)> {
        self.map_err(|err| (status_code, err.to_string()))
    }
}

pub trait WithStatusCode<T> {
    fn with_code(self, status_code: StatusCode) -> Result<T, (StatusCode, String)>;
}

impl<T, E: Display> InternalError<T> for Result<T, E> {
    fn internal_server(self) -> Result<T, (StatusCode, String)> {
        self.with_code(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

pub trait InternalError<T> {
    fn internal_server(self) -> Result<T, (StatusCode, String)>;
}

impl<T, E: Display> BadRequest<T> for Result<T, E> {
    fn bad_request(self) -> Result<T, (StatusCode, String)> {
        self.with_code(StatusCode::BAD_REQUEST)
    }
}

pub trait BadRequest<T> {
    fn bad_request(self) -> Result<T, (StatusCode, String)>;
}
