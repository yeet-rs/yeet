use ed25519_dalek::VerifyingKey;

use crate::request;

request! (
    delete_key(delete_key: VerifyingKey),
    delete("/key/delete") -> StatusCode,
    body: &delete_key
);
