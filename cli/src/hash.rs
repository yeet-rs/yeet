//! Password hashing for yeet host set-password.
//! The vm test driver includes this file too, so the test checks the real thing

use color_eyre::{Result, eyre::eyre};
use sha_crypt::{PasswordHasher as _, ShaCrypt};

/// Salts for sha512-crypt are max 16 chars. The salt gets base64 encoded so 12 bytes give
/// exactly 16. The crate default is 16 bytes (22 chars) and chpasswd, which accounts-daemon
/// uses under the hood, rejects that. Found that one out the hard way
const SALT_BYTES: usize = 12;

/// Hash a password as a crypt(3) sha512 string, so $6$rounds=5000$salt$hash
pub fn hash_password(password: &str) -> Result<String> {
    let salt = sha_crypt::password_hash::try_generate_salt()
        .map_err(|err| eyre!("Could not generate a salt: {err}"))?;
    let salt = salt
        .first_chunk::<SALT_BYTES>()
        .ok_or_else(|| eyre!("Generated salt is too short"))?;

    let hash = ShaCrypt::SHA512
        .hash_password_with_salt(password.as_bytes(), salt)
        .map_err(|err| eyre!("Could not hash the password: {err}"))?;
    Ok(hash.as_str().to_owned())
}

#[cfg(test)]
mod tests {
    use sha_crypt::{PasswordHashRef, PasswordVerifier as _};

    use super::*;

    #[test]
    fn shadow_accepts_format() {
        let hash = hash_password("hunter2").unwrap();
        // same rule as is_valid_hash in shadow: $6$[rounds=N$]<1-16 chars>$<86 chars>
        let parts: Vec<&str> = hash.split('$').collect();
        assert_eq!(parts.first(), Some(&""));
        assert_eq!(parts.get(1), Some(&"6"));
        assert_eq!(parts.get(2), Some(&"rounds=5000"));
        assert_eq!(parts.get(3).map(|salt| salt.len()), Some(16));
        assert_eq!(parts.get(4).map(|hash| hash.len()), Some(86));
    }

    #[test]
    fn verifies() {
        let hash = hash_password("hunter2").unwrap();
        let hash = PasswordHashRef::new(&hash).unwrap();
        ShaCrypt::default()
            .verify_password(b"hunter2", hash)
            .unwrap();
        assert!(ShaCrypt::default().verify_password(b"wrong", hash).is_err());
    }
}
