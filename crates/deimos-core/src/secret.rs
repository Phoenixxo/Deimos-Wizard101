use std::fmt;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::rpc::AuthToken;

pub const MAX_USERNAME_BYTES: usize = 256;
pub const MAX_PASSWORD_BYTES: usize = 512;
const NONCE_BYTES: usize = 12;
const KEY_BYTES: usize = 32;
const LENGTH_PREFIX_BYTES: usize = 2;

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedCredential {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for SealedCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedCredential")
            .field("nonce", &"[REDACTED]")
            .field("ciphertext", &"[REDACTED]")
            .finish()
    }
}

pub struct CredentialSecret {
    username: Zeroizing<Vec<u8>>,
    password: Zeroizing<Vec<u8>>,
}

impl CredentialSecret {
    pub fn username(&self) -> &[u8] {
        &self.username
    }

    pub fn password(&self) -> &[u8] {
        &self.password
    }
}

impl fmt::Debug for CredentialSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialSecret([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretError {
    InvalidToken,
    InvalidCredential,
    EncryptionFailed,
    DecryptionFailed,
}

impl fmt::Display for SecretError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidToken => "the agent authentication key is invalid",
            Self::InvalidCredential => "the credential payload is invalid",
            Self::EncryptionFailed => "the credential payload could not be sealed",
            Self::DecryptionFailed => "the credential payload could not be opened",
        })
    }
}

impl std::error::Error for SecretError {}

pub fn seal_credential(
    token: &AuthToken,
    username: &[u8],
    password: &[u8],
    associated_data: &[u8],
) -> Result<SealedCredential, SecretError> {
    validate_fields(username, password)?;
    let mut plaintext = Zeroizing::new(Vec::with_capacity(
        LENGTH_PREFIX_BYTES * 2 + username.len() + password.len(),
    ));
    plaintext.extend_from_slice(&(username.len() as u16).to_le_bytes());
    plaintext.extend_from_slice(username);
    plaintext.extend_from_slice(&(password.len() as u16).to_le_bytes());
    plaintext.extend_from_slice(password);

    let key = token_key(token)?;
    let cipher = ChaCha20Poly1305::new((&*key).into());
    let mut nonce = vec![0u8; NONCE_BYTES];
    getrandom::getrandom(&mut nonce).map_err(|_| SecretError::EncryptionFailed)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| SecretError::EncryptionFailed)?;
    Ok(SealedCredential { nonce, ciphertext })
}

pub fn open_credential(
    token: &AuthToken,
    sealed: &SealedCredential,
    associated_data: &[u8],
) -> Result<CredentialSecret, SecretError> {
    if sealed.nonce.len() != NONCE_BYTES
        || sealed.ciphertext.len()
            > MAX_USERNAME_BYTES + MAX_PASSWORD_BYTES + LENGTH_PREFIX_BYTES * 2 + 16
    {
        return Err(SecretError::InvalidCredential);
    }
    let key = token_key(token)?;
    let cipher = ChaCha20Poly1305::new((&*key).into());
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&sealed.nonce),
                Payload {
                    msg: &sealed.ciphertext,
                    aad: associated_data,
                },
            )
            .map_err(|_| SecretError::DecryptionFailed)?,
    );
    parse_plaintext(&plaintext)
}

fn parse_plaintext(plaintext: &[u8]) -> Result<CredentialSecret, SecretError> {
    let mut cursor = 0usize;
    let username_len = read_length(plaintext, &mut cursor)?;
    let username_end = cursor
        .checked_add(username_len)
        .filter(|end| *end <= plaintext.len())
        .ok_or(SecretError::InvalidCredential)?;
    let username = Zeroizing::new(plaintext[cursor..username_end].to_vec());
    cursor = username_end;
    let password_len = read_length(plaintext, &mut cursor)?;
    let password_end = cursor
        .checked_add(password_len)
        .filter(|end| *end == plaintext.len())
        .ok_or(SecretError::InvalidCredential)?;
    let password = Zeroizing::new(plaintext[cursor..password_end].to_vec());
    validate_fields(&username, &password)?;
    Ok(CredentialSecret { username, password })
}

fn read_length(bytes: &[u8], cursor: &mut usize) -> Result<usize, SecretError> {
    let end = cursor
        .checked_add(LENGTH_PREFIX_BYTES)
        .filter(|end| *end <= bytes.len())
        .ok_or(SecretError::InvalidCredential)?;
    let value = u16::from_le_bytes(
        bytes[*cursor..end]
            .try_into()
            .map_err(|_| SecretError::InvalidCredential)?,
    );
    *cursor = end;
    Ok(usize::from(value))
}

fn validate_fields(username: &[u8], password: &[u8]) -> Result<(), SecretError> {
    if username.is_empty()
        || username.len() > MAX_USERNAME_BYTES
        || password.is_empty()
        || password.len() > MAX_PASSWORD_BYTES
        || username.contains(&0)
        || password.contains(&0)
    {
        return Err(SecretError::InvalidCredential);
    }
    Ok(())
}

fn token_key(token: &AuthToken) -> Result<Zeroizing<[u8; KEY_BYTES]>, SecretError> {
    let text = token.as_str().as_bytes();
    if text.len() != KEY_BYTES * 2 {
        return Err(SecretError::InvalidToken);
    }
    let mut key = Zeroizing::new([0u8; KEY_BYTES]);
    for (index, pair) in text.chunks_exact(2).enumerate() {
        key[index] = (hex(pair[0])? << 4) | hex(pair[1])?;
    }
    Ok(key)
}

fn hex(value: u8) -> Result<u8, SecretError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(SecretError::InvalidToken),
    }
}

impl Drop for SealedCredential {
    fn drop(&mut self) {
        self.nonce.zeroize();
        self.ciphertext.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::{open_credential, seal_credential, SealedCredential};
    use crate::rpc::AuthToken;

    #[test]
    fn credential_round_trip_is_bound_to_context_and_redacted() {
        let token = AuthToken::generate().expect("token");
        let sealed = seal_credential(&token, b"wizard@example.com", b"secret-value", b"client-1")
            .expect("seal");
        let opened = open_credential(&token, &sealed, b"client-1").expect("open");
        assert_eq!(opened.username(), b"wizard@example.com");
        assert_eq!(opened.password(), b"secret-value");
        assert!(!format!("{sealed:?}").contains("secret-value"));
        assert!(open_credential(&token, &sealed, b"client-2").is_err());
    }

    #[test]
    fn malformed_and_oversized_envelopes_are_rejected() {
        let token = AuthToken::generate().expect("token");
        let malformed = SealedCredential {
            nonce: vec![0; 11],
            ciphertext: vec![0; 16],
        };
        assert!(open_credential(&token, &malformed, b"client").is_err());
        assert!(seal_credential(&token, b"", b"password", b"client").is_err());
    }
}
