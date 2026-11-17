// src/session.rs
//
// A session records only that a user logged in recently.
// It never stores the master password or any key that decrypts the vault.
// Commands that touch secret content must still ask for the master password.
//
// Storage: the session lives in the OS credential store (keyring), signed with
// an HMAC key that is also kept in the keyring. A lock file serialises access
// between concurrent Pgen processes.

use fs2::FileExt;
use hmac::{Hmac, Mac};
use keyring::Entry;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::error::Error;
use std::fs::{self, File};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::Vault; // adjust to where Vault is defined

type BoxResult<T> = Result<T, Box<dyn Error>>;
type HmacSha256 = Hmac<Sha256>;

/// Inactivity timeout: the session expires this long after the last command
const IDLE_TIMEOUT_SECS: u64 = 30 * 60;

/// Hard cap: a session never lasts longer than this, however active the user is
const MAX_SESSION_AGE_SECS: u64 = 8 * 60 * 60;

const KEYRING_SERVICE: &str = "pgen" ;
const SESSION_KEY_USER: &str = "active-session";
const SIGNING_KEY_USER: &str = "session-signing-key";
const APP_DIR: &str = "pgen";
const LOCK_FILE: &str = "session.lock";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub vault_id: String,
    pub token: String,
    pub created_at: u64, // Unix seconds, when the session started
    pub expires_at: u64, // Unix seconds, when it expires if left idle
}

/// What is actually stored: the session plus its signature
#[derive(Serialize, Deserialize)]
struct StoredSession {
    session: Session,
    signature: String, // hex HMAC over the session fields
}

// ---------- helpers ----------

fn now_secs() -> BoxResult<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn new_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Lock file location: the user's config folder, e.g. %APPDATA%\pgen on Windows
fn config_dir() -> BoxResult<PathBuf> {
    let mut dir = dirs::config_dir().ok_or("no user config directory found")?;
    dir.push(APP_DIR);
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Holds an exclusive lock until the returned handle is dropped.
/// Serialises read-modify-write cycles across concurrent Pgen processes.
fn lock() -> BoxResult<File> {
    let file = File::create(config_dir()?.join(LOCK_FILE))?;
    file.lock_exclusive()?;
    Ok(file)
}

fn session_entry() -> BoxResult<Entry> {
    Ok(Entry::new(KEYRING_SERVICE, SESSION_KEY_USER)?)
}

/// The HMAC key. Created once, then reused. Lives in the keyring, not on disk.
fn signing_key() -> BoxResult<Vec<u8>> {
    let entry = Entry::new(KEYRING_SERVICE, SIGNING_KEY_USER)?;
    match entry.get_password() {
        Ok(hex_key) => Ok(hex::decode(hex_key)?),
        Err(keyring::Error::NoEntry) => {
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            entry.set_password(&hex::encode(key))?;
            Ok(key.to_vec())
        }
        Err(e) => Err(e.into()),
    }
}

/// The exact bytes that are signed. Any field change changes this string.
fn payload(s: &Session) -> String {
    format!("{}|{}|{}|{}", s.vault_id, s.token, s.created_at, s.expires_at)
}

fn sign(s: &Session) -> BoxResult<String> {
    let mut mac = HmacSha256::new_from_slice(&signing_key()?).map_err(|_| "invalid signing key")?;
    mac.update(payload(s).as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn verify(s: &Session, signature_hex: &str) -> BoxResult<bool> {
    let tag = hex::decode(signature_hex)?;
    let mut mac = HmacSha256::new_from_slice(&signing_key()?).map_err(|_| "invalid signing key")?;
    mac.update(payload(s).as_bytes());
    Ok(mac.verify_slice(&tag).is_ok())
}

// ---------- unlocked internals (caller must hold the lock) ----------

fn store_unlocked(session: &Session) -> BoxResult<()> {
    let stored = StoredSession {
        session: session.clone(),
        signature: sign(session)?,
    };
    session_entry()?.set_password(&serde_json::to_string(&stored)?)?;
    Ok(())
}

/// Reads and verifies the stored session. A missing or tampered record returns None.
fn load_unlocked() -> BoxResult<Option<Session>> {
    let json = match session_entry()?.get_password() {
        Ok(json) => json,
        Err(keyring::Error::NoEntry) => return Ok(None),
        Err(e) => return Err(e.into()),
    };

    let stored: StoredSession = match serde_json::from_str(&json) {
        Ok(s) => s,
        Err(_) => {
            clear_unlocked()?; // unreadable record: remove it
            return Ok(None);
        }
    };

    if verify(&stored.session, &stored.signature)? {
        Ok(Some(stored.session))
    } else {
        clear_unlocked()?; // edited or forged record: remove it
        Ok(None)
    }
}

fn clear_unlocked() -> BoxResult<()> {
    match session_entry()?.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn active_unlocked() -> BoxResult<Option<Session>> {
    let mut session = match load_unlocked()? {
        Some(s) => s,
        None => return Ok(None),
    };

    let now = now_secs()?;
    let hard_limit = session.created_at.saturating_add(MAX_SESSION_AGE_SECS);

    if now >= session.expires_at || now >= hard_limit {
        clear_unlocked()?;
        return Ok(None);
    }

    // Activity extends the idle timeout, but never past the hard cap
    session.expires_at = (now + IDLE_TIMEOUT_SECS).min(hard_limit);
    store_unlocked(&session)?;
    Ok(Some(session))
}




// ---------- public API ----------

/// Called once, at the end of a successful start-vault
pub fn create_session(vault: &Vault) -> BoxResult<Session> {
    let _guard = lock()?;
    let now = now_secs()?;
    let session = Session {
        vault_id: vault.vault_profile.vault_id.clone(),
        token: new_token(),
        created_at: now,
        expires_at: now + IDLE_TIMEOUT_SECS,
    };
    store_unlocked(&session)?;
    Ok(session)
}

/// Removes the session. Safe to call when there is none (log-out, expiry).
pub fn clear_session() -> BoxResult<()> {
    let _guard = lock()?;
    clear_unlocked()
}

/// Returns the active session, or None if there is none, it has expired,
/// or it failed signature verification. Extends the idle timeout when valid.
pub fn active_session() -> BoxResult<Option<Session>> {
    let _guard = lock()?;
    active_unlocked()
}

/// For commands that need a logged-in user and should fail without one
pub fn require_session() -> BoxResult<Session> {
    active_session()?.ok_or_else(|| "Not logged in. Run Pgen start-vault first.".into())
}

/// For commands that should re-authenticate instead of failing when the session is gone.
/// The lock is released before `reauth` runs, so reauth can call create_session.
pub fn require_session_or_reauth<F>(reauth: F) -> BoxResult<Session>
where
    F: FnOnce() -> BoxResult<Session>,
{
    match active_session()? {
        Some(session) => Ok(session),
        None => reauth(),
    }
}