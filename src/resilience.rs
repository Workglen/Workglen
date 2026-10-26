//! Panic boundaries and explicit lock recovery policy. Recovery is appropriate
//! for exclusion-only locks and structurally valid caches, not authority/store
//! transitions. Those must be reset or fenced by their owner.
use crate::error::Result;
use std::sync::{Mutex, MutexGuard};

#[derive(Debug)]
pub struct IsolatedPanic;
impl std::fmt::Display for IsolatedPanic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Internal operation failed; review its outcome before retrying")
    }
}
impl std::error::Error for IsolatedPanic {}

/// End the failed operation without retrying a possibly completed side effect.
/// Unwinding drops sockets, transactions and admission permits inside `f`.
/// This cannot intercept aborts, allocation failure or stack exhaustion.
pub fn boundary<T>(name: &'static str, f: impl FnOnce() -> Result<T>) -> Result<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(result) => result,
        Err(_) => {
            eprintln!("{name}: internal panic isolated; operation outcome may be uncertain");
            Err(IsolatedPanic.into())
        }
    }
}

/// Only use where interruption cannot invalidate the protected value (unit
/// exclusion locks, scalar deadlines and independently validated telemetry).
pub fn lock<T>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn try_lock(
    lock: &Mutex<()>,
) -> std::result::Result<MutexGuard<'_, ()>, std::sync::TryLockError<MutexGuard<'_, ()>>> {
    match lock.try_lock() {
        Err(std::sync::TryLockError::Poisoned(error)) => {
            lock.clear_poison();
            Ok(error.into_inner())
        }
        result => result,
    }
}

/// Revoke cached authority / discard pooled resources after interrupted updates.
pub fn reset_lock<T: Default>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
    match lock.lock() {
        Ok(guard) => guard,
        Err(error) => {
            let mut guard = error.into_inner();
            *guard = T::default();
            lock.clear_poison();
            guard
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn panic_releases_admission_and_exclusion_for_next_session() {
        let gate = crate::net::Gate::new(1);
        let mutex = Mutex::new(());
        let result: Result<()> = boundary("synthetic session", || {
            let _permit = gate.enter().unwrap();
            let _guard = lock(&mutex);
            panic!("injected session fault");
        });
        assert!(result.is_err());
        assert!(mutex.is_poisoned());
        boundary("next session", || {
            let _permit = gate.enter().expect("admission released");
            let _guard = lock(&mutex);
            Ok(())
        })
        .unwrap();
    }
    #[test]
    fn poisoned_authority_cache_is_revoked_before_reuse() {
        let sessions = Mutex::new(std::collections::HashMap::from([("old", "token")]));
        let _: Result<()> = boundary("cache update", || {
            let mut guard = lock(&sessions);
            guard.insert("partial", "token");
            panic!("injected cache fault");
        });
        let mut guard = reset_lock(&sessions);
        assert!(guard.is_empty());
        guard.insert("new", "fresh login");
        drop(guard);
        assert!(!sessions.is_poisoned());
        assert_eq!(reset_lock(&sessions).len(), 1);
    }
    #[test]
    fn boundary_never_replays_an_uncertain_side_effect() {
        let count = std::sync::atomic::AtomicUsize::new(0);
        let _: Result<()> = boundary("uncertain write", || {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            panic!("after side effect");
        });
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
    #[test]
    fn poisoned_try_lock_recovers_but_live_contention_is_still_busy() {
        let mutex = Mutex::new(());
        let _: Result<()> = boundary("password gate", || {
            let _guard = lock(&mutex);
            panic!("injected fault");
        });
        let guard = try_lock(&mutex).unwrap();
        assert!(try_lock(&mutex).is_err());
        assert!(!mutex.is_poisoned());
        drop(guard);
        assert!(try_lock(&mutex).is_ok());
    }
    #[test]
    fn listener_serves_next_connection_after_injected_session_panic() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let gate = crate::net::Gate::new(1);
            let exclusion = Mutex::new(());
            for i in 0..2 {
                let (mut socket, _) = listener.accept().unwrap();
                let permit = gate.enter().expect("previous session released admission");
                let exclusion = &exclusion;
                let result = boundary("loopback session", move || {
                    let _permit = permit;
                    let _guard = lock(exclusion);
                    if i == 0 {
                        panic!("injected session fault");
                    }
                    socket.write_all(b"next session succeeds")?;
                    Ok(())
                });
                assert_eq!(result.is_ok(), i == 1);
            }
        });
        for i in 0..2 {
            let mut client = std::net::TcpStream::connect(address).unwrap();
            client
                .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                .unwrap();
            let mut bytes = Vec::new();
            client.read_to_end(&mut bytes).unwrap();
            assert_eq!(
                bytes.as_slice(),
                if i == 0 {
                    &b""[..]
                } else {
                    &b"next session succeeds"[..]
                }
            );
        }
        worker.join().unwrap();
    }
}
