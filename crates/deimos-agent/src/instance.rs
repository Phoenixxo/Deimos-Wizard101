use std::io;

/// The GUID prevents accidental collision with unrelated Windows software.
///
/// This named object is duplicate suppression, not an authentication boundary:
/// another process owned by the same user in the same Wine prefix can pre-create
/// it and deny agent startup. We intentionally rely on the process default DACL
/// instead of custom Windows security attributes because Wine implementations
/// vary; the authenticated loopback token still prevents agent impersonation.
pub const AGENT_MUTEX_NAME: &str =
    r"Local\DeimosWizard101Agent-{D8A6F2B7-6D30-4B12-9ED5-9B709A7C8F41}";

#[cfg(windows)]
mod platform {
    use super::{io, AGENT_MUTEX_NAME};
    use windows::core::HSTRING;
    use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE};
    use windows::Win32::System::Threading::CreateMutexW;

    pub struct AgentInstanceGuard {
        handle: HANDLE,
    }

    impl AgentInstanceGuard {
        pub fn acquire() -> io::Result<Self> {
            let name = HSTRING::from(AGENT_MUTEX_NAME);
            let handle = unsafe { CreateMutexW(None, false, &name) }?;
            if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
                unsafe {
                    CloseHandle(handle)?;
                }
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "another Deimos agent is already running in this Wine bottle",
                ));
            }
            Ok(Self { handle })
        }
    }

    impl Drop for AgentInstanceGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use super::io;

    pub struct AgentInstanceGuard;

    impl AgentInstanceGuard {
        pub fn acquire() -> io::Result<Self> {
            Ok(Self)
        }
    }
}

pub use platform::AgentInstanceGuard;

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use super::AgentInstanceGuard;
    use super::AGENT_MUTEX_NAME;

    #[test]
    fn instance_mutex_is_stable_and_does_not_contain_a_path() {
        assert_eq!(
            AGENT_MUTEX_NAME,
            r"Local\DeimosWizard101Agent-{D8A6F2B7-6D30-4B12-9ED5-9B709A7C8F41}"
        );
        assert!(!AGENT_MUTEX_NAME.contains(':'));
        assert!(!AGENT_MUTEX_NAME.contains('/'));
        assert!(AGENT_MUTEX_NAME.contains('{'));
    }

    #[cfg(windows)]
    #[test]
    fn duplicate_agent_guard_is_rejected_while_first_is_live() {
        let _first = AgentInstanceGuard::acquire().expect("first agent should acquire the mutex");
        let duplicate = match AgentInstanceGuard::acquire() {
            Ok(_) => panic!("duplicate agent must be rejected"),
            Err(error) => error,
        };
        assert_eq!(duplicate.kind(), std::io::ErrorKind::AddrInUse);
    }
}
