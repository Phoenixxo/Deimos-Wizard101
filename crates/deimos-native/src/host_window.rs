#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostWindowGeometry {
    pub left: i32,
    pub top: i32,
    pub width: i32,
    pub height: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostWindowError {
    pub message: String,
    pub native_code: Option<u32>,
}

impl HostWindowError {
    #[cfg(target_os = "windows")]
    fn native(operation: &str) -> Self {
        let native_code = unsafe { windows::Win32::Foundation::GetLastError() }.0;
        Self {
            message: format!("{operation} failed with Windows error {native_code}"),
            native_code: Some(native_code),
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn unsupported() -> Self {
        Self {
            message: "native overlay window operations are available only on Windows".to_string(),
            native_code: None,
        }
    }
}

pub struct HostWindowService;

impl HostWindowService {
    pub fn client_geometry(raw_window: u64) -> Result<HostWindowGeometry, HostWindowError> {
        #[cfg(target_os = "windows")]
        {
            use windows::Win32::Foundation::{POINT, RECT};
            use windows::Win32::Graphics::Gdi::ClientToScreen;
            use windows::Win32::UI::WindowsAndMessaging::GetClientRect;

            let window = validated_window(raw_window)?;
            let mut origin = POINT::default();
            if !unsafe { ClientToScreen(window, &mut origin) }.as_bool() {
                return Err(HostWindowError::native("ClientToScreen"));
            }
            let mut rectangle = RECT::default();
            unsafe { GetClientRect(window, &mut rectangle) }
                .map_err(|_| HostWindowError::native("GetClientRect"))?;
            Ok(HostWindowGeometry {
                left: origin.x,
                top: origin.y,
                width: rectangle.right - rectangle.left,
                height: rectangle.bottom - rectangle.top,
            })
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = raw_window;
            Err(HostWindowError::unsupported())
        }
    }

    pub fn make_click_through(raw_window: u64) -> Result<(), HostWindowError> {
        #[cfg(target_os = "windows")]
        {
            use windows::Win32::Foundation::{SetLastError, WIN32_ERROR};
            use windows::Win32::UI::WindowsAndMessaging::{
                GetWindowLongW, SetWindowLongW, GWL_EXSTYLE, WS_EX_LAYERED, WS_EX_TRANSPARENT,
            };

            let window = validated_window(raw_window)?;
            let current_style = unsafe { GetWindowLongW(window, GWL_EXSTYLE) };
            let new_style = current_style | (WS_EX_TRANSPARENT.0 | WS_EX_LAYERED.0) as i32;
            unsafe { SetLastError(WIN32_ERROR(0)) };
            let previous_style = unsafe { SetWindowLongW(window, GWL_EXSTYLE, new_style) };
            if previous_style == 0 && unsafe { windows::Win32::Foundation::GetLastError() }.0 != 0 {
                return Err(HostWindowError::native("SetWindowLongW"));
            }
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = raw_window;
            Err(HostWindowError::unsupported())
        }
    }

    pub fn stack_above(
        raw_overlay_window: u64,
        raw_game_window: u64,
    ) -> Result<(), HostWindowError> {
        #[cfg(target_os = "windows")]
        {
            use windows::Win32::UI::WindowsAndMessaging::{
                GetWindow, SetWindowPos, GW_HWNDPREV, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE,
            };

            let overlay_window = validated_window(raw_overlay_window)?;
            let game_window = validated_window(raw_game_window)?;
            let above_game = unsafe { GetWindow(game_window, GW_HWNDPREV) }.unwrap_or_default();
            if above_game == overlay_window {
                return Ok(());
            }
            unsafe {
                SetWindowPos(
                    overlay_window,
                    above_game,
                    0,
                    0,
                    0,
                    0,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
                )
            }
            .map_err(|_| HostWindowError::native("SetWindowPos"))
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (raw_overlay_window, raw_game_window);
            Err(HostWindowError::unsupported())
        }
    }
}

#[cfg(target_os = "windows")]
fn validated_window(raw_window: u64) -> Result<windows::Win32::Foundation::HWND, HostWindowError> {
    use std::ffi::c_void;

    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::IsWindow;

    let raw_window = usize::try_from(raw_window).map_err(|_| HostWindowError {
        message: "the native window identifier is outside the supported range".to_string(),
        native_code: None,
    })?;
    let window = HWND(raw_window as *mut c_void);
    if raw_window == 0 || !unsafe { IsWindow(window) }.as_bool() {
        return Err(HostWindowError {
            message: "the selected native window is no longer available".to_string(),
            native_code: None,
        });
    }
    Ok(window)
}

#[cfg(all(test, not(target_os = "windows")))]
mod tests {
    use super::*;

    #[test]
    fn native_overlay_operations_are_rejected_off_windows() {
        let error = HostWindowService::client_geometry(1).expect_err("platform should reject");
        assert!(error.message.contains("only on Windows"));
        assert_eq!(error.native_code, None);
    }
}
