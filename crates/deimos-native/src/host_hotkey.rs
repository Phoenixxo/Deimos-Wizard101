use std::collections::HashMap;

pub const MOD_ALT: u16 = 0x0001;
pub const MOD_CONTROL: u16 = 0x0002;
pub const MOD_SHIFT: u16 = 0x0004;
pub const MOD_NOREPEAT: u16 = 0x4000;
const SUPPORTED_MODIFIERS: u16 = MOD_ALT | MOD_CONTROL | MOD_SHIFT | MOD_NOREPEAT;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct HotkeyChord {
    pub virtual_key: u16,
    pub modifiers: u16,
}

impl HotkeyChord {
    fn normalized(self) -> Self {
        Self {
            virtual_key: self.virtual_key,
            modifiers: self.modifiers & !MOD_NOREPEAT,
        }
    }

    fn no_repeat(self) -> bool {
        self.modifiers & MOD_NOREPEAT != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostHotkeyErrorKind {
    Conflict,
    NotRegistered,
    UnsupportedKey,
    InvalidModifiers,
    #[cfg(target_os = "macos")]
    PermissionRequired,
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    UnsupportedPlatform,
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    Native,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostHotkeyError {
    pub kind: HostHotkeyErrorKind,
    pub message: String,
    pub virtual_key: Option<u16>,
    pub modifiers: Option<u16>,
    pub native_code: Option<i64>,
}

impl HostHotkeyError {
    fn for_chord(
        kind: HostHotkeyErrorKind,
        message: impl Into<String>,
        chord: HotkeyChord,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
            virtual_key: Some(chord.virtual_key),
            modifiers: Some(chord.modifiers),
            native_code: None,
        }
    }

    #[cfg(any(target_os = "windows", target_os = "macos"))]
    fn native(
        kind: HostHotkeyErrorKind,
        message: impl Into<String>,
        chord: Option<HotkeyChord>,
        native_code: Option<i64>,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
            virtual_key: chord.map(|value| value.virtual_key),
            modifiers: chord.map(|value| value.modifiers),
            native_code,
        }
    }
}

trait PlatformHotkeyBackend: Send {
    fn register(&mut self, registration_id: u32, chord: HotkeyChord)
        -> Result<(), HostHotkeyError>;
    fn unregister(
        &mut self,
        registration_id: u32,
        chord: HotkeyChord,
    ) -> Result<(), HostHotkeyError>;
    fn poll_events(&mut self) -> Vec<NativeHotkeyEvent>;
    fn shutdown(&mut self);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativeHotkeyEvent {
    registration_id: Option<u32>,
    virtual_key: u16,
    modifiers: u16,
    is_repeat: bool,
}

struct Registration {
    chord: HotkeyChord,
}

pub struct HostHotkeyService {
    backend: Box<dyn PlatformHotkeyBackend>,
    registrations: HashMap<u32, Registration>,
    chord_ids: HashMap<HotkeyChord, u32>,
    next_registration_id: u32,
}

impl Default for HostHotkeyService {
    fn default() -> Self {
        Self::new(platform_backend())
    }
}

impl HostHotkeyService {
    fn new(backend: Box<dyn PlatformHotkeyBackend>) -> Self {
        Self {
            backend,
            registrations: HashMap::new(),
            chord_ids: HashMap::new(),
            next_registration_id: 1,
        }
    }

    pub fn register(&mut self, virtual_key: u16, modifiers: u16) -> Result<u32, HostHotkeyError> {
        let chord = validate_chord(virtual_key, modifiers)?;
        let normalized = chord.normalized();
        if self.chord_ids.contains_key(&normalized) {
            return Err(HostHotkeyError::for_chord(
                HostHotkeyErrorKind::Conflict,
                "the requested shortcut is already registered by this process",
                chord,
            ));
        }

        let registration_id = self.allocate_registration_id();
        self.backend.register(registration_id, chord)?;
        self.registrations
            .insert(registration_id, Registration { chord });
        self.chord_ids.insert(normalized, registration_id);
        Ok(registration_id)
    }

    pub fn unregister(&mut self, registration_id: u32) -> Result<(), HostHotkeyError> {
        let Some(registration) = self.registrations.get(&registration_id) else {
            return Err(HostHotkeyError {
                kind: HostHotkeyErrorKind::NotRegistered,
                message: format!("hotkey registration {registration_id} does not exist"),
                virtual_key: None,
                modifiers: None,
                native_code: None,
            });
        };
        self.backend
            .unregister(registration_id, registration.chord)?;
        let registration = self
            .registrations
            .remove(&registration_id)
            .expect("registration was checked above");
        self.chord_ids.remove(&registration.chord.normalized());
        Ok(())
    }

    pub fn clear(&mut self) -> Result<(), HostHotkeyError> {
        let registration_ids: Vec<u32> = self.registrations.keys().copied().collect();
        let mut first_error = None;
        for registration_id in registration_ids {
            if let Err(error) = self.unregister(registration_id) {
                first_error.get_or_insert(error);
            }
        }
        if let Some(error) = first_error {
            Err(error)
        } else {
            Ok(())
        }
    }

    pub fn poll_events(&mut self) -> Vec<u32> {
        let mut events = Vec::new();
        for event in self.backend.poll_events() {
            if let Some(registration_id) = event.registration_id {
                if self.registrations.contains_key(&registration_id) {
                    events.push(registration_id);
                }
                continue;
            }
            let normalized = HotkeyChord {
                virtual_key: event.virtual_key,
                modifiers: event.modifiers,
            }
            .normalized();
            let Some(registration_id) = self.chord_ids.get(&normalized).copied() else {
                continue;
            };
            let Some(registration) = self.registrations.get(&registration_id) else {
                continue;
            };
            if !event.is_repeat || !registration.chord.no_repeat() {
                events.push(registration_id);
            }
        }
        events
    }

    fn allocate_registration_id(&mut self) -> u32 {
        loop {
            let candidate = self.next_registration_id;
            self.next_registration_id = self.next_registration_id.wrapping_add(1).max(1);
            if !self.registrations.contains_key(&candidate) {
                return candidate;
            }
        }
    }
}

impl Drop for HostHotkeyService {
    fn drop(&mut self) {
        let _ = self.clear();
        self.backend.shutdown();
    }
}

fn validate_chord(virtual_key: u16, modifiers: u16) -> Result<HotkeyChord, HostHotkeyError> {
    let chord = HotkeyChord {
        virtual_key,
        modifiers,
    };
    if virtual_key == 0 || virtual_key > u8::MAX as u16 {
        return Err(HostHotkeyError::for_chord(
            HostHotkeyErrorKind::UnsupportedKey,
            "the virtual key must be a supported Windows virtual-key value",
            chord,
        ));
    }
    if modifiers & !SUPPORTED_MODIFIERS != 0 {
        return Err(HostHotkeyError::for_chord(
            HostHotkeyErrorKind::InvalidModifiers,
            "the shortcut contains unsupported modifier flags",
            chord,
        ));
    }
    #[cfg(target_os = "macos")]
    if macos::mac_keycode(virtual_key).is_none() {
        return Err(HostHotkeyError::for_chord(
            HostHotkeyErrorKind::UnsupportedKey,
            "the virtual key does not have a macOS keyboard equivalent",
            chord,
        ));
    }
    Ok(chord)
}

#[cfg(target_os = "windows")]
fn platform_backend() -> Box<dyn PlatformHotkeyBackend> {
    Box::new(windows_backend::WindowsHotkeyBackend::default())
}

#[cfg(target_os = "macos")]
fn platform_backend() -> Box<dyn PlatformHotkeyBackend> {
    Box::new(macos::MacHotkeyBackend::default())
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn platform_backend() -> Box<dyn PlatformHotkeyBackend> {
    Box::new(UnsupportedBackend)
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
struct UnsupportedBackend;

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
impl PlatformHotkeyBackend for UnsupportedBackend {
    fn register(
        &mut self,
        _registration_id: u32,
        chord: HotkeyChord,
    ) -> Result<(), HostHotkeyError> {
        Err(HostHotkeyError::for_chord(
            HostHotkeyErrorKind::UnsupportedPlatform,
            "global hotkeys are supported only on Windows and macOS",
            chord,
        ))
    }

    fn unregister(
        &mut self,
        _registration_id: u32,
        _chord: HotkeyChord,
    ) -> Result<(), HostHotkeyError> {
        Ok(())
    }

    fn poll_events(&mut self) -> Vec<NativeHotkeyEvent> {
        Vec::new()
    }

    fn shutdown(&mut self) {}
}

#[cfg(target_os = "windows")]
mod windows_backend {
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        RegisterHotKey, UnregisterHotKey, HOT_KEY_MODIFIERS, MOD_ALT as WIN_MOD_ALT,
        MOD_CONTROL as WIN_MOD_CONTROL, MOD_NOREPEAT as WIN_MOD_NOREPEAT,
        MOD_SHIFT as WIN_MOD_SHIFT,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        PeekMessageW, MSG, PM_NOREMOVE, PM_REMOVE, WM_HOTKEY,
    };

    use super::{
        HostHotkeyError, HostHotkeyErrorKind, HotkeyChord, NativeHotkeyEvent,
        PlatformHotkeyBackend, MOD_ALT, MOD_CONTROL, MOD_NOREPEAT, MOD_SHIFT,
    };

    enum Command {
        Register {
            registration_id: u32,
            chord: HotkeyChord,
            response: Sender<Result<(), HostHotkeyError>>,
        },
        Unregister {
            registration_id: u32,
            chord: HotkeyChord,
            response: Sender<Result<(), HostHotkeyError>>,
        },
        Stop,
    }

    pub struct WindowsHotkeyBackend {
        commands: Sender<Command>,
        events: Receiver<NativeHotkeyEvent>,
        worker: Option<JoinHandle<()>>,
    }

    impl Default for WindowsHotkeyBackend {
        fn default() -> Self {
            let (command_tx, command_rx) = mpsc::channel();
            let (event_tx, event_rx) = mpsc::channel();
            let worker = thread::Builder::new()
                .name("deimos-hotkeys".to_string())
                .spawn(move || run_worker(command_rx, event_tx))
                .expect("hotkey worker thread should start");
            Self {
                commands: command_tx,
                events: event_rx,
                worker: Some(worker),
            }
        }
    }

    impl WindowsHotkeyBackend {
        fn request(
            &self,
            command: impl FnOnce(Sender<Result<(), HostHotkeyError>>) -> Command,
            chord: HotkeyChord,
        ) -> Result<(), HostHotkeyError> {
            let (response_tx, response_rx) = mpsc::channel();
            self.commands.send(command(response_tx)).map_err(|error| {
                HostHotkeyError::native(
                    HostHotkeyErrorKind::Native,
                    format!("the Windows hotkey worker stopped unexpectedly: {error}"),
                    Some(chord),
                    None,
                )
            })?;
            response_rx.recv().map_err(|error| {
                HostHotkeyError::native(
                    HostHotkeyErrorKind::Native,
                    format!("the Windows hotkey worker did not return a result: {error}"),
                    Some(chord),
                    None,
                )
            })?
        }
    }

    impl PlatformHotkeyBackend for WindowsHotkeyBackend {
        fn register(
            &mut self,
            registration_id: u32,
            chord: HotkeyChord,
        ) -> Result<(), HostHotkeyError> {
            self.request(
                |response| Command::Register {
                    registration_id,
                    chord,
                    response,
                },
                chord,
            )
        }

        fn unregister(
            &mut self,
            registration_id: u32,
            chord: HotkeyChord,
        ) -> Result<(), HostHotkeyError> {
            self.request(
                |response| Command::Unregister {
                    registration_id,
                    chord,
                    response,
                },
                chord,
            )
        }

        fn poll_events(&mut self) -> Vec<NativeHotkeyEvent> {
            self.events.try_iter().collect()
        }

        fn shutdown(&mut self) {
            let _ = self.commands.send(Command::Stop);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    fn run_worker(commands: Receiver<Command>, events: Sender<NativeHotkeyEvent>) {
        // Thread hotkeys post WM_HOTKEY to this worker, so create its message
        // queue before processing the first registration request.
        let mut queue_message = MSG::default();
        unsafe {
            let _ = PeekMessageW(&mut queue_message, HWND::default(), 0, 0, PM_NOREMOVE);
        }

        let mut running = true;
        while running {
            for command in commands.try_iter() {
                match command {
                    Command::Register {
                        registration_id,
                        chord,
                        response,
                    } => {
                        let modifiers = windows_modifiers(chord.modifiers);
                        let result = unsafe {
                            RegisterHotKey(
                                HWND::default(),
                                registration_id as i32,
                                modifiers,
                                chord.virtual_key as u32,
                            )
                        }
                        .map_err(|error| {
                            let native_code = error.code().0 as i64;
                            let kind = if native_code == 0x80070581u32 as i32 as i64 {
                                HostHotkeyErrorKind::Conflict
                            } else {
                                HostHotkeyErrorKind::Native
                            };
                            HostHotkeyError::native(
                                kind,
                                format!("RegisterHotKey failed: {error}"),
                                Some(chord),
                                Some(native_code),
                            )
                        });
                        let _ = response.send(result);
                    }
                    Command::Unregister {
                        registration_id,
                        chord,
                        response,
                    } => {
                        let result =
                            unsafe { UnregisterHotKey(HWND::default(), registration_id as i32) }
                                .map_err(|error| {
                                    HostHotkeyError::native(
                                        HostHotkeyErrorKind::Native,
                                        format!("UnregisterHotKey failed: {error}"),
                                        Some(chord),
                                        Some(error.code().0 as i64),
                                    )
                                });
                        let _ = response.send(result);
                    }
                    Command::Stop => running = false,
                }
            }

            let mut message = MSG::default();
            while unsafe {
                PeekMessageW(
                    &mut message,
                    HWND::default(),
                    WM_HOTKEY,
                    WM_HOTKEY,
                    PM_REMOVE,
                )
            }
            .as_bool()
            {
                let _ = events.send(NativeHotkeyEvent {
                    registration_id: Some(message.wParam.0 as u32),
                    virtual_key: 0,
                    modifiers: 0,
                    is_repeat: false,
                });
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn windows_modifiers(modifiers: u16) -> HOT_KEY_MODIFIERS {
        let mut result = HOT_KEY_MODIFIERS(0);
        if modifiers & MOD_ALT != 0 {
            result |= WIN_MOD_ALT;
        }
        if modifiers & MOD_CONTROL != 0 {
            result |= WIN_MOD_CONTROL;
        }
        if modifiers & MOD_SHIFT != 0 {
            result |= WIN_MOD_SHIFT;
        }
        if modifiers & MOD_NOREPEAT != 0 {
            result |= WIN_MOD_NOREPEAT;
        }
        result
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::collections::HashSet;
    use std::ffi::c_void;
    use std::ptr;
    use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use super::{
        HostHotkeyError, HostHotkeyErrorKind, HotkeyChord, NativeHotkeyEvent,
        PlatformHotkeyBackend, MOD_ALT, MOD_CONTROL, MOD_SHIFT,
    };

    type CFAllocatorRef = *const c_void;
    type CFRunLoopRef = *mut c_void;
    type CFRunLoopSourceRef = *mut c_void;
    type CFStringRef = *const c_void;
    type CFMachPortRef = *mut c_void;
    type CGEventTapProxy = *mut c_void;
    type CGEventRef = *mut c_void;
    type CGEventType = u32;
    type CGEventMask = u64;
    type CGEventFlags = u64;
    type CGEventField = u32;

    const KEY_DOWN: CGEventType = 10;
    const EVENT_TAP_DISABLED_BY_TIMEOUT: CGEventType = 0xffff_fffe;
    const EVENT_TAP_DISABLED_BY_USER_INPUT: CGEventType = 0xffff_ffff;
    const SESSION_EVENT_TAP: u32 = 1;
    const HEAD_INSERT_EVENT_TAP: u32 = 0;
    const LISTEN_ONLY: u32 = 1;
    const KEYBOARD_EVENT_AUTOREPEAT: CGEventField = 8;
    const KEYBOARD_EVENT_KEYCODE: CGEventField = 9;
    const FLAG_SHIFT: CGEventFlags = 0x0002_0000;
    const FLAG_CONTROL: CGEventFlags = 0x0004_0000;
    const FLAG_ALTERNATE: CGEventFlags = 0x0008_0000;

    #[link(name = "ApplicationServices", kind = "framework")]
    extern "C" {
        fn CGEventTapCreate(
            tap: u32,
            place: u32,
            options: u32,
            events_of_interest: CGEventMask,
            callback: unsafe extern "C" fn(
                CGEventTapProxy,
                CGEventType,
                CGEventRef,
                *mut c_void,
            ) -> CGEventRef,
            user_info: *mut c_void,
        ) -> CFMachPortRef;
        fn CGPreflightListenEventAccess() -> bool;
        fn CGEventTapEnable(tap: CFMachPortRef, enable: bool);
        fn CGEventGetFlags(event: CGEventRef) -> CGEventFlags;
        fn CGEventGetIntegerValueField(event: CGEventRef, field: CGEventField) -> i64;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        static kCFRunLoopDefaultMode: CFStringRef;
        fn CFMachPortCreateRunLoopSource(
            allocator: CFAllocatorRef,
            port: CFMachPortRef,
            order: isize,
        ) -> CFRunLoopSourceRef;
        fn CFMachPortInvalidate(port: CFMachPortRef);
        fn CFRunLoopGetCurrent() -> CFRunLoopRef;
        fn CFRunLoopAddSource(
            run_loop: CFRunLoopRef,
            source: CFRunLoopSourceRef,
            mode: CFStringRef,
        );
        fn CFRunLoopRemoveSource(
            run_loop: CFRunLoopRef,
            source: CFRunLoopSourceRef,
            mode: CFStringRef,
        );
        fn CFRunLoopRunInMode(mode: CFStringRef, seconds: f64, return_after_source: bool) -> i32;
        fn CFRelease(value: *const c_void);
    }

    struct CallbackContext {
        events: Sender<NativeHotkeyEvent>,
        event_tap: AtomicPtr<c_void>,
    }

    struct Worker {
        stop: Arc<AtomicBool>,
        handle: JoinHandle<()>,
    }

    pub struct MacHotkeyBackend {
        events: Receiver<NativeHotkeyEvent>,
        event_sender: Sender<NativeHotkeyEvent>,
        worker: Option<Worker>,
        owned_chords: HashSet<HotkeyChord>,
    }

    impl Default for MacHotkeyBackend {
        fn default() -> Self {
            let (event_sender, events) = mpsc::channel();
            Self {
                events,
                event_sender,
                worker: None,
                owned_chords: HashSet::new(),
            }
        }
    }

    fn registered_chords() -> &'static Mutex<HashSet<HotkeyChord>> {
        static REGISTERED_CHORDS: OnceLock<Mutex<HashSet<HotkeyChord>>> = OnceLock::new();
        REGISTERED_CHORDS.get_or_init(|| Mutex::new(HashSet::new()))
    }

    impl MacHotkeyBackend {
        fn ensure_worker(&mut self, chord: HotkeyChord) -> Result<(), HostHotkeyError> {
            if self.worker.is_some() {
                return Ok(());
            }
            let stop = Arc::new(AtomicBool::new(false));
            let worker_stop = Arc::clone(&stop);
            let event_sender = self.event_sender.clone();
            let (ready_tx, ready_rx) = mpsc::sync_channel(1);
            let handle = thread::Builder::new()
                .name("deimos-hotkeys".to_string())
                .spawn(move || run_event_tap(worker_stop, event_sender, ready_tx))
                .map_err(|error| {
                    HostHotkeyError::native(
                        HostHotkeyErrorKind::Native,
                        format!("the macOS hotkey worker could not start: {error}"),
                        Some(chord),
                        None,
                    )
                })?;
            match ready_rx.recv_timeout(Duration::from_secs(2)) {
                Ok(Ok(())) => {
                    self.worker = Some(Worker { stop, handle });
                    Ok(())
                }
                Ok(Err(mut error)) => {
                    error.virtual_key = Some(chord.virtual_key);
                    error.modifiers = Some(chord.modifiers);
                    let _ = handle.join();
                    Err(error)
                }
                Err(error) => {
                    stop.store(true, Ordering::Release);
                    let _ = handle.join();
                    Err(HostHotkeyError::native(
                        HostHotkeyErrorKind::Native,
                        format!("the macOS hotkey worker did not become ready: {error}"),
                        Some(chord),
                        None,
                    ))
                }
            }
        }
    }

    impl PlatformHotkeyBackend for MacHotkeyBackend {
        fn register(
            &mut self,
            _registration_id: u32,
            chord: HotkeyChord,
        ) -> Result<(), HostHotkeyError> {
            let normalized = chord.normalized();
            {
                let mut registered = registered_chords().lock().map_err(|_| {
                    HostHotkeyError::native(
                        HostHotkeyErrorKind::Native,
                        "the macOS hotkey registration state is unavailable",
                        Some(chord),
                        None,
                    )
                })?;
                if !registered.insert(normalized) {
                    return Err(HostHotkeyError::for_chord(
                        HostHotkeyErrorKind::Conflict,
                        "the requested shortcut is already registered by this process",
                        chord,
                    ));
                }
            }

            if let Err(error) = self.ensure_worker(chord) {
                if let Ok(mut registered) = registered_chords().lock() {
                    registered.remove(&normalized);
                }
                return Err(error);
            }
            self.owned_chords.insert(normalized);
            Ok(())
        }

        fn unregister(
            &mut self,
            _registration_id: u32,
            chord: HotkeyChord,
        ) -> Result<(), HostHotkeyError> {
            let normalized = chord.normalized();
            let mut registered = registered_chords().lock().map_err(|_| {
                HostHotkeyError::native(
                    HostHotkeyErrorKind::Native,
                    "the macOS hotkey registration state is unavailable",
                    Some(chord),
                    None,
                )
            })?;
            registered.remove(&normalized);
            self.owned_chords.remove(&normalized);
            Ok(())
        }

        fn poll_events(&mut self) -> Vec<NativeHotkeyEvent> {
            self.events.try_iter().collect()
        }

        fn shutdown(&mut self) {
            if let Ok(mut registered) = registered_chords().lock() {
                for chord in self.owned_chords.drain() {
                    registered.remove(&chord);
                }
            }
            if let Some(worker) = self.worker.take() {
                worker.stop.store(true, Ordering::Release);
                let _ = worker.handle.join();
            }
        }
    }

    fn run_event_tap(
        stop: Arc<AtomicBool>,
        events: Sender<NativeHotkeyEvent>,
        ready: mpsc::SyncSender<Result<(), HostHotkeyError>>,
    ) {
        if !unsafe { CGPreflightListenEventAccess() } {
            let _ = ready.send(Err(HostHotkeyError::native(
                HostHotkeyErrorKind::PermissionRequired,
                "macOS has not granted permission to listen for global keyboard events",
                None,
                None,
            )));
            return;
        }

        let context = Box::new(CallbackContext {
            events,
            event_tap: AtomicPtr::new(ptr::null_mut()),
        });
        let context_ptr = Box::into_raw(context);
        let event_tap = unsafe {
            CGEventTapCreate(
                SESSION_EVENT_TAP,
                HEAD_INSERT_EVENT_TAP,
                LISTEN_ONLY,
                1u64 << KEY_DOWN,
                event_tap_callback,
                context_ptr.cast(),
            )
        };
        if event_tap.is_null() {
            unsafe {
                drop(Box::from_raw(context_ptr));
            }
            let _ = ready.send(Err(HostHotkeyError::native(
                HostHotkeyErrorKind::Native,
                "CGEventTapCreate could not listen for global keyboard events",
                None,
                None,
            )));
            return;
        }
        unsafe {
            (*context_ptr)
                .event_tap
                .store(event_tap.cast(), Ordering::Release);
        }
        let source = unsafe { CFMachPortCreateRunLoopSource(ptr::null(), event_tap, 0) };
        if source.is_null() {
            unsafe {
                CFMachPortInvalidate(event_tap);
                CFRelease(event_tap.cast());
                drop(Box::from_raw(context_ptr));
            }
            let _ = ready.send(Err(HostHotkeyError::native(
                HostHotkeyErrorKind::Native,
                "macOS could not create a run-loop source for global hotkeys",
                None,
                None,
            )));
            return;
        }
        let run_loop = unsafe { CFRunLoopGetCurrent() };
        unsafe {
            CFRunLoopAddSource(run_loop, source, kCFRunLoopDefaultMode);
            CGEventTapEnable(event_tap, true);
        }
        let _ = ready.send(Ok(()));
        while !stop.load(Ordering::Acquire) {
            unsafe {
                CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.05, true);
            }
        }
        unsafe {
            CFMachPortInvalidate(event_tap);
            CFRunLoopRemoveSource(run_loop, source, kCFRunLoopDefaultMode);
            CFRelease(source.cast());
            CFRelease(event_tap.cast());
            drop(Box::from_raw(context_ptr));
        }
    }

    unsafe extern "C" fn event_tap_callback(
        _proxy: CGEventTapProxy,
        event_type: CGEventType,
        event: CGEventRef,
        user_info: *mut c_void,
    ) -> CGEventRef {
        if user_info.is_null() {
            return event;
        }
        let context = &*(user_info.cast::<CallbackContext>());
        if matches!(
            event_type,
            EVENT_TAP_DISABLED_BY_TIMEOUT | EVENT_TAP_DISABLED_BY_USER_INPUT
        ) {
            let event_tap = context.event_tap.load(Ordering::Acquire);
            if !event_tap.is_null() {
                CGEventTapEnable(event_tap.cast(), true);
            }
            return event;
        }
        if event_type != KEY_DOWN || event.is_null() {
            return event;
        }
        let mac_key = CGEventGetIntegerValueField(event, KEYBOARD_EVENT_KEYCODE);
        let Ok(mac_key) = u16::try_from(mac_key) else {
            return event;
        };
        let Some(virtual_key) = windows_virtual_key(mac_key) else {
            return event;
        };
        let flags = CGEventGetFlags(event);
        let mut modifiers = 0;
        if flags & FLAG_ALTERNATE != 0 {
            modifiers |= MOD_ALT;
        }
        if flags & FLAG_CONTROL != 0 {
            modifiers |= MOD_CONTROL;
        }
        if flags & FLAG_SHIFT != 0 {
            modifiers |= MOD_SHIFT;
        }
        let is_repeat = CGEventGetIntegerValueField(event, KEYBOARD_EVENT_AUTOREPEAT) != 0;
        let _ = context.events.send(NativeHotkeyEvent {
            registration_id: None,
            virtual_key,
            modifiers,
            is_repeat,
        });
        event
    }

    pub(super) fn mac_keycode(virtual_key: u16) -> Option<u16> {
        WINDOWS_TO_MAC
            .iter()
            .find_map(|(windows, mac)| (*windows == virtual_key).then_some(*mac))
    }

    fn windows_virtual_key(mac_key: u16) -> Option<u16> {
        WINDOWS_TO_MAC
            .iter()
            .find_map(|(windows, mac)| (*mac == mac_key).then_some(*windows))
    }

    const WINDOWS_TO_MAC: &[(u16, u16)] = &[
        (0x08, 51),
        (0x09, 48),
        (0x0D, 36),
        (0x13, 113),
        (0x14, 57),
        (0x1B, 53),
        (0x20, 49),
        (0x21, 116),
        (0x22, 121),
        (0x23, 119),
        (0x24, 115),
        (0x25, 123),
        (0x26, 126),
        (0x27, 124),
        (0x28, 125),
        (0x2D, 114),
        (0x2E, 117),
        (0x30, 29),
        (0x31, 18),
        (0x32, 19),
        (0x33, 20),
        (0x34, 21),
        (0x35, 23),
        (0x36, 22),
        (0x37, 26),
        (0x38, 28),
        (0x39, 25),
        (0x41, 0),
        (0x42, 11),
        (0x43, 8),
        (0x44, 2),
        (0x45, 14),
        (0x46, 3),
        (0x47, 5),
        (0x48, 4),
        (0x49, 34),
        (0x4A, 38),
        (0x4B, 40),
        (0x4C, 37),
        (0x4D, 46),
        (0x4E, 45),
        (0x4F, 31),
        (0x50, 35),
        (0x51, 12),
        (0x52, 15),
        (0x53, 1),
        (0x54, 17),
        (0x55, 32),
        (0x56, 9),
        (0x57, 13),
        (0x58, 7),
        (0x59, 16),
        (0x5A, 6),
        (0x60, 82),
        (0x61, 83),
        (0x62, 84),
        (0x63, 85),
        (0x64, 86),
        (0x65, 87),
        (0x66, 88),
        (0x67, 89),
        (0x68, 91),
        (0x69, 92),
        (0x6A, 67),
        (0x6B, 69),
        (0x6D, 78),
        (0x6E, 65),
        (0x6F, 75),
        (0x70, 122),
        (0x71, 120),
        (0x72, 99),
        (0x73, 118),
        (0x74, 96),
        (0x75, 97),
        (0x76, 98),
        (0x77, 100),
        (0x78, 101),
        (0x79, 109),
        (0x7A, 103),
        (0x7B, 111),
        (0x90, 71),
        (0xBA, 41),
        (0xBB, 24),
        (0xBC, 43),
        (0xBD, 27),
        (0xBE, 47),
        (0xBF, 44),
        (0xC0, 50),
        (0xDB, 33),
        (0xDC, 42),
        (0xDD, 30),
        (0xDE, 39),
    ];
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    #[derive(Default)]
    struct FakeBackend {
        registered: Vec<(u32, HotkeyChord)>,
        unregistered: Vec<u32>,
        events: VecDeque<NativeHotkeyEvent>,
        registration_error: Option<HostHotkeyError>,
    }

    impl PlatformHotkeyBackend for FakeBackend {
        fn register(
            &mut self,
            registration_id: u32,
            chord: HotkeyChord,
        ) -> Result<(), HostHotkeyError> {
            if let Some(error) = self.registration_error.clone() {
                return Err(error);
            }
            self.registered.push((registration_id, chord));
            Ok(())
        }

        fn unregister(
            &mut self,
            registration_id: u32,
            _chord: HotkeyChord,
        ) -> Result<(), HostHotkeyError> {
            self.unregistered.push(registration_id);
            Ok(())
        }

        fn poll_events(&mut self) -> Vec<NativeHotkeyEvent> {
            self.events.drain(..).collect()
        }

        fn shutdown(&mut self) {}
    }

    #[test]
    fn registration_conflicts_ignore_the_no_repeat_flag() {
        let mut service = HostHotkeyService::new(Box::<FakeBackend>::default());
        service.register(0x70, 0).expect("first registration");
        let error = service
            .register(0x70, MOD_NOREPEAT)
            .expect_err("same key combination should conflict");
        assert_eq!(error.kind, HostHotkeyErrorKind::Conflict);
    }

    #[test]
    fn unregister_releases_a_chord_for_reuse() {
        let mut service = HostHotkeyService::new(Box::<FakeBackend>::default());
        let registration_id = service.register(0x71, MOD_SHIFT).expect("register");
        service.unregister(registration_id).expect("unregister");
        let replacement = service.register(0x71, MOD_SHIFT).expect("reuse chord");
        assert_ne!(registration_id, replacement);
    }

    #[test]
    fn repeated_events_respect_no_repeat_per_registration() {
        let mut backend = FakeBackend::default();
        backend.events.push_back(NativeHotkeyEvent {
            registration_id: None,
            virtual_key: 0x72,
            modifiers: MOD_CONTROL,
            is_repeat: true,
        });
        let mut service = HostHotkeyService::new(Box::new(backend));
        service
            .register(0x72, MOD_CONTROL | MOD_NOREPEAT)
            .expect("register");
        assert!(service.poll_events().is_empty());
    }

    #[test]
    fn invalid_modifier_bits_are_rejected_before_native_registration() {
        let mut service = HostHotkeyService::new(Box::<FakeBackend>::default());
        let error = service
            .register(0x73, 0x0100)
            .expect_err("unknown modifier should fail");
        assert_eq!(error.kind, HostHotkeyErrorKind::InvalidModifiers);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_maps_the_application_shortcut_keys_to_physical_keycodes() {
        assert_eq!(super::macos::mac_keycode(0x41), Some(0));
        assert_eq!(super::macos::mac_keycode(0x70), Some(122));
        assert_eq!(super::macos::mac_keycode(0x7B), Some(111));
        assert_eq!(super::macos::mac_keycode(0x87), None);
    }
}
