use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClipboardError {
    #[error("no clipboard backend: {0}")]
    Unavailable(String),
    #[error("clipboard failed: {0}")]
    Failed(String),
}

#[cfg(target_os = "android")]
const ANDROID_UNAVAILABLE: &str = "clipboard access goes through the Android AutofillService";

#[must_use]
pub fn backend_name() -> &'static str {
    #[cfg(target_os = "android")]
    {
        "android-autofill"
    }
    #[cfg(target_os = "linux")]
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        "wayland (wl-copy)"
    } else {
        "x11"
    }
    #[cfg(target_os = "windows")]
    {
        "windows"
    }
    #[cfg(target_os = "macos")]
    {
        "macos"
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "windows",
        target_os = "macos",
        target_os = "android"
    )))]
    {
        "unknown"
    }
}

#[cfg(target_os = "android")]
#[must_use]
pub fn available() -> bool {
    false
}

#[cfg(not(target_os = "android"))]
#[must_use]
pub fn available() -> bool {
    arboard::Clipboard::new().is_ok()
}

#[cfg(target_os = "android")]
pub fn copy(_text: &str) -> Result<(), ClipboardError> {
    Err(ClipboardError::Unavailable(ANDROID_UNAVAILABLE.to_owned()))
}

#[cfg(not(target_os = "android"))]
pub fn copy(text: &str) -> Result<(), ClipboardError> {
    let mut board =
        arboard::Clipboard::new().map_err(|e| ClipboardError::Unavailable(e.to_string()))?;
    board
        .set_text(text.to_owned())
        .map_err(|e| ClipboardError::Failed(e.to_string()))
}

#[cfg(target_os = "android")]
pub fn read_back() -> Result<Option<String>, ClipboardError> {
    Err(ClipboardError::Unavailable(ANDROID_UNAVAILABLE.to_owned()))
}

#[cfg(not(target_os = "android"))]
pub fn read_back() -> Result<Option<String>, ClipboardError> {
    let mut board =
        arboard::Clipboard::new().map_err(|e| ClipboardError::Unavailable(e.to_string()))?;
    board
        .get_text()
        .map(Some)
        .map_err(|e| ClipboardError::Failed(e.to_string()))
}

#[cfg(target_os = "android")]
pub fn clear_if_ours(_secret: &str) -> Result<bool, ClipboardError> {
    Ok(false)
}

#[cfg(not(target_os = "android"))]
pub fn clear_if_ours(secret: &str) -> Result<bool, ClipboardError> {
    match read_back()? {
        Some(current) if current == secret => {
            copy("")?;
            Ok(true)
        }
        _ => Ok(false),
    }
}
