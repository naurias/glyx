use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub [u8; 16]);

impl DeviceId {
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        getrandom::getrandom(&mut bytes).expect("OS CSPRNG unavailable");
        Self(bytes)
    }
    #[must_use]
    pub fn zero() -> Self {
        Self([0u8; 16])
    }
    #[must_use]
    pub fn to_hex(self) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(32);
        for b in self.0 {
            let _ = write!(out, "{b:02x}");
        }
        out
    }
    #[must_use]
    pub fn from_hex(value: &str) -> Option<Self> {
        if value.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(Self(bytes))
    }
}

#[must_use]
pub fn wall_ms_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis().try_into().unwrap_or(u64::MAX))
}
