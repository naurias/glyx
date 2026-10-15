use std::time::{SystemTime, UNIX_EPOCH};

use crate::CryptoError;

pub struct TotpParams {
    pub seed: Vec<u8>,
    pub step: u64,
    pub digits: usize,
}

impl std::fmt::Debug for TotpParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpParams")
            .field("seed", &"[redacted]")
            .field("step", &self.step)
            .field("digits", &self.digits)
            .finish()
    }
}

pub fn params_from_uri(url: &str) -> Result<TotpParams, CryptoError> {
    let bad = |why: &str| CryptoError::Param(format!("bad otpauth url: {why}"));
    let query = url.split('?').nth(1).ok_or_else(|| bad("missing query"))?;
    let mut seed = None;
    let mut step = 30u64;
    let mut digits = 6usize;
    for pair in query.split('&') {
        if let Some(v) = pair.strip_prefix("secret=") {
            seed = Some(
                totp_rs::Secret::Encoded(v.to_uppercase().replace(' ', ""))
                    .to_bytes()
                    .map_err(|_| bad("bad secret"))?,
            );
        } else if let Some(v) = pair.strip_prefix("period=") {
            step = v.parse().map_err(|_| bad("bad period"))?;
        } else if let Some(v) = pair.strip_prefix("digits=") {
            digits = v.parse().map_err(|_| bad("bad digits"))?;
        } else if let Some(v) = pair.strip_prefix("algorithm=") {
            if !v.eq_ignore_ascii_case("SHA1") {
                return Err(bad("only SHA1 in M1"));
            }
        }
    }
    Ok(TotpParams {
        seed: seed.ok_or_else(|| bad("no secret"))?,
        step,
        digits,
    })
}

pub fn seed_from_b32(text: &str) -> Result<Vec<u8>, CryptoError> {
    totp_rs::Secret::Encoded(text.to_uppercase().replace(' ', ""))
        .to_bytes()
        .map_err(|e| CryptoError::Param(e.to_string()))
}

fn build(params: &TotpParams) -> Result<totp_rs::TOTP, CryptoError> {
    totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        params.digits,
        1,
        params.step,
        params.seed.clone(),
        None,
        String::new(),
    )
    .map_err(|e| CryptoError::Param(e.to_string()))
}

pub fn generate_code(params: &TotpParams) -> Result<String, CryptoError> {
    build(params)?
        .generate_current()
        .map_err(|e| CryptoError::Param(e.to_string()))
}

pub fn generate_at(params: &TotpParams, unix_secs: u64) -> Result<String, CryptoError> {
    Ok(build(params)?.generate(unix_secs))
}

pub fn verify_code(params: &TotpParams, code: &str) -> Result<bool, CryptoError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| CryptoError::Param(e.to_string()))?
        .as_secs();
    let totp = build(params)?;
    let window = i64::try_from(params.step).unwrap_or(i64::MAX);
    for skew in [0i64, -1, 1] {
        let t = now.saturating_add_signed(skew.saturating_mul(window));
        if totp.generate(t) == code {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rfc_params() -> TotpParams {
        TotpParams {
            seed: b"12345678901234567890".to_vec(),
            step: 30,
            digits: 8,
        }
    }

    #[test]
    fn rfc6238_vector() {
        assert_eq!(generate_at(&rfc_params(), 59).expect("code"), "94287082");
        assert_eq!(
            generate_at(&rfc_params(), 1_111_111_109).expect("code"),
            "07081804"
        );
    }

    #[test]
    fn otpauth_parsing() {
        let p = params_from_uri(
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&period=30&digits=6",
        )
        .expect("parses");
        assert_eq!(p.seed.len(), 20);
        assert_eq!(p.step, 30);
        assert_eq!(p.digits, 6);
        assert!(params_from_uri("otpauth://totp/x?period=30").is_err());
    }

    #[test]
    fn verify_roundtrip() {
        let p = TotpParams {
            seed: b"12345678901234567890".to_vec(),
            step: 30,
            digits: 6,
        };
        let code = generate_code(&p).expect("code");
        assert!(verify_code(&p, &code).expect("verifies"));
        assert!(!verify_code(&p, "000000").expect("rejects") || code == "000000");
    }
}
