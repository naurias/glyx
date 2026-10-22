use serde::{Deserialize, Serialize};

use crate::CryptoError;

pub const PASSWORD_ALPHABET: &str =
    "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789!@#$%^&*-_+=";

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 24,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: true,
        }
    }
}

fn class_chars(options: &PasswordOptions) -> Vec<&'static str> {
    let mut classes = Vec::new();
    if options.lowercase {
        classes.push(if options.exclude_ambiguous {
            "abcdefghjkmnpqrstuvwxyz"
        } else {
            "abcdefghijklmnopqrstuvwxyz"
        });
    }
    if options.uppercase {
        classes.push(if options.exclude_ambiguous {
            "ABCDEFGHJKMNPQRSTUVWXYZ"
        } else {
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        });
    }
    if options.digits {
        classes.push(if options.exclude_ambiguous {
            "23456789"
        } else {
            "0123456789"
        });
    }
    if options.symbols {
        classes.push("!@#$%^&*-_+=");
    }
    classes
}

fn random_index(len: usize) -> Result<usize, CryptoError> {
    let len_u32 =
        u32::try_from(len).map_err(|_| CryptoError::Param("alphabet too large".into()))?;
    let limit = u32::MAX - (u32::MAX % len_u32);
    loop {
        let mut bytes = [0u8; 4];
        crate::rand::fill_random(&mut bytes)?;
        let value = u32::from_le_bytes(bytes);
        if value < limit {
            return Ok((value % len_u32) as usize);
        }
    }
}

pub fn generate_with_options(options: PasswordOptions) -> Result<String, CryptoError> {
    if options.length == 0 || options.length > 1024 {
        return Err(CryptoError::Param(
            "password length must be 1..=1024".into(),
        ));
    }
    let classes = class_chars(&options);
    if classes.is_empty() {
        return Err(CryptoError::Param(
            "select at least one character class".into(),
        ));
    }
    if options.length < classes.len() {
        return Err(CryptoError::Param(
            "password is shorter than the selected character classes".into(),
        ));
    }
    let union: Vec<char> = classes.iter().flat_map(|class| class.chars()).collect();
    let mut chars = Vec::with_capacity(options.length);
    for class in &classes {
        let class: Vec<char> = class.chars().collect();
        chars.push(class[random_index(class.len())?]);
    }
    while chars.len() < options.length {
        chars.push(union[random_index(union.len())?]);
    }
    for i in (1..chars.len()).rev() {
        let j = random_index(i + 1)?;
        chars.swap(i, j);
    }
    Ok(chars.into_iter().collect())
}

pub fn generate_password(len: usize) -> Result<String, CryptoError> {
    generate_with_options(PasswordOptions {
        length: len,
        ..PasswordOptions::default()
    })
}

#[must_use]
pub fn password_entropy_bits(options: &PasswordOptions) -> f64 {
    let classes = class_chars(options);
    let charset: usize = classes.iter().map(|class| class.chars().count()).sum();
    if charset == 0 {
        return 0.0;
    }
    let length = f64::from(u32::try_from(options.length).unwrap_or(u32::MAX));
    let charset = f64::from(u32::try_from(charset).unwrap_or(u32::MAX));
    length * charset.log2()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_shape() {
        let pw = generate_password(24).expect("generates");
        assert_eq!(pw.len(), 24);
        assert!(pw
            .bytes()
            .all(|b| PASSWORD_ALPHABET.as_bytes().contains(&b)));
        assert!(generate_password(0).is_err());
    }

    #[test]
    fn selected_classes_are_guaranteed() {
        let options = PasswordOptions {
            length: 16,
            lowercase: true,
            uppercase: false,
            digits: true,
            symbols: false,
            exclude_ambiguous: true,
        };
        let pw = generate_with_options(options).expect("generates");
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
        assert!(!pw.chars().any(|c| c.is_ascii_uppercase()));
        assert!(!pw.chars().any(|c| "!@#$%^&*-_+=".contains(c)));
        assert!(generate_with_options(PasswordOptions {
            length: 1,
            lowercase: true,
            uppercase: true,
            digits: false,
            symbols: false,
            exclude_ambiguous: true,
        })
        .is_err());
        assert!(generate_with_options(PasswordOptions {
            length: 8,
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            exclude_ambiguous: true,
        })
        .is_err());
    }
}
