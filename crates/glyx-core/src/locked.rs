use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LockedForm {
    Ref,
    EncryptedPointer,
    MaskedShape,
}

#[must_use]
pub fn ref_placeholder(item_id: &Uuid, field: &str) -> String {
    format!("{{{{glyx:{item_id}/{field}}}}}")
}

#[must_use]
pub fn parse_ref_placeholder(text: &str) -> Option<(Uuid, String)> {
    let text = text.trim();
    let inner = text.strip_prefix("{{glyx:")?.strip_suffix("}}")?;
    let (id, field) = inner.split_once('/')?;
    let id = id.parse::<Uuid>().ok()?;
    if field.is_empty() || field.contains(['{', '}', '/', ' ', '\n', '\r', '\t']) {
        return None;
    }
    Some((id, field.to_owned()))
}

#[must_use]
pub fn masked_fallback(field: &str) -> String {
    format!("__GLYXSEC:{field}__")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_rejects_ref_placeholders() {
        let id = Uuid::now_v7();
        let text = ref_placeholder(&id, "password");
        assert_eq!(
            parse_ref_placeholder(&text),
            Some((id, "password".to_owned()))
        );
        assert_eq!(parse_ref_placeholder("  "), None);
        assert_eq!(parse_ref_placeholder("{{glyx:not-a-uuid/password}}"), None);
        assert_eq!(parse_ref_placeholder(&format!("{{{{glyx:{id}/}}}}")), None);
        assert_eq!(
            parse_ref_placeholder(&format!("{{{{glyx:{id}/a b}}}}")),
            None
        );
    }
}
