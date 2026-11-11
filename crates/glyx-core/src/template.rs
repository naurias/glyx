use super::ItemType;

#[derive(Debug, Clone, Copy)]
pub struct FieldSpec {
    pub name: &'static str,
    pub secret: bool,
    pub required: bool,
}

const LOGIN: &[FieldSpec] = &[
    FieldSpec {
        name: "username",
        secret: false,
        required: true,
    },
    FieldSpec {
        name: "password",
        secret: true,
        required: true,
    },
    FieldSpec {
        name: "url",
        secret: false,
        required: false,
    },
    FieldSpec {
        name: "package",
        secret: false,
        required: false,
    },
    FieldSpec {
        name: "notes",
        secret: false,
        required: false,
    },
    FieldSpec {
        name: "seed",
        secret: true,
        required: false,
    },
    FieldSpec {
        name: "digits",
        secret: false,
        required: false,
    },
    FieldSpec {
        name: "period",
        secret: false,
        required: false,
    },
];

const PASSKEY: &[FieldSpec] = &[
    FieldSpec {
        name: "relying_party",
        secret: false,
        required: true,
    },
    FieldSpec {
        name: "rp_name",
        secret: false,
        required: false,
    },
    FieldSpec {
        name: "user_handle",
        secret: false,
        required: true,
    },
    FieldSpec {
        name: "user_name",
        secret: false,
        required: false,
    },
    FieldSpec {
        name: "display_name",
        secret: false,
        required: false,
    },
    FieldSpec {
        name: "credential_id",
        secret: true,
        required: true,
    },
    FieldSpec {
        name: "private_key",
        secret: true,
        required: false,
    },
    FieldSpec {
        name: "algorithm",
        secret: false,
        required: false,
    },
    FieldSpec {
        name: "sign_count",
        secret: false,
        required: false,
    },
    FieldSpec {
        name: "discoverable",
        secret: false,
        required: false,
    },
    FieldSpec {
        name: "backup_eligible",
        secret: false,
        required: false,
    },
    FieldSpec {
        name: "backup_state",
        secret: false,
        required: false,
    },
    FieldSpec {
        name: "aaguid",
        secret: false,
        required: false,
    },
    FieldSpec {
        name: "created_ms",
        secret: false,
        required: false,
    },
    FieldSpec {
        name: "last_used_ms",
        secret: false,
        required: false,
    },
    FieldSpec {
        name: "transports",
        secret: false,
        required: false,
    },
    FieldSpec {
        name: "login_id",
        secret: false,
        required: false,
    },
];

const TOTP: &[FieldSpec] = &[
    FieldSpec {
        name: "seed",
        secret: true,
        required: true,
    },
    FieldSpec {
        name: "digits",
        secret: false,
        required: false,
    },
    FieldSpec {
        name: "period",
        secret: false,
        required: false,
    },
    FieldSpec {
        name: "login_id",
        secret: false,
        required: false,
    },
];

const IDENTITY: &[FieldSpec] = &[
    FieldSpec {
        name: "full_name",
        secret: false,
        required: true,
    },
    FieldSpec {
        name: "email",
        secret: false,
        required: false,
    },
    FieldSpec {
        name: "phone",
        secret: false,
        required: false,
    },
    FieldSpec {
        name: "address",
        secret: false,
        required: false,
    },
];

const CARD: &[FieldSpec] = &[
    FieldSpec {
        name: "number",
        secret: true,
        required: true,
    },
    FieldSpec {
        name: "holder",
        secret: false,
        required: true,
    },
    FieldSpec {
        name: "expiry",
        secret: false,
        required: true,
    },
    FieldSpec {
        name: "cvc",
        secret: true,
        required: true,
    },
];

const NOTE: &[FieldSpec] = &[FieldSpec {
    name: "body",
    secret: false,
    required: true,
}];

const FILE: &[FieldSpec] = &[
    FieldSpec {
        name: "blob",
        secret: false,
        required: true,
    },
    FieldSpec {
        name: "filename",
        secret: false,
        required: false,
    },
];

const SSH_KEY: &[FieldSpec] = &[
    FieldSpec {
        name: "private",
        secret: true,
        required: true,
    },
    FieldSpec {
        name: "public",
        secret: false,
        required: true,
    },
    FieldSpec {
        name: "comment",
        secret: false,
        required: false,
    },
    FieldSpec {
        name: "agent_enabled",
        secret: false,
        required: false,
    },
];

const GENERIC_KEY: &[FieldSpec] = &[
    FieldSpec {
        name: "material",
        secret: true,
        required: true,
    },
    FieldSpec {
        name: "kind",
        secret: false,
        required: false,
    },
];

const POINTER: &[FieldSpec] = &[];

#[must_use]
pub fn spec(item_type: ItemType) -> &'static [FieldSpec] {
    match item_type {
        ItemType::Login => LOGIN,
        ItemType::Passkey => PASSKEY,
        ItemType::Totp => TOTP,
        ItemType::Identity => IDENTITY,
        ItemType::Card => CARD,
        ItemType::Note => NOTE,
        ItemType::File => FILE,
        ItemType::SshKey => SSH_KEY,
        ItemType::GenericKey => GENERIC_KEY,
        ItemType::Pointer => POINTER,
    }
}

pub const ALL_TYPES: [ItemType; 10] = [
    ItemType::Login,
    ItemType::Passkey,
    ItemType::Totp,
    ItemType::Identity,
    ItemType::Card,
    ItemType::Note,
    ItemType::File,
    ItemType::SshKey,
    ItemType::GenericKey,
    ItemType::Pointer,
];

pub fn parse_type(text: &str) -> Result<ItemType, super::CoreError> {
    match text {
        "login" => Ok(ItemType::Login),
        "passkey" => Ok(ItemType::Passkey),
        "totp" => Ok(ItemType::Totp),
        "identity" => Ok(ItemType::Identity),
        "card" => Ok(ItemType::Card),
        "note" => Ok(ItemType::Note),
        "file" => Ok(ItemType::File),
        "ssh_key" | "ssh-key" | "sshkey" => Ok(ItemType::SshKey),
        "generic_key" | "generic-key" | "key" => Ok(ItemType::GenericKey),
        "pointer" | "ptr" => Ok(ItemType::Pointer),
        other => Err(super::CoreError::UnknownItemType(other.to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_type_has_no_required_template_fields() {
        assert!(spec(ItemType::Pointer).is_empty());
        assert_eq!(parse_type("pointer").expect("parse"), ItemType::Pointer);
        assert_eq!(parse_type("ptr").expect("parse"), ItemType::Pointer);
        assert!(ALL_TYPES.contains(&ItemType::Pointer));
    }
}
