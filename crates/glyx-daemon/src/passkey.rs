use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ciborium::value::Value as CborValue;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use p256::pkcs8::EncodePublicKey as _;
use p256::SecretKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::Zeroize as _;

use glyx_core::{Item, ItemType};

const AAGUID: [u8; 16] = *b"glyx-passkey-v1\0";

#[derive(Debug, thiserror::Error)]
pub enum PasskeyError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    NotAllowed(String),
    #[error("{0}")]
    InvalidState(String),
    #[error("{0}")]
    NotSupported(String),
    #[error("{0}")]
    Security(String),
}

impl PasskeyError {
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "TypeError",
            Self::NotAllowed(_) => "NotAllowedError",
            Self::InvalidState(_) => "InvalidStateError",
            Self::NotSupported(_) => "NotSupportedError",
            Self::Security(_) => "SecurityError",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CreationOptions {
    pub origin: String,
    pub rp_id: String,
    pub rp_name: String,
    pub user_handle: String,
    pub user_name: String,
    pub display_name: String,
    pub challenge: String,
    pub user_verification: String,
    pub discoverable: bool,
    pub exclude_credentials: Vec<String>,
    pub cred_props: bool,
}

#[derive(Debug, Clone)]
pub struct AssertionOptions {
    pub origin: String,
    pub rp_id: String,
    pub challenge: String,
    pub user_verification: String,
    pub allow_credentials: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CreatedPasskey {
    pub response: Value,
    pub private_key: String,
    pub credential_id: String,
    pub aaguid: String,
    pub discoverable: bool,
    pub rp_id: String,
    pub rp_name: String,
    pub user_handle: String,
    pub user_name: String,
    pub display_name: String,
    pub user_verified: bool,
}

#[derive(Debug, Clone)]
pub struct Assertion {
    pub response: Value,
    pub rp_id: String,
    pub user_verified: bool,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, serde::Serialize)]
pub struct PasskeyMetadata {
    pub item_id: String,
    pub name: String,
    pub rp_id: String,
    pub rp_name: String,
    pub user_name: String,
    pub display_name: String,
    pub credential_id: String,
    pub algorithm: String,
    pub sign_count: u64,
    pub aaguid: String,
    pub transports: String,
    pub discoverable: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub created_ms: u64,
    pub last_used_ms: u64,
    pub usable: bool,
}

#[derive(Debug)]
struct OriginInfo {
    origin: String,
    host: String,
}

#[allow(clippy::too_many_lines)]
pub fn parse_creation(options: &Value, origin: &str) -> Result<CreationOptions, PasskeyError> {
    let info = parse_origin(origin)?;
    let rp = options
        .get("rp")
        .and_then(Value::as_object)
        .ok_or_else(|| PasskeyError::BadRequest("missing rp".into()))?;
    let rp_id_raw = rp.get("id").and_then(Value::as_str);
    let rp_id = validate_rp_id(&info.host, rp_id_raw.unwrap_or(&info.host))?;
    let rp_name = rp
        .get("name")
        .and_then(Value::as_str)
        .filter(|v| !v.trim().is_empty())
        .unwrap_or(&rp_id)
        .to_owned();
    let user = options
        .get("user")
        .and_then(Value::as_object)
        .ok_or_else(|| PasskeyError::BadRequest("missing user".into()))?;
    let user_handle = user
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| PasskeyError::BadRequest("missing user.id".into()))?;
    decode_b64(user_handle)?;
    let user_name = user
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let display_name = user
        .get("displayName")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let challenge = options
        .get("challenge")
        .and_then(Value::as_str)
        .ok_or_else(|| PasskeyError::BadRequest("missing challenge".into()))?;
    decode_b64(challenge)?;
    let params = options
        .get("pubKeyCredParams")
        .and_then(Value::as_array)
        .ok_or_else(|| PasskeyError::BadRequest("missing pubKeyCredParams".into()))?;
    let supports_es256 = params.iter().any(|param| {
        param.get("type").and_then(Value::as_str) == Some("public-key")
            && param.get("alg").and_then(Value::as_i64) == Some(-7)
    });
    if !supports_es256 {
        return Err(PasskeyError::NotSupported(
            "this authenticator supports ES256 only".into(),
        ));
    }
    let selection = options.get("authenticatorSelection");
    let attachment = selection
        .and_then(|v| v.get("authenticatorAttachment"))
        .and_then(Value::as_str);
    if attachment == Some("cross-platform") {
        return Err(PasskeyError::NotAllowed(
            "this authenticator is platform-bound".into(),
        ));
    }
    let require_resident = selection
        .and_then(|v| v.get("requireResidentKey"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let resident_key = selection
        .and_then(|v| v.get("residentKey"))
        .and_then(Value::as_str)
        .unwrap_or(if require_resident {
            "required"
        } else {
            "preferred"
        });
    let discoverable = require_resident || resident_key != "discouraged";
    let user_verification = selection
        .and_then(|v| v.get("userVerification"))
        .and_then(Value::as_str)
        .unwrap_or("preferred")
        .to_owned();
    let exclude_credentials = options
        .get("excludeCredentials")
        .and_then(Value::as_array)
        .map_or_else(Vec::new, |items| {
            items
                .iter()
                .filter_map(|item| item.get("id").and_then(Value::as_str))
                .filter(|id| decode_b64(id).is_ok())
                .map(ToOwned::to_owned)
                .collect()
        });
    let cred_props = options
        .get("extensions")
        .and_then(|v| v.get("credProps"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok(CreationOptions {
        origin: info.origin,
        rp_id,
        rp_name,
        user_handle: user_handle.to_owned(),
        user_name,
        display_name,
        challenge: challenge.to_owned(),
        user_verification,
        discoverable,
        exclude_credentials,
        cred_props,
    })
}

pub fn parse_assertion(options: &Value, origin: &str) -> Result<AssertionOptions, PasskeyError> {
    let info = parse_origin(origin)?;
    let rp_id_raw = options.get("rpId").and_then(Value::as_str);
    let rp_id = validate_rp_id(&info.host, rp_id_raw.unwrap_or(&info.host))?;
    let challenge = options
        .get("challenge")
        .and_then(Value::as_str)
        .ok_or_else(|| PasskeyError::BadRequest("missing challenge".into()))?;
    decode_b64(challenge)?;
    let user_verification = options
        .get("userVerification")
        .and_then(Value::as_str)
        .unwrap_or("preferred")
        .to_owned();
    let allow_credentials = options
        .get("allowCredentials")
        .and_then(Value::as_array)
        .map_or_else(Vec::new, |items| {
            items
                .iter()
                .filter_map(|item| item.get("id").and_then(Value::as_str))
                .filter(|id| decode_b64(id).is_ok())
                .map(ToOwned::to_owned)
                .collect()
        });
    Ok(AssertionOptions {
        origin: info.origin,
        rp_id,
        challenge: challenge.to_owned(),
        user_verification,
        allow_credentials,
    })
}

pub fn create_credential(
    options: &CreationOptions,
    user_verified: bool,
) -> Result<CreatedPasskey, PasskeyError> {
    if options.user_verification == "required" && !user_verified {
        return Err(PasskeyError::NotAllowed(
            "user verification is required".into(),
        ));
    }
    let mut secret_bytes = [0u8; 32];
    let secret = loop {
        glyx_crypto::fill_random(&mut secret_bytes)
            .map_err(|e| PasskeyError::BadRequest(e.to_string()))?;
        if let Ok(secret) = SecretKey::from_slice(&secret_bytes) {
            break secret;
        }
    };
    secret_bytes.zeroize();
    let mut credential_id_bytes = [0u8; 32];
    glyx_crypto::fill_random(&mut credential_id_bytes)
        .map_err(|e| PasskeyError::BadRequest(e.to_string()))?;
    let credential_id = encode_b64(&credential_id_bytes);
    let public = secret.public_key();
    let point = public.to_encoded_point(false);
    let x = point
        .x()
        .ok_or_else(|| PasskeyError::BadRequest("bad public key".into()))?;
    let y = point
        .y()
        .ok_or_else(|| PasskeyError::BadRequest("bad public key".into()))?;
    let cose = cose_key(x.as_slice(), y.as_slice())?;
    let public_key_der = public
        .to_public_key_der()
        .map_err(|e| PasskeyError::BadRequest(e.to_string()))?;
    let client_data = client_data("webauthn.create", &options.challenge, &options.origin)?;
    let mut flags = 0x01 | 0x08 | 0x10 | 0x40;
    if user_verified {
        flags |= 0x04;
    }
    let auth_data = creation_auth_data(&options.rp_id, flags, &credential_id_bytes, &cose);
    let attestation = attestation_object(&auth_data)?;
    let response = json!({
        "id": credential_id,
        "rawId": credential_id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": {
            "clientDataJSON": encode_b64(&client_data),
            "attestationObject": encode_b64(&attestation),
            "authenticatorData": encode_b64(&auth_data),
            "publicKey": encode_b64(public_key_der.as_bytes()),
            "transports": ["internal"],
            "publicKeyAlgorithm": -7
        },
        "clientExtensionResults": if options.cred_props {
            json!({"credProps": {"rk": options.discoverable}})
        } else {
            json!({})
        }
    });
    Ok(CreatedPasskey {
        response,
        private_key: encode_b64(&secret.to_bytes()),
        credential_id,
        aaguid: encode_b64(&AAGUID),
        discoverable: options.discoverable,
        rp_id: options.rp_id.clone(),
        rp_name: options.rp_name.clone(),
        user_handle: options.user_handle.clone(),
        user_name: options.user_name.clone(),
        display_name: options.display_name.clone(),
        user_verified,
    })
}

pub fn assert_credential(
    options: &AssertionOptions,
    item: &Item,
    user_verified: bool,
) -> Result<Assertion, PasskeyError> {
    if options.user_verification == "required" && !user_verified {
        return Err(PasskeyError::NotAllowed(
            "user verification is required".into(),
        ));
    }
    let field = |name: &str| item.fields.get(name).map(|f| f.value.expose());
    let rp_id = field("relying_party")
        .ok_or_else(|| PasskeyError::NotAllowed("passkey has no relying party".into()))?;
    if rp_id != options.rp_id {
        return Err(PasskeyError::NotAllowed(
            "passkey relying party does not match".into(),
        ));
    }
    let credential_id = field("credential_id")
        .ok_or_else(|| PasskeyError::NotAllowed("passkey has no credential id".into()))?;
    let private_key = field("private_key")
        .ok_or_else(|| PasskeyError::NotAllowed("passkey has no private key".into()))?;
    let user_handle = field("user_handle")
        .ok_or_else(|| PasskeyError::NotAllowed("passkey has no user handle".into()))?;
    let mut secret_bytes = decode_b64(private_key)?;
    let secret = SecretKey::from_slice(&secret_bytes)
        .map_err(|_| PasskeyError::NotAllowed("passkey private key is invalid".into()))?;
    secret_bytes.zeroize();
    let signing_key = SigningKey::from(&secret);
    let client_data = client_data("webauthn.get", &options.challenge, &options.origin)?;
    let client_hash = Sha256::digest(&client_data);
    let backup_eligible = field("backup_eligible")
        .and_then(parse_bool)
        .unwrap_or(true);
    let backup_state = field("backup_state").and_then(parse_bool).unwrap_or(true);
    let mut flags = 0x01;
    if user_verified {
        flags |= 0x04;
    }
    if backup_eligible {
        flags |= 0x08;
    }
    if backup_state {
        flags |= 0x10;
    }
    let auth_data = assertion_auth_data(&options.rp_id, flags);
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&client_hash);
    let signature: Signature = signing_key.sign(&signed);
    let der = signature.to_der();
    let response = json!({
        "id": credential_id,
        "rawId": credential_id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": {
            "clientDataJSON": encode_b64(&client_data),
            "authenticatorData": encode_b64(&auth_data),
            "signature": encode_b64(der.as_bytes()),
            "userHandle": if user_handle.is_empty() {
                Value::Null
            } else {
                Value::String(user_handle.to_owned())
            }
        },
        "clientExtensionResults": {}
    });
    Ok(Assertion {
        response,
        rp_id: options.rp_id.clone(),
        user_verified,
    })
}

#[must_use]
pub fn metadata(item: &Item) -> Option<PasskeyMetadata> {
    if item.item_type != ItemType::Passkey {
        return None;
    }
    let field = |name: &str| item.fields.get(name).map(|f| f.value.expose().to_owned());
    let rp_id = field("relying_party").unwrap_or_default();
    let rp_name = field("rp_name")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| rp_id.clone());
    let user_name = field("user_name").unwrap_or_default();
    let display_name = field("display_name").unwrap_or_default();
    let credential_id = field("credential_id").unwrap_or_default();
    let private_key = field("private_key").unwrap_or_default();
    let algorithm = field("algorithm").unwrap_or_else(|| "ES256".to_owned());
    let sign_count = field("sign_count")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let aaguid = field("aaguid").unwrap_or_default();
    let transports = field("transports").unwrap_or_default();
    let discoverable = field("discoverable")
        .and_then(|v| parse_bool(&v))
        .unwrap_or(true);
    let backup_eligible = field("backup_eligible")
        .and_then(|v| parse_bool(&v))
        .unwrap_or(true);
    let backup_state = field("backup_state")
        .and_then(|v| parse_bool(&v))
        .unwrap_or(true);
    let created_ms = field("created_ms")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let last_used_ms = field("last_used_ms")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    Some(PasskeyMetadata {
        item_id: item.id.to_string(),
        name: item.name.clone(),
        rp_id,
        rp_name,
        user_name,
        display_name,
        credential_id,
        algorithm,
        sign_count,
        aaguid,
        transports,
        discoverable,
        backup_eligible,
        backup_state,
        created_ms,
        last_used_ms,
        usable: !private_key.is_empty(),
    })
}

#[must_use]
pub fn lookup(items: &[Item], rp_id: &str, allow_credentials: &[String]) -> Vec<PasskeyMetadata> {
    let mut out = Vec::new();
    for item in items {
        let Some(meta) = metadata(item) else {
            continue;
        };
        if meta.rp_id != rp_id {
            continue;
        }
        if !allow_credentials.is_empty()
            && !allow_credentials
                .iter()
                .any(|id| credential_id_eq(id, &meta.credential_id))
        {
            continue;
        }
        if allow_credentials.is_empty() && !meta.discoverable {
            continue;
        }
        out.push(meta);
    }
    out.sort_by(|a, b| {
        b.last_used_ms
            .cmp(&a.last_used_ms)
            .then_with(|| a.name.cmp(&b.name))
    });
    out
}

/// Compare two base64url credential ids by their decoded bytes so that
/// padded and unpadded encodings of the same id match.
#[must_use]
pub fn credential_id_eq(left: &str, right: &str) -> bool {
    match (decode_b64(left), decode_b64(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

pub fn validate_origin_rp(origin: &str, rp_id: &str) -> Result<String, PasskeyError> {
    let info = parse_origin(origin)?;
    validate_rp_id(&info.host, rp_id)
}

fn parse_origin(origin: &str) -> Result<OriginInfo, PasskeyError> {
    let parsed = Url::parse(origin).map_err(|_| PasskeyError::Security("invalid origin".into()))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| PasskeyError::Security("origin has no host".into()))?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let local = host == "localhost" || host == "127.0.0.1";
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && local) {
        return Err(PasskeyError::Security(
            "WebAuthn requires https or localhost".into(),
        ));
    }
    Ok(OriginInfo {
        origin: parsed.origin().ascii_serialization(),
        host,
    })
}

fn validate_rp_id(origin_host: &str, rp_id: &str) -> Result<String, PasskeyError> {
    let rp_id = rp_id.trim_end_matches('.').to_ascii_lowercase();
    if rp_id.is_empty() {
        return Err(PasskeyError::Security("empty rp id".into()));
    }
    if rp_id != origin_host && !origin_host.ends_with(&format!(".{rp_id}")) {
        return Err(PasskeyError::Security(
            "rp id is not a suffix of the origin host".into(),
        ));
    }
    let local = rp_id == "localhost" || rp_id.parse::<std::net::IpAddr>().is_ok();
    if !local && psl::domain_str(&rp_id).is_none() {
        return Err(PasskeyError::Security(
            "rp id is not a registrable domain".into(),
        ));
    }
    Ok(rp_id)
}

fn decode_b64(value: &str) -> Result<Vec<u8>, PasskeyError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(value))
        .map_err(|_| PasskeyError::BadRequest("invalid base64url".into()))
}

fn encode_b64(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(value)
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" => Some(false),
        _ => None,
    }
}

fn client_data(kind: &str, challenge: &str, origin: &str) -> Result<Vec<u8>, PasskeyError> {
    serde_json::to_vec(&json!({
        "type": kind,
        "challenge": challenge,
        "origin": origin,
        "crossOrigin": false
    }))
    .map_err(|e| PasskeyError::BadRequest(e.to_string()))
}

fn creation_auth_data(rp_id: &str, flags: u8, credential_id: &[u8], cose: &[u8]) -> Vec<u8> {
    let rp_hash = Sha256::digest(rp_id.as_bytes());
    let mut out = Vec::with_capacity(37 + 18 + credential_id.len() + cose.len());
    out.extend_from_slice(&rp_hash);
    out.push(flags);
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&AAGUID);
    out.extend_from_slice(
        &u16::try_from(credential_id.len())
            .unwrap_or(0)
            .to_be_bytes(),
    );
    out.extend_from_slice(credential_id);
    out.extend_from_slice(cose);
    out
}

fn assertion_auth_data(rp_id: &str, flags: u8) -> Vec<u8> {
    let rp_hash = Sha256::digest(rp_id.as_bytes());
    let mut out = Vec::with_capacity(37);
    out.extend_from_slice(&rp_hash);
    out.push(flags);
    out.extend_from_slice(&[0, 0, 0, 0]);
    out
}

fn cose_key(x: &[u8], y: &[u8]) -> Result<Vec<u8>, PasskeyError> {
    let value = CborValue::Map(vec![
        (CborValue::Integer(1.into()), CborValue::Integer(2.into())),
        (
            CborValue::Integer(3.into()),
            CborValue::Integer((-7).into()),
        ),
        (
            CborValue::Integer((-1).into()),
            CborValue::Integer(1.into()),
        ),
        (
            CborValue::Integer((-2).into()),
            CborValue::Bytes(x.to_vec()),
        ),
        (
            CborValue::Integer((-3).into()),
            CborValue::Bytes(y.to_vec()),
        ),
    ]);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&value, &mut out)
        .map_err(|e| PasskeyError::BadRequest(e.to_string()))?;
    Ok(out)
}

fn attestation_object(auth_data: &[u8]) -> Result<Vec<u8>, PasskeyError> {
    let value = CborValue::Map(vec![
        (
            CborValue::Text("fmt".into()),
            CborValue::Text("none".into()),
        ),
        (
            CborValue::Text("attStmt".into()),
            CborValue::Map(Vec::new()),
        ),
        (
            CborValue::Text("authData".into()),
            CborValue::Bytes(auth_data.to_vec()),
        ),
    ]);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&value, &mut out)
        .map_err(|e| PasskeyError::BadRequest(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier as _;
    use p256::ecdsa::VerifyingKey;
    use p256::pkcs8::DecodePublicKey as _;

    fn creation_options() -> Value {
        json!({
            "rp": {"id": "example.com", "name": "Example"},
            "user": {
                "id": "dXNlcg",
                "name": "alice@example.com",
                "displayName": "Alice"
            },
            "challenge": "Y2hhbGxlbmdl",
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "authenticatorSelection": {
                "residentKey": "required",
                "userVerification": "required"
            },
            "extensions": {"credProps": true}
        })
    }

    #[test]
    fn create_response_has_chromium_required_fields() {
        let parsed = parse_creation(&creation_options(), "https://example.com").expect("parse");
        let created = create_credential(&parsed, true).expect("create");
        let response = &created.response["response"];
        let auth_data = decode_b64(
            response["authenticatorData"]
                .as_str()
                .expect("authenticatorData"),
        )
        .expect("auth data");
        let attestation = decode_b64(
            response["attestationObject"]
                .as_str()
                .expect("attestationObject"),
        )
        .expect("attestation");
        let cbor: CborValue = ciborium::de::from_reader(attestation.as_slice()).expect("cbor");
        let CborValue::Map(fields) = cbor else {
            panic!("attestation object must be a map");
        };
        let embedded = fields
            .iter()
            .find_map(|(key, value)| (key == &CborValue::Text("authData".into())).then_some(value))
            .expect("authData in attestation");
        let CborValue::Bytes(embedded) = embedded else {
            panic!("authData must be bytes");
        };
        assert_eq!(embedded, &auth_data);

        let public_key =
            decode_b64(response["publicKey"].as_str().expect("publicKey")).expect("public key der");
        let parsed_key =
            p256::PublicKey::from_public_key_der(&public_key).expect("parse public key der");
        let secret =
            SecretKey::from_slice(&decode_b64(&created.private_key).expect("key")).expect("secret");
        assert_eq!(
            parsed_key.to_encoded_point(false),
            secret.public_key().to_encoded_point(false)
        );
        assert_eq!(response["publicKeyAlgorithm"], -7);
        assert_eq!(response["transports"][0], "internal");
        assert!(created.response["clientExtensionResults"].is_object());
    }

    #[test]
    fn credential_ids_match_across_padding() {
        assert!(credential_id_eq("AQI", "AQI="));
        assert!(!credential_id_eq("AQI", "AQM"));
    }

    #[test]
    fn create_and_assert_roundtrip() {
        let parsed = parse_creation(&creation_options(), "https://example.com").expect("parse");
        let created = create_credential(&parsed, true).expect("create");
        let attestation = decode_b64(
            created.response["response"]["attestationObject"]
                .as_str()
                .expect("attestation"),
        )
        .expect("attestation bytes");
        let cbor: CborValue = ciborium::de::from_reader(attestation.as_slice()).expect("cbor");
        let CborValue::Map(fields) = cbor else {
            panic!("attestation object must be a map");
        };
        assert!(fields.iter().any(|(key, value)| {
            key == &CborValue::Text("fmt".into()) && value == &CborValue::Text("none".into())
        }));
        let mut item = Item {
            id: uuid::Uuid::now_v7(),
            item_type: ItemType::Passkey,
            name: "example".into(),
            folder: String::new(),
            tags: Vec::new(),
            favorite: false,
            fields: std::collections::BTreeMap::new(),
            hlc: glyx_core::Hlc {
                wall_ms: 1,
                seq: 0,
                node: glyx_core::DeviceId::zero(),
            },
            rev: 1,
            deleted: false,
            updated_by: glyx_core::DeviceId::zero(),
        };
        for (key, value) in [
            ("relying_party", created.rp_id.clone()),
            ("user_handle", created.user_handle.clone()),
            ("credential_id", created.credential_id.clone()),
            ("private_key", created.private_key.clone()),
            ("backup_eligible", "true".into()),
            ("backup_state", "true".into()),
        ] {
            item.fields.insert(
                key.to_owned(),
                glyx_core::Field {
                    value: glyx_core::SecretString::new(value),
                    field_hlc: item.hlc,
                },
            );
        }
        let options = parse_assertion(
            &json!({
                "rpId": "example.com",
                "challenge": "b3RoZXItY2hhbGxlbmdl",
                "userVerification": "required",
                "allowCredentials": [{"type": "public-key", "id": created.credential_id}]
            }),
            "https://example.com",
        )
        .expect("parse assertion");
        let assertion = assert_credential(&options, &item, true).expect("assert");
        assert_eq!(assertion.response["id"], created.credential_id);
        let signature = assertion.response["response"]["signature"]
            .as_str()
            .expect("signature");
        let auth_data = assertion.response["response"]["authenticatorData"]
            .as_str()
            .expect("auth data");
        let client_data = assertion.response["response"]["clientDataJSON"]
            .as_str()
            .expect("client data");
        let secret =
            SecretKey::from_slice(&decode_b64(&created.private_key).expect("key")).expect("secret");
        let verifying = VerifyingKey::from(secret.public_key());
        let signature = Signature::from_der(&decode_b64(signature).expect("der")).expect("sig");
        let mut signed = decode_b64(auth_data).expect("auth");
        signed.extend_from_slice(&Sha256::digest(decode_b64(client_data).expect("client")));
        verifying.verify(&signed, &signature).expect("verify");

        if let Some(handle) = item.fields.get_mut("user_handle") {
            handle.value = glyx_core::SecretString::new(String::new());
        }
        let assertion = assert_credential(&options, &item, true).expect("assert empty handle");
        assert!(assertion.response["response"]["userHandle"].is_null());
    }

    #[test]
    fn rejects_wrong_origin() {
        let error =
            parse_creation(&creation_options(), "https://evil.example").expect_err("reject");
        assert!(matches!(error, PasskeyError::Security(_)));
    }

    #[test]
    fn metadata_and_lookup() {
        let parsed = parse_creation(&creation_options(), "https://example.com").expect("parse");
        let created = create_credential(&parsed, true).expect("create");
        let item = Item {
            id: uuid::Uuid::now_v7(),
            item_type: ItemType::Passkey,
            name: "example".into(),
            folder: String::new(),
            tags: Vec::new(),
            favorite: false,
            fields: [
                ("relying_party".to_owned(), created.rp_id),
                ("credential_id".to_owned(), created.credential_id.clone()),
                ("private_key".to_owned(), created.private_key),
                ("discoverable".to_owned(), "true".to_owned()),
            ]
            .into_iter()
            .map(|(key, value)| {
                (
                    key,
                    glyx_core::Field {
                        value: glyx_core::SecretString::new(value),
                        field_hlc: glyx_core::Hlc {
                            wall_ms: 1,
                            seq: 0,
                            node: glyx_core::DeviceId::zero(),
                        },
                    },
                )
            })
            .collect(),
            hlc: glyx_core::Hlc {
                wall_ms: 1,
                seq: 0,
                node: glyx_core::DeviceId::zero(),
            },
            rev: 1,
            deleted: false,
            updated_by: glyx_core::DeviceId::zero(),
        };
        let found = lookup(std::slice::from_ref(&item), "example.com", &[]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].credential_id, created.credential_id);
    }
}
