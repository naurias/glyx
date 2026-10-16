use std::collections::BTreeMap;
use std::io::Read;

use anyhow::{Context, Result};

pub fn url_host(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit('@').next().unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host);
    let host = host.strip_suffix('.').unwrap_or(host).to_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

pub fn host_matches(item_host: &str, query: &str) -> bool {
    let item = item_host.to_lowercase();
    let query = query.to_lowercase();
    item == query || item.ends_with(&format!(".{query}"))
}

pub fn read_credential_input() -> Result<BTreeMap<String, String>> {
    let mut text = String::new();
    std::io::stdin().read_to_string(&mut text)?;
    let mut out = BTreeMap::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once('=') {
            out.insert(k.trim().to_owned(), v.trim().to_owned());
        }
    }
    Ok(out)
}

pub fn find_login(
    uv: &glyx_store::UnlockedVault,
    host: &str,
    username: Option<&str>,
) -> Result<Option<glyx_core::Item>> {
    let mut best: Option<(bool, glyx_core::Item)> = None;
    for row in uv.list(false)? {
        if row.item_type != "login" {
            continue;
        }
        let Some(item) = uv.get_item(&row.id)? else {
            continue;
        };
        let Some(url) = item.fields.get("url").map(|f| f.value.expose().to_owned()) else {
            continue;
        };
        let Some(item_host) = url_host(&url) else {
            continue;
        };
        if !host_matches(&item_host, host) {
            continue;
        }
        let user_ok = username.is_none_or(|u| {
            item.fields
                .get("username")
                .is_some_and(|f| f.value.expose() == u)
        });
        let exact = username.is_some_and(|u| {
            item.fields
                .get("username")
                .is_some_and(|f| f.value.expose() == u)
        });
        if !user_ok && username.is_some() {
            continue;
        }
        let replace = match &best {
            None => true,
            Some((best_exact, _)) => exact && !best_exact,
        };
        if replace {
            best = Some((exact, item));
        }
    }
    Ok(best.map(|(_, item)| item))
}

pub fn cmd_get(uv: &mut glyx_store::UnlockedVault, input: &BTreeMap<String, String>) -> Result<()> {
    let host = input.get("host").context("git did not send host")?;
    let username = input.get("username").map(String::as_str);
    if let Some(item) = find_login(uv, host, username)? {
        if let Some(user) = item.fields.get("username") {
            println!("username={}", user.value.expose());
        }
        if let Some(pass) = item.fields.get("password") {
            println!("password={}", pass.value.expose());
        }
    }
    Ok(())
}

pub fn cmd_store(
    uv: &mut glyx_store::UnlockedVault,
    input: &BTreeMap<String, String>,
) -> Result<()> {
    let host = input.get("host").context("git did not send host")?;
    let username = input.get("username").context("git did not send username")?;
    let password = input.get("password").context("git did not send password")?;
    let protocol = input.get("protocol").map_or("https", String::as_str);
    if let Some(mut item) = find_login(uv, host, Some(username))? {
        let mut values = BTreeMap::new();
        values.insert("password".to_owned(), password.clone());
        glyx_store::present::apply_fields(uv, &mut item, values)?;
        uv.put_item(&item)?;
        return Ok(());
    }
    let hlc = uv.next_hlc()?;
    let node = uv.device_node();
    let mut fields = BTreeMap::new();
    for (k, v) in [
        ("username", username.clone()),
        ("password", password.clone()),
        ("url", format!("{protocol}://{host}")),
    ] {
        fields.insert(
            k.to_owned(),
            glyx_core::Field {
                value: glyx_core::SecretString::new(v),
                field_hlc: hlc,
            },
        );
    }
    uv.put_item(&glyx_core::Item {
        id: uuid::Uuid::now_v7(),
        item_type: glyx_core::ItemType::Login,
        name: host.clone(),
        folder: String::new(),
        tags: Vec::new(),
        fields,
        hlc,
        rev: 1,
        deleted: false,
        updated_by: node,
    })?;
    Ok(())
}

pub fn cmd_erase(
    uv: &mut glyx_store::UnlockedVault,
    input: &BTreeMap<String, String>,
) -> Result<()> {
    let host = input.get("host").context("git did not send host")?;
    let username = input.get("username").map(String::as_str);
    if let Some(item) = find_login(uv, host, username)? {
        uv.delete_item(&item.id)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_parsing() {
        assert_eq!(
            url_host("https://github.com/a/b"),
            Some("github.com".to_owned())
        );
        assert_eq!(
            url_host("git@github.com:user/repo"),
            Some("github.com".to_owned())
        );
        assert_eq!(
            url_host("https://user@host.example:8443/x"),
            Some("host.example".to_owned())
        );
        assert!(url_host("").is_none());
        assert!(host_matches("api.github.com", "github.com"));
        assert!(!host_matches("github.com.evil.com", "github.com"));
        assert!(host_matches("GitHub.COM", "github.com"));
    }
}
