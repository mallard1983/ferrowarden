use super::*;

fn client_for(url: &str) -> FerroClient {
    let config = Config::from_lookup(|name| {
        Ok(match name {
            "FERROWARDEN_URL" => Some(url.to_string()),
            "FERROWARDEN_AGENT_KEY" => Some("KEY0123456789".to_string()),
            _ => None,
        })
    })
    .unwrap();
    FerroClient::new(&config).unwrap()
}

#[test]
fn endpoints_have_no_double_slash_with_or_without_a_prefix() {
    let bare = client_for("https://f.example.com/");
    assert_eq!(
        bare.endpoint("/v1/credentials", Some("detail=true"))
            .as_str(),
        "https://f.example.com/v1/credentials?detail=true"
    );
    let prefixed = client_for("https://f.example.com/pfx/");
    assert_eq!(
        prefixed.endpoint("/v1/forward", None).as_str(),
        "https://f.example.com/pfx/v1/forward"
    );
}
