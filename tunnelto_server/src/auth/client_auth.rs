use crate::auth::reconnect_token::ReconnectTokenPayload;
use crate::auth::{AuthResult, AuthService};
use crate::{ReconnectToken, CONFIG};
use futures::{SinkExt, StreamExt};
use tracing::error;
use tunnelto_lib::{ClientHello, ClientId, ClientType, ServerHello};
use warp::filters::ws::{Message, WebSocket};

pub struct ClientHandshake {
    pub id: ClientId,
    pub sub_domain: String,
    pub is_anonymous: bool,
}

#[tracing::instrument(skip(websocket))]
pub async fn auth_client_handshake(
    mut websocket: WebSocket,
) -> Option<(WebSocket, ClientHandshake)> {
    let client_hello_data = match websocket.next().await {
        Some(Ok(msg)) => msg,
        _ => {
            error!("no client init message");
            return None;
        }
    };

    auth_client(client_hello_data.as_bytes(), websocket).await
}

#[tracing::instrument(skip(client_hello_data, websocket))]
async fn auth_client(
    client_hello_data: &[u8],
    mut websocket: WebSocket,
) -> Option<(WebSocket, ClientHandshake)> {
    // parse the client hello
    let client_hello: ClientHello = match serde_json::from_slice(client_hello_data) {
        Ok(ch) => ch,
        Err(error) => {
            error!(?error, "invalid client hello");
            let data = serde_json::to_vec(&ServerHello::AuthFailed).unwrap_or_default();
            let _ = websocket.send(Message::binary(data)).await;
            return None;
        }
    };

    let (key_to_use_for_subdomain_auth, client_id_for_handshake, actual_requested_sub_domain) = match client_hello.client_type {
        ClientType::Anonymous => {
            // Original logic for Anonymous: send AuthFailed and return.
            // Reconnect tokens for anonymous clients are handled if ClientHello has a token
            // and ClientType is Auth { key: _ } but sub_domain is None (see below) or
            // if a dedicated path for Anonymous + Token existed (which it doesn't directly here).
            // If a client sends ClientType::Anonymous, it's typically expecting a random domain or an error.
            if let Some(token) = client_hello.reconnect_token {
                // If an anonymous client sends a reconnect token, handle it.
                return handle_reconnect_token(token, websocket).await;
            }
            error!("Client sent ClientType::Anonymous without a reconnect token. This path usually expects an API key or a token.");
            let data = serde_json::to_vec(&ServerHello::AuthFailed).unwrap_or_default();
            let _ = websocket.send(Message::binary(data)).await;
            return None;
        }
        ClientType::Auth { key } => { // `key` here is tunnelto_lib::AuthKey (String wrapper)
            let raw_api_key_string = &key.0;

            // 1. Process the raw API key string using the active AuthService's `auth_key` method.
            let processed_key = match crate::AUTH_DB_SERVICE.auth_key(raw_api_key_string).await {
                Ok(pk) => pk, // pk is now of type `AUTH_DB_SERVICE::AuthKey` (String or ())
                Err(_) => {
                    error!(apiKey=%raw_api_key_string, "API key rejected by AUTH_DB_SERVICE.auth_key");
                    let data = serde_json::to_vec(&ServerHello::AuthFailed).unwrap_or_default();
                    let _ = websocket.send(Message::binary(data)).await;
                    return None;
                }
            };

            let client_id_val = key.client_id(); // Use original key for consistent client_id derivation

            match client_hello.sub_domain {
                Some(requested_sub_domain_str) => {
                    let (ws, final_sub_domain_str) = match sanitize_sub_domain_and_pre_validate(
                        websocket,
                        requested_sub_domain_str,
                        &client_id_val, // Pass client_id derived from original key
                    )
                    .await {
                        Some(s) => s,
                        None => return None, // sanitize_sub_domain_and_pre_validate sends error response
                    };
                    websocket = ws;
                    (processed_key, client_id_val, final_sub_domain_str)
                }
                None => { // No specific subdomain requested with API key
                    if let Some(token) = client_hello.reconnect_token {
                        // API key was provided, but also a reconnect token, and no specific subdomain.
                        // Prioritize reconnect token.
                        return handle_reconnect_token(token, websocket).await;
                    }
                    // Only API key, no subdomain, no token: assign a random one.
                    let final_sub_domain_str = ServerHello::random_domain();
                    (processed_key, client_id_val, final_sub_domain_str)
                }
            }
        }
    };

    tracing::info!(requested_sub_domain=%actual_requested_sub_domain, "will auth sub domain");

    // next authenticate the sub-domain
    // Pass `&key_to_use_for_subdomain_auth` which is now correctly typed (String for AuthDb, () for NoAuth).
    let sub_domain_after_auth = match crate::AUTH_DB_SERVICE
        .auth_sub_domain(&key_to_use_for_subdomain_auth, &actual_requested_sub_domain)
        .await
    {
        Ok(AuthResult::Available) | Ok(AuthResult::ReservedByYou) => actual_requested_sub_domain,
        Ok(AuthResult::ReservedByYouButDelinquent) | Ok(AuthResult::PaymentRequired) => {
            tracing::info!(requested_sub_domain=%actual_requested_sub_domain, "payment required or delinquent");
            let data = serde_json::to_vec(&ServerHello::AuthFailed).unwrap_or_default();
            let _ = websocket.send(Message::binary(data)).await;
            return None;
        }
        Ok(AuthResult::ReservedByOther) => {
            let data = serde_json::to_vec(&ServerHello::SubDomainInUse).unwrap_or_default();
            let _ = websocket.send(Message::binary(data)).await;
            return None;
        }
        Err(error) => {
            error!(?error, "error auth-ing user");
            let data = serde_json::to_vec(&ServerHello::AuthFailed).unwrap_or_default();
            let _ = websocket.send(Message::binary(data)).await;
            return None;
        }
    };

    tracing::info!(subdomain=%sub_domain_after_auth, "did auth sub_domain");

    Some((
        websocket,
        ClientHandshake {
            id: client_id_for_handshake, 
            sub_domain: sub_domain_after_auth, 
            is_anonymous: false, // For ClientType::Auth path, or successful reconnect which sets its own is_anonymous
        },
    ))
}

#[tracing::instrument(skip(token, websocket))]
async fn handle_reconnect_token(
    token: ReconnectToken,
    mut websocket: WebSocket,
) -> Option<(WebSocket, ClientHandshake)> {
    let payload = match ReconnectTokenPayload::verify(token, &CONFIG.master_sig_key) {
        Ok(payload) => payload,
        Err(error) => {
            error!(?error, "invalid reconnect token");
            let data = serde_json::to_vec(&ServerHello::AuthFailed).unwrap_or_default();
            let _ = websocket.send(Message::binary(data)).await;
            return None;
        }
    };

    tracing::debug!(
        client_id=%&payload.client_id,
        "accepting reconnect token from client",
    );

    Some((
        websocket,
        ClientHandshake {
            id: payload.client_id,
            sub_domain: payload.sub_domain,
            is_anonymous: true,
        },
    ))
}

async fn sanitize_sub_domain_and_pre_validate(
    mut websocket: WebSocket,
    requested_sub_domain: String,
    client_id: &ClientId,
) -> Option<(WebSocket, String)> {
    let sub_domain = requested_sub_domain.to_lowercase();

    if sub_domain
        .chars()
        .filter(|c| !(c.is_alphanumeric() || c == &'-'))
        .count()
        > 0
    {
        error!("invalid client hello: only alphanumeric/hyphen chars allowed!");
        let data = serde_json::to_vec(&ServerHello::InvalidSubDomain).unwrap_or_default();
        let _ = websocket.send(Message::binary(data)).await;
        return None;
    }

    if CONFIG.blocked_sub_domains.contains(&sub_domain) {
        error!("invalid client hello: sub-domain restrict!");
        let data = serde_json::to_vec(&ServerHello::SubDomainInUse).unwrap_or_default();
        let _ = websocket.send(Message::binary(data)).await;
        return None;
    }

    match crate::network::instance_for_host(&sub_domain).await {
        Err(crate::network::Error::DoesNotServeHost) => {}
        Ok((_, existing_client)) => {
            if &existing_client != client_id {
                error!("invalid client hello: requested sub domain in use already!");
                let data = serde_json::to_vec(&ServerHello::SubDomainInUse).unwrap_or_default();
                let _ = websocket.send(Message::binary(data)).await;
                return None;
            }
        }
        Err(e) => {
            tracing::debug!("Got error checking instances: {:?}", e);
        }
    }

    Some((websocket, sub_domain))
}
