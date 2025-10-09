use crate::{
    error::{AppError, ExpectedError},
    services::server_token::{Human, Role},
    utils::extract_bearer_token,
    ServerToken,
};

use crate::AppState;

use axum::{
    body::Body,
    extract::{Request, State},
    http::HeaderMap,
    middleware::Next,
    response::IntoResponse,
    Extension,
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
struct RealmAccess {
    roles: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    exp: usize,
    realm_access: RealmAccess,
}

pub async fn extract_role_middleware(
    State(server_token): State<std::sync::Arc<ServerToken>>,
    header: HeaderMap,
    mut req: Request,
    next: Next,
) -> Result<impl IntoResponse, AppError> {
    let token_string = extract_bearer_token(&header)?;
    let token = server_token.decode_token(&token_string)?;

    req.extensions_mut().insert(token.claims.role.clone());
    req.extensions_mut().insert(token);

    let res = next.run(req).await;
    let status = res.status().clone();
    let headers = res.headers().clone();
    let body = res.into_body();

    return Ok((status, headers, body));
}

pub async fn extract_human_middleware(
    Extension(role): Extension<Role>,
    Extension(app_state): Extension<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Result<(StatusCode, HeaderMap, Body), AppError> {
    let allowed_company_id = &app_state.config.allowed_company_id;

    tracing::info!("extract_human_middleware: role = {:?}", &role);
    match role {
            Role::Human(human) => {
                tracing::debug!("Token is human, user_id = {}", &human.user_id);
                req.extensions_mut().insert(human.clone());
            }
            Role::Machine(machine) => {
                tracing::debug!("Token is machine, company_id = {}", &machine.company_id);
                if machine.company_id == *allowed_company_id {
                    tracing::info!("Machine token matches allowed_company_id; promoting to human with admin role");
                    // create synthetic human
                    let human_equivalent = Human {
                        user_id: machine.company_id.clone(),  // or some fallback
                        realm_access_roles: vec!["dexspace_admin".to_string()],
                        company_id: machine.company_id.clone(),
                        // include other fields if needed
                    };
                    req.extensions_mut().insert(human_equivalent);
                } else {
                    tracing::warn!(
                        "Machine token rejected: company_id `{}` != allowed `{}`",
                        &machine.company_id,
                        allowed_company_id
                    );
                    return Err(AppError::Expected(ExpectedError {
                        status_code: StatusCode::UNAUTHORIZED,
                        message: "You need a valid human or machine token with correct company_id".to_owned(),
                        reason: format!(
                            "Machine token has company_id `{}`, allowed is `{}`",
                            &machine.company_id, allowed_company_id
                        ),
                        metadata: None,
                    }));
                }
            }
        }
    let res = next.run(req).await;
    let status = res.status().clone();
    let headers = res.headers().clone();
    let body = res.into_body();

    return Ok((status, headers, body));
}

pub async fn auth_role_middleware(
    State(roles): State<Vec<String>>,
    Extension(human): Extension<Human>,
    Extension(app_state): Extension<AppState>,
    req: Request,
    next: Next,
) -> Result<(StatusCode, HeaderMap, Body), AppError> {
    let has_role = human.realm_access_roles.iter().any(|r| roles.contains(&r));
    let allowed_company_id = &app_state.config.allowed_company_id;
    let has_company_id = human.company_id == *allowed_company_id;

    if !has_role && !has_company_id {
        return Err(AppError::Expected(ExpectedError {
            status_code: StatusCode::UNAUTHORIZED,
            message:  "You don't have the correct access role or company_id".to_owned(),
            reason: format!("User '{}' with roles '{:?}' and company_id '{:?}' does not have any required access roles '{:?}' or company_id '{}'",
                  &human.user_id, &human.realm_access_roles, &human.company_id, &roles, allowed_company_id),
            metadata: None,
        }));
    }

    let res = next.run(req).await;
    let status = res.status().clone();
    let headers = res.headers().clone();
    let body = res.into_body();

    return Ok((status, headers, body));
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body, extract::Extension, http::Request, middleware::from_fn_with_state,
        routing::get, Router,
    };
    use reqwest::{header::AUTHORIZATION, StatusCode};
    use tower::ServiceExt;

    use crate::services::server_token::{
        self,
        server_token_test_helper::{self, get_test_service},
        Human, Role,
    };

    #[tokio::test]
    async fn test_extract_role_no_token() {
        async fn get_hello(Extension(_role): Extension<Role>) -> String {
            return "Hello world".to_owned();
        }

        let router = Router::new()
            .route("/", get(get_hello))
            .layer(from_fn_with_state(
                std::sync::Arc::new(get_test_service()),
                extract_role_middleware,
            ));

        let response = router
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED)
    }

    #[tokio::test]
    async fn test_extract_role() {
        async fn get_hello(Extension(_role): Extension<Role>) -> String {
            return "Hello world".to_owned();
        }

        let router = Router::new()
            .route("/", get(get_hello))
            .layer(from_fn_with_state(
                std::sync::Arc::new(get_test_service()),
                extract_role_middleware,
            ));

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(
                        AUTHORIZATION,
                        server_token_test_helper::get_human_token_header(None, None),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK)
    }

    #[tokio::test]
    async fn test_extract_human_from_machine_token() {
        async fn get_hello(Extension(_role): Extension<Human>) -> String {
            return "Hello world".to_owned();
        }

        let server_token = std::sync::Arc::new(get_test_service());
        let router = Router::new()
            .route("/", get(get_hello))
            .layer(from_fn_with_state(
                server_token.clone(),
                extract_human_middleware,
            ))
            .layer(from_fn_with_state(
                server_token.clone(),
                extract_role_middleware,
            ));

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(
                        AUTHORIZATION,
                        server_token::server_token_test_helper::get_machine_token_header(None),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED)
    }

    #[tokio::test]
    async fn test_extract_human() {
        async fn get_hello(Extension(_role): Extension<Human>) -> String {
            return "Hello world".to_owned();
        }

        let server_token = std::sync::Arc::new(get_test_service());
        let router = Router::new()
            .route("/", get(get_hello))
            .layer(from_fn_with_state(
                server_token.clone(),
                extract_human_middleware,
            ))
            .layer(from_fn_with_state(
                server_token.clone(),
                extract_role_middleware,
            ));

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(
                        AUTHORIZATION,
                        server_token::server_token_test_helper::get_human_token_header(None, None),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK)
    }
}
