use axum::{
    body::Body,
    extract::Query,
    response::Json,
    routing::{delete, get, patch, post},
    Router,
};
use jetbra_tools::cert::jetbra_key::{extract_valid_jbkey, gen_license_data};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

async fn plain_text() -> &'static str {
    "Hello, World!"
}

#[derive(Deserialize)]
struct ExtractJBKeyParams {
    license: Option<String>,
}

async fn extract_valid_jbkey_view(Json(payload): Json<ExtractJBKeyParams>) -> Json<Value> {
    return match extract_valid_jbkey(payload.license.as_deref().unwrap()) {
        Ok((license_id, license_data)) => Json(json!({ "licenseId": license_id, "licenseData": license_data })),
        Err(e) => Json(json!({ "detail": "Invalid Jetbra Key" })),
    };
}

#[tokio::main]
async fn main() {
    let api_path = "/api/";

    // build our application with a single route
    let app = Router::new()
        .route(format!("{}jbkey/", api_path).as_str(), get(plain_text))
        .route(
            format!("{}jbkey/extract/", api_path).as_str(),
            post(extract_valid_jbkey_view),
        );

    // run our app with hyper, listening globally on port 8888
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8888").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
