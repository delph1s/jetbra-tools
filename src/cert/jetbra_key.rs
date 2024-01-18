use crate::error::Error as JBTError;
use crate::fs::embed_resources::get_products_list_default;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::Path;
use std::str::from_utf8;
use std::string::ToString;

/// Extracts and decodes a license key from a given string.
///
/// # Arguments
/// * `k` - A string slice containing the encoded license key.
///
/// # Returns
/// A `Result` which is `Ok` containing a tuple of the license ID and the decoded license data
/// if successful, or an `Err` with a static string describing the error.
pub fn extract_valid_jbkey(k: &str) -> Result<(String, String), Box<dyn Error>> {
    let k_list: Vec<&str> = k.split('-').collect();
    if k_list.len() != 4 {
        return Err(Box::new(io::Error::new(
            ErrorKind::InvalidInput,
            "Valid keys are separated into id, license, signature and public key using the `-` symbol",
        )));
    }
    let license_id = k_list[0].to_string();

    let license_data_base64 = k_list[1];
    let license_data_bytes = STANDARD
        .decode(license_data_base64)
        .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "Base64 decoding failed"))?;
    let license_data = from_utf8(&license_data_bytes)
        .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "UTF-8 conversion failed"))?
        .to_string();

    Ok((license_id, license_data))
}

#[derive(Deserialize)]
struct IDEConfig {
    name: String,
    code: String,
    plugin: Vec<String>,
}

#[derive(Deserialize)]
struct PluginConfig {
    name: String,
    code: String,
}

#[derive(Deserialize)]
struct ProductConfig {
    ide: Vec<IDEConfig>,
    plugin: Vec<PluginConfig>,
}

#[derive(Serialize)]
struct LicenseProduct {
    code: String,
    fallback_date: String,
    paid_up_to: String,
    extended: bool,
}

#[derive(Serialize)]
#[serde(rename_all(serialize = "camelCase"))]
struct LicenseData {
    license_id: String,
    licensee_name: String,
    assignee_name: String,
    assignee_email: String,
    license_restriction: String,
    check_concurrent_use: bool,
    products: Vec<LicenseProduct>,
    metadata: String,
    hash: String,
    grace_period_days: u32,
    auto_prolongated: bool,
    is_auto_prolongated: bool,
}

/// Reads product configuration from a TOML file.
///
/// First, attempts to read from a local `products.toml` file. If the file does not exist,
/// it falls back to a default embedded list of products.
///
/// Returns a `Result` with `ProductConfig` on success or an error boxed as `Box<dyn Error>`
/// if any step of reading or parsing the file fails.
fn read_products() -> Result<ProductConfig, Box<dyn Error>> {
    // Check if `products.toml` exists in the current directory.
    if Path::new("./products.toml").exists() {
        // Attempt to read the TOML file content.
        let content = fs::read_to_string("./products.toml")
            .map_err(|_| Box::new(JBTError::new("Failed to read customer products.toml")))?;
        // Attempt to parse the TOML content.
        let config = toml::from_str(&content).map_err(|_| Box::new(JBTError::new("Failed to parse TOML")))?;

        return Ok(config);
    }

    // Use default products if local file is not found.
    let products_embedded = get_products_list_default().ok_or(JBTError::new("Failed to read default products.toml"))?;
    let content = from_utf8(products_embedded.data.as_ref())
        .map_err(|_| Box::new(JBTError::new("Failed to read default products.toml")))?;
    // Parse the TOML content from the embedded data.
    let config = toml::from_str(&content).map_err(|_| Box::new(JBTError::new("Failed to parse TOML")))?;

    Ok(config)
}

// gen_license_data 函数实现
pub fn gen_license_data(
    ide: Option<HashMap<String, String>>,
    plugins: Option<Vec<HashMap<String, String>>>,
    license_id: String,
    licensee_name: String,
    assignee_name: String,
    assignee_email: String,
) -> Result<String, Box<dyn Error>> {
    if ide.is_none() && plugins.is_none() {
        return Err(Box::new(JBTError::new(
            "The ide and plugins parameters cannot both be null.",
        )));
    }
    // 判断 ide 是否为空
    let ide_is_some = ide.is_some();

    let products = read_products()?;
    let mut data_products = Vec::new();

    if let Some(ide_data) = ide {
        let ide_code = ide_data.get("code").unwrap();
        let ide_expired = ide_data.get("expired").unwrap();

        let matched_ide = products
            .ide
            .into_iter()
            .find(|i| &i.code == ide_code)
            .ok_or("There is no ide code that matches.")?;

        for plugin_code in matched_ide.plugin {
            let matched_plugin = products
                .plugin
                .iter()
                .find(|p| p.code == plugin_code)
                .ok_or("Plugin code not found in products.")?;

            data_products.push(LicenseProduct {
                code: matched_plugin.code.clone(),
                fallback_date: ide_expired.clone(),
                paid_up_to: ide_expired.clone(),
                extended: true,
            });
        }
    }

    // 添加 plugins 数据
    if let Some(plugin_list) = plugins {
        for plugin_data in plugin_list {
            let plugin_code = plugin_data.get("code").unwrap();
            let plugin_expired = plugin_data.get("expired").unwrap();

            let matched_plugin = products
                .plugin
                .iter()
                .find(|p| &p.code == plugin_code)
                .ok_or("Plugin code not found in products.")?;

            data_products.push(LicenseProduct {
                code: matched_plugin.code.clone(),
                fallback_date: plugin_expired.clone(),
                paid_up_to: plugin_expired.clone(),
                extended: ide_is_some,
            });
        }
    }

    // 确保 code 唯一
    data_products.dedup_by(|a, b| a.code == b.code);

    // 构建并返回最终的 json 字符串
    let license_data = LicenseData {
        license_id,
        licensee_name,
        assignee_name,
        assignee_email,
        license_restriction: "".to_string(),
        check_concurrent_use: false,
        products: data_products,
        metadata: "0120220902PSAN000005".to_string(),
        hash: "TRIAL:1234567890".to_string(),
        grace_period_days: 7,
        auto_prolongated: false,
        is_auto_prolongated: false,
    };

    Ok(serde_json::to_string(&license_data).expect("Failed to serialize license data"))
}

enum PublicExponent {
    OldExponent = 3,
    NewExponent = 65537,
}

// 根据指定的起始和结束时间生成证书
// fn gen_certificate(
//     datetime_start: u64,
//     datetime_end: u64,
//     public_exponent: PublicExponent,
//     key_size: usize,
//     subject_name: &str,
//     issuer_name: &str,
// ) -> Result<(String, String), Box<dyn std::error::Error>> {
//     // 生成 RSA 私钥
//     let private_key = RsaPrivateKey::new(&mut rand::thread_rng(), key_size)?;
//     let public_key = RsaPublicKey::from(&private_key);
//
//     // 创建证书参数
//     // PublicExponent::NewExponent
//     let mut params = CertificateParams::new(vec![subject_name.to_string()]);
//     params.not_before = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(datetime_start);
//     params.not_after = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(datetime_end);
//     params.key_pair = Some(KeyPair::from(private_key));
//
//     // 生成证书
//     let cert = Certificate::from_params(params)?;
//     let cert_pem = cert.serialize_pem()?;
//     let private_key_pem = cert.serialize_private_key_pem();
//
//     Ok((private_key_pem, cert_pem))
// }
