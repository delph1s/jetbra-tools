use crate::time::time_fmt::{dt2odt, CertTime};
// use openssl::{
//     pkey::PKey,
//     rsa::{Padding, Rsa},
//     x509::{X509Builder, X509Name, X509NameBuilder, X509},
// };
use rand::{rngs::OsRng, RngCore};
use rcgen::{
    Certificate,
    CertificateParams,
    DistinguishedName,
    DnType,
    // ExtendedKeyUsagePurpose,
    // IsCa,
    KeyIdMethod,
    KeyPair,
    // KeyUsagePurpose,
    // NameConstraints,
    // SanType,
    SerialNumber,
    PKCS_RSA_SHA256,
};
use rsa::traits::PublicKeyParts;
use rsa::{
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPrivateKey},
    pkcs8::EncodePrivateKey,
    BigUint, RsaPrivateKey, RsaPublicKey,
};
use std::{
    error::Error,
    fs::File,
    io::BufReader,
    // path::Path
};
use time::OffsetDateTime;
use x509_parser::{certificate::X509Certificate, nom::AsBytes, pem::Pem};

/// 定义一个名为 `PublicExponent` 的枚举（enum）。
/// 枚举用于表示一组已命名的常数值，这里用于表示公钥指数。
///
/// - `OldExponent` 变体，其值为 3。这可能用于一些旧的或传统的加密算法。
/// - `NewExponent` 变体，其值为 65537。这是一种更常用的公钥指数，广泛用于现代加密算法。
enum PublicExponent {
    OldExponent = 3,
    NewExponent = 65537,
}

impl Default for PublicExponent {
    /// 为 `PublicExponent` 枚举实现 `Default` 特质。
    /// `Default` 特质用于提供类型的默认值。这在创建 `GenCertificateParams` 实例时使用。
    fn default() -> Self {
        PublicExponent::NewExponent
    }
}

/// 生成一个包含 20 个随机字节的序列号。
///
/// 这个函数不接受任何参数，并返回一个 `Vec<u8>` 类型的值，
/// 其中包含了 20 个随机字节。这些字节由 OsRng（操作系统级的随机数生成器）
/// 生成，保证了随机性和安全性。
///
/// # 返回值
/// 返回一个包含 20 个随机字节的 `Vec<u8>`。
///
/// 注意：由于这个函数生成的是随机值，所以每次调用的结果都将不同。
pub(super) fn random_serial_number() -> Vec<u8> {
    // 创建一个可变数组 serial_number，包含 20 个字节，初始值全部为 0
    let mut serial_number = [0u8; 20];
    // 使用 OsRng 的 fill_bytes 方法填充这个数组，使其包含随机字节
    // OsRng 是一个密码学安全的随机数生成器
    OsRng.fill_bytes(&mut serial_number);

    // 将数组转换成 Vec<u8> 类型并返回
    // 这允许返回的序列号在函数外部被自由地修改和使用
    serial_number.to_vec()
}

/// 生成一个随机的 `u64` 类型的序列号。
///
/// 这个函数使用 `OsRng` 生成器生成一个随机的 `u64` 类型的值。
/// 然后将这个值左移一位，以提供一个稍有不同的随机数。
///
/// # 返回值
/// 返回一个 `u64` 类型的随机数。
pub(super) fn random_u64_serial_number() -> u64 {
    // 使用 OsRng 生成器生成一个随机的 u64 类型的值
    let mut random_u64 = OsRng.next_u64();
    // 将随机生成的数左移一位，这种操作会改变这个数的位表示
    // 左移一位相当于乘以 2，但效率更高
    random_u64 <<= 1;

    // 返回修改后的随机数
    random_u64
}

/// The GenCertificateParams struct is used to hold the parameters required for generating a certificate. Here's a brief explanation of each field:
///
/// - `datetime_start` - The start time for the certificate's validity period, represented as a Unix timestamp.
/// - `datetime_end` - The end time for the certificate's validity period, represented as a Unix timestamp.
/// - `public_exponent` - The public exponent to be used for RSA encryption. It's an enum that can be either OldExponent (value 3) or NewExponent (value 65537).
/// - `key_size` - The size of the RSA key to be generated.
/// - `subject_name` - The subject name for the certificate.
/// - `issuer_name` - The issuer name for the certificate.
struct GenCertificateParams {
    datetime_start: OffsetDateTime,
    datetime_end: OffsetDateTime,
    public_exponent: PublicExponent,
    key_size: u16,
    subject_name: String,
    issuer_name: String,
}

impl Default for GenCertificateParams {
    /// The Default trait is implemented for GenCertificateParams to provide default values for each field. This is used when an instance of GenCertificateParams is created without specifying values for its fields. The default values are:
    ///
    /// - `datetime_start` - 1218182888 (Unix timestamp)
    /// - `datetime_end` - 4102444799 (Unix timestamp)
    /// - `public_exponent` - NewExponent (65537)
    /// - `key_size` - 4096 bits
    /// - `subject_name` - "Your Subject Name"
    /// - `issuer_name` - "JetProfile CA"
    fn default() -> Self {
        Self {
            datetime_start: OffsetDateTime::from_unix_timestamp_nanos(1218182888888).unwrap(),
            datetime_end: OffsetDateTime::from_unix_timestamp_nanos(4102444799999).unwrap(),
            public_exponent: PublicExponent::NewExponent,
            key_size: 4096,
            subject_name: "anonymous-from-20080808".to_string(),
            issuer_name: "JetProfile CA".to_string(),
        }
    }
}

/// Generates an RSA certificate and private key.
///
/// # Arguments
///
/// - `gen_certificate_params` - struct GenCertificateParams
///   - `datetime_start` - Tuple representing the start datetime.
///   - `datetime_end` - Tuple representing the end datetime.
///   - `public_exponent` - Public exponent for RSA.
///   - `key_size` - Key size for RSA.
///   - `subject_name` - Subject name for the certificate.
///   - `issuer_name` - Issuer name for the certificate.
///
/// # Returns
///
/// A Result containing a tuple of the private key and certificate in PEM format,
/// or an error message.
fn rc_gen_certificate(gen_certificate_params: GenCertificateParams) -> Result<(String, String), Box<dyn Error>> {
    // 生成 RSA 私钥
    let mut rng = OsRng;
    let exp = BigUint::from(gen_certificate_params.public_exponent as u64);
    let private_key = RsaPrivateKey::new_with_exp(&mut rng, gen_certificate_params.key_size as usize, &exp)?;
    let private_key_der = private_key.to_pkcs8_der()?;
    // let private_key_pem = private_key.to_pkcs1_pem(LineEnding::LF)?;
    // 保存证书
    // let path = Path::new("./.cache/private_key.pem");
    // private_key.write_pkcs1_pem_file(path, LineEnding::LF)?;
    // 生成对应的公钥
    // let public_key = private_key.to_public_key();

    // 设置证书参数
    let mut cert_params = CertificateParams::new(vec![]);
    // 设置签名算法
    cert_params.alg = &PKCS_RSA_SHA256;
    // 设置起止时间
    cert_params.not_before = gen_certificate_params.datetime_start;
    cert_params.not_after = gen_certificate_params.datetime_end;
    // 设置序列号
    cert_params.serial_number = Some(SerialNumber::from(random_serial_number()));
    // 设置替代名称
    // cert_params.subject_alt_names.push(SanType::DnsName("*".to_string()));
    // cert_params
    //     .subject_alt_names
    //     .push(SanType::Rfc822Name(gen_certificate_params.subject_name.clone()));
    // 设置主题名称
    cert_params.distinguished_name = DistinguishedName::new();
    cert_params
        .distinguished_name
        .push(DnType::CommonName, gen_certificate_params.issuer_name);
    // cert_params.distinguished_name.push(DnType::OrganizationName, "JTs");
    // cert_params
    //     .distinguished_name
    //     .push(DnType::OrganizationalUnitName, "JTs");
    // cert_params.distinguished_name.push(DnType::CountryName, "JB");
    // cert_params.distinguished_name.push(DnType::StateOrProvinceName, "JB");
    // 设置是否为CA
    // cert_params.is_ca = IsCa::ExplicitNoCa;
    // 设置用途
    // cert_params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    // cert_params.key_usages.push(KeyUsagePurpose::KeyEncipherment);
    // cert_params.extended_key_usages(ExtendedKeyUsagePurpose::try_from());
    // 设置名称约束
    // cert_params.name_constraints = NameConstraints::new();
    // 设置证书吊销列表(CRL)分发点的可选列表
    // cert_params.crl_distribution_points = ;
    // 设置自定义扩展
    // cert_params.custom_extensions = ;
    // 设置密钥对
    cert_params.key_pair = Some(KeyPair::try_from(private_key_der.as_bytes())?);
    // 如果为True，则将向生成的证书添加`Authority Key标识符`扩展名
    // cert_params.use_authority_key_identifier_extension = true;
    // 设置从公钥生成密钥标识符的方法，默认为SHA-256
    cert_params.key_identifier_method = KeyIdMethod::Sha256;

    // 对证书进行签名
    let cert = Certificate::from_params(cert_params)?;
    // 将私钥和证书导出为 PEM 格式的字符串
    // let cert_der = cert.serialize_der()?;
    let cert_pem = cert.serialize_pem()?;
    // let private_key_der = cert.serialize_private_key_der();
    let private_key_pem = cert.serialize_private_key_pem();

    // 打印私钥和证书
    // println!("Private key:\n{}", private_key_pem);
    // println!("Certificate:\n{}", cert_pem);
    // println!("Certificate:\n{}", cert_der.into_vec());
    // fs::write("./.cache/cert.der", &cert_pem_der).expect("Unable to write file");

    Ok((private_key_pem, cert_pem))
}

/// Generates an RSA certificate and private key.
///
/// # Arguments
///
/// - `gen_certificate_params` - struct GenCertificateParams
///   - `datetime_start` - Tuple representing the start datetime.
///   - `datetime_end` - Tuple representing the end datetime.
///   - `public_exponent` - Public exponent for RSA.
///   - `key_size` - Key size for RSA.
///   - `subject_name` - Subject name for the certificate.
///   - `issuer_name` - Issuer name for the certificate.
///
/// # Returns
///
/// A Result containing a tuple of the private key and certificate in PEM format,
/// or an error message.
// pub fn openssl_gen_certificate(gen_certificate_params: GenCertificateParams) -> Result<(String, String), Box<dyn Error>> {
//     // Generate RSA private key
//     let rsa = Rsa::generate_with_e(key_size, public_exponent)?;
//     let private_key = PKey::from_rsa(rsa)?;
//
//     // Get public key
//     let public_key = PKey::from_rsa(private_key.rsa()?.to_owned())?;
//
//     // Create X.509 builder
//     let mut builder = X509Builder::new()?;
//     let mut name = X509NameBuilder::new()?;
//     name.append_entry_by_text("CN", subject_name)?;
//     let subject_name = name.build();
//     let mut issuer = X509NameBuilder::new()?;
//     issuer.append_entry_by_text("CN", issuer_name)?;
//     let issuer_name = issuer.build();
//
//     builder.set_subject_name(&subject_name)?;
//     builder.set_issuer_name(&issuer_name)?;
//     builder.set_not_before(&Asn1Time::from_tm(&time_to_tm(datetime_start)?)?)?;
//     builder.set_not_after(&Asn1Time::from_tm(&time_to_tm(datetime_end)?)?)?;
//     builder.set_pubkey(&public_key)?;
//     builder.set_serial_number(&openssl::bn::BigNum::from_u32(rand::random())?.to_asn1_integer()?)?;
//
//     // Sign the certificate
//     builder.sign(&private_key, openssl::hash::MessageDigest::sha256())?;
//
//     // Export to PEM
//     let certificate = builder.build();
//     let private_key_pem = private_key.private_key_to_pem_pkcs8()?;
//     let certificate_pem = certificate.to_pem()?;
//
//     Ok((private_key_pem, certificate_pem))
// }

pub fn parse_root_public_key_from_file(cert_path: &str) -> Result<String, Box<dyn Error>> {
    let cert_file = File::open(cert_path)?;
    let cert_pem = Pem::read(BufReader::new(cert_file))?;
    let x509_cert = cert_pem.0.parse_x509()?;
    let public_key = x509_cert.public_key().clone();
    let subject_public_key_data = public_key.subject_public_key.data.as_ref();
    let rsa_public_key =
        RsaPublicKey::from_pkcs1_der(&subject_public_key_data).expect("Failed to convert to RSA public key");
    let rsa_public_key_parts = rsa_public_key.n().to_string();

    Ok(rsa_public_key_parts)
}

pub fn sign_from_file(cert_path: &str) -> Result<(String, String), Box<dyn Error>> {
    let cert_file = File::open(cert_path)?;
    let cert_pem = Pem::read(BufReader::new(cert_file))?;
    let x509_cert = cert_pem.0.parse_x509()?;
    let sign = x509_cert.signature_value.as_ref();
    let sign_big_uint = BigUint::from_bytes_be(sign);

    let filled_sign = "".to_string();

    Ok((sign_big_uint.to_string(), filled_sign))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::time_fmt::{dt2odt, CertTime};
    use std::fs;
    use std::io::Write;
    use x509_parser::nom::AsBytes;

    #[test]
    fn test_gen_certificate() {
        let datetime_start = dt2odt(&CertTime {
            year: 2000,
            month: 1,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
            microsecond: 0,
        })
        .unwrap();
        let datetime_end = dt2odt(&CertTime::default()).unwrap();
        let public_exponent = PublicExponent::NewExponent;
        let key_size = 4096;
        let subject_name = "Your Subject Name".to_string();
        let issuer_name = "JetProfile CA".to_string();

        let (private_key_pem, certificate_pem) = rc_gen_certificate(GenCertificateParams {
            datetime_start,
            datetime_end,
            public_exponent,
            key_size,
            subject_name,
            issuer_name,
            ..Default::default()
        })
        .unwrap();

        fs::write("./.cache/jbts/key.pem", private_key_pem.as_bytes()).expect("Unable to write private key file");
        fs::write("./.cache/jbts/cert.pem", certificate_pem.as_bytes()).expect("Unable to write certificate file");
    }

    #[test]
    fn test_rc_gen_sign() {
        let (sign, filled_sign) = sign_from_file("./.cache/jbts/cert.pem").unwrap();
        let mut sign_file = File::create("./.cache/jbts/sign.txt").unwrap();
        sign_file
            .write_all(sign.to_string().as_bytes())
            .expect("Unable to write sign file");
        println!("{}", sign.to_string());

        let root_public_key = parse_root_public_key_from_file("./.cache/jbts/root.pem").unwrap();
        println!("{}", root_public_key);
    }
}
