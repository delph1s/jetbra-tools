import binascii
import datetime
import base64
import json
import re

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID

from Crypto.Hash import SHA1, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Util.asn1 import DerSequence, DerObjectId, DerNull, DerOctetString
from Crypto.Util.number import ceil_div


JETBRAINS_ROOT_CA = (
    "-----BEGIN CERTIFICATE-----\n"
    "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\n"
    "-----END CERTIFICATE-----"
)

JETBRAINS_SERVER_ROOT_CA = (
    "-----BEGIN CERTIFICATE-----\n"
    "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\n"
    "7tlDFnvaRnQukqSG+VqNWg==\n"
    "-----END CERTIFICATE-----"
)


def extract_valid_jetbra_key(k):
    """
    从给定的 key 中提取有效的许可证ID和许可证数据。

    该函数解析一个特定格式的字符串，该字符串由四部分组成，用"-"分隔。这四部分分别是许可证 ID、
    Base64 编码的许可证数据、签名和公钥字符串。此函数只关心许可证 ID 和 Base64 编码的许可证数据，
    将 Base64 编码的数据解码为 UTF-8 字符串。

    Params:
        k (str): 包含许可证 ID、Base64 编码的许可证数据、签名和公钥的 key 字符串。

    Returns:
        tuple[str, str]: 包含许可证 ID 和解码后的许可证数据的元组。如果 key 格式不正确或解码失败，
                         返回两个空字符串。

    Exceptions:
        ValueError: 如果输入的 key 不符合预期格式。
    """

    k_list = k.split("-")
    if len(k_list) != 4:
        raise ValueError("不是有效的 key")

    license_id = k_list[0]
    license_data_base64 = k_list[1]

    try:
        license_data = base64.b64decode(license_data_base64)
        license_data = license_data.decode("utf-8")
    except binascii.Error:
        return "", ""
    except UnicodeDecodeError:
        return "", ""

    return license_id, license_data


def gen_certificate(
    datetime_start=(2000, 1, 1, 0, 0, 0, 0),
    datetime_end=(2099, 12, 31, 23, 59, 59, 999999),
    public_exponent=65537,
    key_size=4096,
    subject_name="anonymous-from-2000-01-01",
    issuer_name="JetProfile CA",
):
    """
    生成具有指定参数的自签名 X.509 证书和对应的 RSA 私钥。

    Params:
        datetime_start (tuple): 证书有效期开始的日期时间，格式为(year, month, day, hour, minute, second, microsecond)。
        datetime_end (tuple): 证书有效期结束的日期时间，格式为(year, month, day, hour, minute, second, microsecond)。
        public_exponent (int): 新密钥的公共指数，通常为65537。
        key_size (int): 生成RSA密钥的大小（位数），推荐使用4096位。
        subject_name (str): 证书主题的名称。
        issuer_name (str): 签发证书的颁发机构的名称。

    Returns:
        tuple: 包含两个元素，第一个是私钥（PEM格式），第二个是公钥证书（PEM格式）。

    Descriptions:
        此函数生成一个RSA私钥和一个自签名的X.509证书，用于测试或开发环境。
    """

    # 将提供的日期时间元组转换为datetime对象
    start_day = datetime.datetime(*datetime_start)
    end_day = datetime.datetime(*datetime_end)

    # 生成RSA私钥，指定公共指数和密钥长度
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,  # 公共指数值，推荐使用 65537
        key_size=key_size,  # 密钥的位大小，推荐至少为 2048 位，此处推荐使用 4096 位
        backend=default_backend(),  # 使用默认的后端提供加密操作
    )

    # 从私钥中获取对应的公钥
    public_key = private_key.public_key()

    # 初始化 X.509 证书生成器
    builder = x509.CertificateBuilder()
    # 设置证书的主题名
    builder = builder.subject_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
            ]
        )
    )
    # 设置证书的颁发者名
    builder = builder.issuer_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)])
    )
    # 设置证书有效期
    builder = builder.not_valid_before(start_day)
    builder = builder.not_valid_after(end_day)
    # 为证书生成一个随机序列号
    builder = builder.serial_number(x509.random_serial_number())
    # 设置证书公钥
    builder = builder.public_key(public_key)
    # 使用私钥对证书进行签名，采用 SHA256 作为摘要算法
    certificate = builder.sign(
        private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend()
    )

    # 将私钥导出为 PEM 格式
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # 将证书导出为 PEM 格式
    public_bytes = certificate.public_bytes(encoding=serialization.Encoding.PEM)

    return private_bytes, public_bytes


def pkcs15_encode(msg_hash, em_len, with_hash_parameters=True):
    """
    根据PKCS#1 v1.5标准，对消息摘要进行编码。

    该函数生成一个符合PKCS#1 v1.5填充规则的编码消息，用于RSA签名过程中的消息摘要。

    Params:
        msg_hash (Hash): 包含消息摘要和相关OID的对象。
        em_len (int): 期望的编码消息长度（字节）。
        with_hash_parameters (bool): 是否在编码中包含哈希参数。默认为True。

    Returns:
        bytes: 按照PKCS#1 v1.5填充规则编码的消息。

    Exceptions:
        TypeError: 如果`em_len`小于所需的最小长度。

    Attentions:
        `em_len`应该足够大，以便包含消息摘要、算法标识符和必要的填充。
    """

    # 生成 DER 序列来表示摘要算法标识符
    digest_algo = DerSequence([DerObjectId(msg_hash.oid).encode()])

    # 如果需要，添加哈希参数（通常是 ASN.1 的 NULL 值）到 DER 序列
    if with_hash_parameters:
        digest_algo.append(DerNull().encode())

    # 生成摘要信息的 DER 编码，包括算法标识符和摘要本身
    digest = DerOctetString(msg_hash.digest())
    digest_info = DerSequence([digest_algo.encode(), digest.encode()]).encode()

    # 检查编码消息长度是否足够，至少需要 11 个字节的固定格式：0x00、0x01、填充字节、0x00 和摘要信息
    if em_len < len(digest_info) + 11:
        raise TypeError(
            "Selected hash algorithm has a too long digest (%d bytes)." % len(digest)
        )
    # 生成填充字符串，填充字节为 0xFF。填充长度为期望长度减去摘要信息长度和 3 个固定字节的长度
    PS = b"\xFF" * (em_len - len(digest_info) - 3)

    # 构造编码消息，包括起始字节 0x00、0x01、填充字节、分隔字节 0x00 和摘要信息
    return b"\x00\x01" + PS + b"\x00" + digest_info


def extract_public_key_str(public_key_bytes: bytes) -> str:
    """
    从给定的公钥字节序列中提取公钥字符串。

    该函数尝试将字节序列解码为UTF-8字符串，并使用正则表达式提取PEM格式的公钥字符串，
    除去了"-----BEGIN CERTIFICATE-----"和"-----END CERTIFICATE-----"标记及其中的换行符。

    Params:
        public_key_bytes (bytes): 包含PEM格式公钥的字节序列。

    Returns:
        str: 提取并处理后的公钥字符串，不包含PEM格式的头部和尾部标记以及换行符。

    Exceptions:
        ValueError: 如果输入的字节序列无法解码为有效的UTF-8字符串或者未在字符串中找到有效的公钥。
    """

    # 定义正则表达式以匹配 PEM 格式的私钥字符串，包括起始和结束标记。使用 re.DOTALL 以支持跨行匹配
    # private_key_str_pattern = re.compile(
    #     r"-----BEGIN RSA PRIVATE KEY-----(.*?)-----END RSA PRIVATE KEY-----", re.DOTALL
    # )

    # 定义正则表达式以匹配 PEM 格式的公钥字符串，包括起始和结束标记。使用 re.DOTALL 以支持跨行匹配
    public_key_str_pattern = re.compile(
        r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", re.DOTALL
    )

    try:
        # 尝试将公钥的字节序列解码为 UTF-8 字符串
        public_key_str = public_key_bytes.decode("utf-8")
    except UnicodeDecodeError:
        # 如果解码失败，抛出 ValueError 异常，指明不是有效的公钥
        raise ValueError("不是有效的公钥")

    # 使用正则表达式在解码后的字符串中搜索公钥
    public_key_str_match = public_key_str_pattern.search(public_key_str)

    # 如果没有匹配到公钥，抛出 ValueError 异常
    if not public_key_str_match:
        raise ValueError("未找到公钥")

    # 从匹配对象中提取公钥字符串（不包括 PEM 格式的头尾标记）
    public_key_str = public_key_str_match.group(1)
    # 移除公钥字符串中的所有换行符
    public_key_str = "".join(public_key_str.split("\n"))

    # 返回处理后的公钥字符串
    return public_key_str


def extract_public_key_modulus(public_key_str: bytes) -> int:
    """
    从公钥字符串中提取模数 (modulus)。

    Args:
        public_key_str (bytes): PEM 格式的公钥字符串。

    Returns:
        int: 公钥的模数。

    Raises:
        ValueError: 如果公钥格式不正确或无法提取模数。
    """
    try:
        # 使用之前定义的函数提取公钥字符串，移除了 PEM 格式的头尾标记和换行符
        public_key_str = extract_public_key_str(public_key_str)

        # 将 Base64 编码的公钥字符串解码为 DER 格式的字节序列，然后加载为证书对象
        cert = x509.load_der_x509_certificate(base64.b64decode(public_key_str))

        # 从证书中提取公钥对象
        public_key = cert.public_key()

        # 返回公钥的模数
        return public_key.public_numbers().n
    except Exception as e:
        raise ValueError(f"无法从公钥中提取模数: {str(e)}")


def gen_sign(public_key_bytes: bytes) -> tuple[int, int]:
    """
    从给定的公钥字节序列生成签名信息。

    该函数首先提取 PEM 格式的公钥字符串，然后从中加载 DER 格式的证书，获取证书的公钥。
    接着计算证书签名和证书内容（不包含签名本身）的 SHA256 摘要的整数表示。
    最后，使用 PKCS#1 v1.5 编码规则对摘要进行编码，并计算其整数值。

    Params:
        public_key_bytes (bytes): 包含 PEM 格式公钥的字节序列。

    Returns:
        tuple[int, int]: 包含两个整数，第一个是证书签名的整数表示，第二个是经过 PKCS#1 v1.5 编码的证书摘要的整数表示。

    Attentions:
        此函数假设公钥字节序列是一个有效的 PEM 格式证书。
    """

    # 使用之前定义的函数提取公钥字符串，移除了 PEM 格式的头尾标记和换行符
    public_key_str = extract_public_key_str(public_key_bytes)
    # 将 Base64 编码的公钥字符串解码为 DER 格式的字节序列，然后加载为证书对象
    cert = x509.load_der_x509_certificate(base64.b64decode(public_key_str))

    # 从证书中提取公钥对象
    public_key = cert.public_key()
    # 将证书的签名部分转换为大端序整数
    sign = int.from_bytes(
        cert.signature,
        byteorder="big",
    )

    # 对证书的 tbs（待签名的证书部分）计算 SHA256 摘要
    digest_cert = SHA256.new(cert.tbs_certificate_bytes)
    # 获取公钥的位数，并计算编码后摘要的长度（以字节为单位），向上取整
    mod_bits = public_key.key_size
    filled_sign = int.from_bytes(
        pkcs15_encode(
            digest_cert, ceil_div(mod_bits, 8)
        ),  # 使用 PKCS#1 v1.5 规则对摘要进行编码
        byteorder="big",
        signed=False,
    )

    # 返回证书的签名整数值和编码后摘要的整数值
    return sign, filled_sign


def gen_license(
    public_key_bytes: bytes,
    private_key_bytes: bytes,
    license_id: str,
    license_data: str,
) -> str:
    """
    根据提供的公私钥和许可证数据生成一个经过签名的许可证字符串。

    该函数首先从给定的公钥字节序列中提取公钥字符串，并加载为 DER 格式的证书。
    然后，它使用私钥对许可证数据的 SHA1 摘要进行签名，并对签名和许可证数据进行 Base64 编码。
    最后，它验证签名的正确性，并组合许可证 ID、Base64 编码的许可证数据、签名和公钥字符串为最终结果。

    Params:
        public_key_bytes (bytes): 包含 PEM 格式公钥的字节序列。
        private_key_bytes (bytes): 包含私钥的字节序列。
        license_id (str): 许可证的唯一标识符。
        license_data (str): 许可证的内容。

    Returns:
        str: 组合了许可证 ID、许可证数据、签名和公钥的字符串，各部分通过"-"分隔。

    Exceptions:
        ValueError: 如果公钥或私钥无效，或签名验证失败。
    """

    # 使用之前定义的函数提取公钥字符串，移除了 PEM 格式的头尾标记和换行符
    public_key_str = extract_public_key_str(public_key_bytes)
    # 将 Base64 编码的公钥字符串解码为DER格式的字节序列，然后加载为证书对象
    cert = x509.load_der_x509_certificate(base64.b64decode(public_key_str))
    # 从证书中提取公钥对象
    public_key = cert.public_key()
    # 将许可证数据编码为 UTF-8 格式的字节序列
    license_data_encoded = license_data.encode("utf-8")
    # 对许可证数据的字节序列计算 SHA1 摘要
    digest = SHA1.new(license_data_encoded)

    # 从字节序列导入私钥对象
    private_key = RSA.import_key(private_key_bytes)
    # 使用私钥对摘要进行签名
    signature = pkcs1_15.new(private_key).sign(digest)

    # 将签名结果进行 Base64 编码
    sig_results = base64.b64encode(signature)
    # 将许可证数据进行 Base64 编码
    license_data_base64 = base64.b64encode(bytes(license_data_encoded))

    # 使用证书的公钥进行验证
    public_key.verify(
        base64.b64decode(sig_results),
        base64.b64decode(license_data_base64),
        padding=padding.PKCS1v15(),
        algorithm=hashes.SHA1(),
    )

    # 使用证书的公钥进行验证
    try:
        public_key.verify(
            base64.b64decode(sig_results),
            base64.b64decode(license_data_base64),
            padding=padding.PKCS1v15(),
            algorithm=hashes.SHA1(),
        )
    except ValueError:
        raise ValueError("签名验证失败")

    # 组合许可证 ID、Base64 编码的许可证数据、签名和公钥字符串为最终的许可证结果
    license_result = (
        f"{license_id}"
        "-"
        f'{license_data_base64.decode("utf-8")}'
        "-"
        f'{sig_results.decode("utf-8")}'
        "-"
        f"{public_key_str}"
    )
    return license_result


def gen_power_cfg(
    cert_sign,
    cert_sign_filled,
    cfg_prefix="EQUAL",
    public_exponent=65537,
    jb_root_ca_sign=None,
):
    """
    生成配置字符串，包括证书签名、公共指数和根 CA 签名。

    此函数构造一个特定格式的配置字符串，用于配置或标识某些安全参数，例如证书签名和根CA签名。
    它还允许指定一个配置前缀和公共指数。

    Params:
        cert_sign (int): 证书的签名值。
        cert_sign_filled (int): 经过填充的证书签名值。
        cfg_prefix (str, 可选): 配置字符串的前缀，默认为"EQUAL"。
        public_exponent (int, 可选): RSA 公钥的公共指数，默认为 65537。
        jb_root_ca_sign (Optional[str], 可选): 根CA的签名值，如果未提供，则使用默认值。

    Returns:
        str: 格式化的配置字符串，包含证书签名、公共指数、根 CA 签名及经过填充的证书签名值。

    Exceptions:
        如果 jb_root_ca_sign 未提供，函数将使用一个预定义的大整数字符串作为默认值。
    """

    jb_root_ca_sign = jb_root_ca_sign or (
        "8601065769528791011927822788763192434860724819629996104840271611"
        "6244893326842304564725814569508228426593301912071464375208899731"
        "2766689988016808929265129401027490891810902278465065056686129972"
        "0851196052374708999527519150702443751734289764134063638791285314"
        "4940779511591371586386725916395768216404061350504031474766080042"
        "4242248055421184038777878268502955477482203711835548014501087778"
        "9591571124238232758788247291323932815177787424630675833200910099"
        "1614145465761408960012694808795446505532198701298993706578501328"
        "4988096504657892738536613208311013047138019418152103262155848541"
        "5743274845100255941662397844298451808757740122297848789036034914"
        "2673234799435938033010332870598106404487233479036589492449492359"
        "5382470094461546336020961505275530597716457288511366082299255537"
        "7628912381363819245207492284125592193467771841742199996409060072"
        "0526004070783970613166214932515123055831606806813940681608011990"
        "6833578907759960298749494098180107991752250725928647349597506532"
        "7785397098522544780611940980698015498451633583151162609152704800"
        "5769992996846806801573516289021385911356367204063068735705490274"
        "7438421559817252127187138838514773245413540030800888215961904267"
        "3487272061105825056061829440235824590064061378319409591955663648"
        "11905585377246353"
    )

    return f"{cfg_prefix},{cert_sign},{public_exponent},{jb_root_ca_sign}->{cert_sign_filled}"


if __name__ == "__main__":
    with (
        open(
            "ca.crt", "rb"
        ) as f_cert,
        open(
            "ca.key", "rb"
        ) as f_key,
        open(
            "licenses.json", "r"
        ) as f_licenses,
    ):
        # new_sign = gen_sign(f_cert.read())
        # new_power_cfg = gen_power_cfg(new_sign[0], new_sign[1])
        # print(new_power_cfg)
        new_license = gen_license(f_cert.read(), f_key.read(), "8888888888", json.dumps(json.loads(f_licenses.read())))
        print(new_license)
