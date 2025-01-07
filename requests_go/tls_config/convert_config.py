from .config import TLSConfig

# X.509证书数字签名算法英文形式标识符
TLS1_3_Identifier = {
    'rsa_pkcs1_sha512': 'PKCS1WithSHA512',
    'rsa_pkcs1_sha384': 'PKCS1WithSHA384',
    'rsa_pkcs1_sha256': 'PKCS1WithSHA256',
    'rsa_pkcs1_sha224': 'PKCS1WithSHA224',
    'rsa_pkcs1_sha1': 'PKCS1WithSHA1',
    'dsa_sha512': 'DSAWithSHA512',
    'dsa_sha384': 'DSAWithSHA384',
    'dsa_sha256': 'DSAWithSHA256',
    'dsa_sha224': 'DSAWithSHA224',
    'dsa_sha1': 'DSAWithSHA1',
    'ecdsa_sha512': 'ECDSAWithSHA512',
    'ecdsa_sha384': 'ECDSAWithSHA384',
    'ecdsa_sha256': 'ECDSAWithSHA256',
    'ecdsa_sha224': 'ECDSAWithSHA224',
    'ecdsa_sha1': 'ECDSAWithSHA1',
    'rsa_pss_rsae_sha512': 'PSSWithSHA512',
    'rsa_pss_rsae_sha384': 'PSSWithSHA384',
    'rsa_pss_rsae_sha256': 'PSSWithSHA256',
    'rsa_pss_rsae_sha224': 'PSSWithSHA224',
    'rsa_pss_rsae_sha1': 'PSSWithSHA1',
    'ecdsa_secp521r1_sha512': 'ECDSAWithP521AndSHA512',
    'ecdsa_secp384r1_sha384': 'ECDSAWithP384AndSHA384',
    'ecdsa_secp256r1_sha256': 'ECDSAWithP256AndSHA256',
    'ecdsa_secp224r1_sha224': 'ECDSAWithP224AndSHA224',
}


def to_tls_config(config: dict) -> TLSConfig:
    tls_config = TLSConfig()
    tls_config.ja3 = get_ja3_string(config)
    tls_config.headers_order = get_header_order(config)
    tls_config.force_http1 = get_force_http1(config)
    tls_config.pseudo_header_order = get_pseudo_header_order(config)

    tls_config.tls_extensions.supported_signature_algorithms = get_supported_signature_algorithms(config)
    tls_config.tls_extensions.cert_compression_algo = get_cert_compression_algo(config)
    tls_config.tls_extensions.record_size_limit = get_record_size_limit(config)
    tls_config.tls_extensions.supported_delegated_credentials_algorithms = get_supported_delegated_credentials_algorithms(config)
    tls_config.tls_extensions.supported_versions = get_supported_versions(config)
    tls_config.tls_extensions.psk_key_exchange_modes = get_psk_key_exchange_modes(config)
    tls_config.tls_extensions.signature_algorithms_cert = get_signature_algorithms_cert(config)
    tls_config.tls_extensions.key_share_curves = get_key_share_curves(config)
    tls_config.tls_extensions.not_used_grease = get_not_used_grease(config)

    tls_config.http2_settings.settings = get_h2_settings(config)
    tls_config.http2_settings.settings_order = get_h2_settings_order(config)
    tls_config.http2_settings.connection_flow = get_connection_flow(config)
    tls_config.http2_settings.header_priority = get_header_priority(config)
    tls_config.http2_settings.priority_frames = get_priority_frames(config)

    return tls_config


def get_ja3_string(config):
    ja3_string = config["tls"]["ja3"]
    return ja3_string


def get_header_order(config):
    headers = {}
    headers_list = []
    sent_frames = config["http2"]["sent_frames"]
    for sent_frame in sent_frames:
        if sent_frame["frame_type"] == "HEADERS":
            headers_list = sent_frame["headers"]
            break
    for header in headers_list:
        if header[0] == ":":
            continue
        key, value = header.split(":", 1)
        key = key.strip()
        value = value.strip()
        headers[key] = value
    return list(headers.keys())


def get_force_http1(config):
    force_http1 = False
    if config["http_version"] != "h2":
        force_http1 = True
    return force_http1


def get_pseudo_header_order(config):
    headers = {}
    headers_list = []
    sent_frames = config["http2"]["sent_frames"]
    for sent_frame in sent_frames:
        if sent_frame["frame_type"] == "HEADERS":
            headers_list = sent_frame["headers"]
            break
    for header in headers_list:
        if header[0] == ":":
            key, value = header.split(":")[1:]
            key = ":" + key.strip()
            value = value.strip()
            headers[key] = value
    return list(headers.keys())


def get_supported_signature_algorithms(config):
    supported_signature_algorithms = []
    extensions = config["tls"]["extensions"]
    for extension in extensions:
        if extension.get("signature_algorithms", False):
            signature_algorithms = extension["signature_algorithms"]
            for signature_algorithm in signature_algorithms:
                supported_signature_algorithms.append(signature_algorithm)
    if supported_signature_algorithms:
        return supported_signature_algorithms
    return None


def get_cert_compression_algo(config):
    cert_compression_algo = None
    extensions = config["tls"]["extensions"]
    for extension in extensions:
        if "compress_certificate" in extension["name"]:
            for algorithm in extension["algorithms"]:
                if not cert_compression_algo:
                    cert_compression_algo = []
                cert_compression_algo.append(algorithm.split("(", 1)[0].strip())
    return cert_compression_algo


def get_record_size_limit(config):
    record_size_limit = None
    extensions = config["tls"]["extensions"]
    for extension in extensions:
        if "record_size_limit" in extension["name"]:
            record_size_limit = int(extension["data"])
    return record_size_limit


def get_supported_delegated_credentials_algorithms(config):
    supported_delegated_credentials_algorithms = []
    extensions = config["tls"]["extensions"]
    for extension in extensions:
        if extension.get("signature_hash_algorithms", False):
            delegated_credentials_algorithms = extension["signature_hash_algorithms"]
            for delegated_credentials_algorithm in delegated_credentials_algorithms:
                supported_delegated_credentials_algorithms.append(delegated_credentials_algorithm)
    if supported_delegated_credentials_algorithms:
        return supported_delegated_credentials_algorithms
    return None


def get_supported_versions(config):
    supported_versions = []
    extensions = config["tls"]["extensions"]
    for extension in extensions:
        if "supported_versions" in extension["name"]:
            versions = extension["versions"]
            for version in versions:
                key = version
                if "TLS_" in key:
                    key = key.split("TLS_", 1)[-1]
                elif "TLS " in key:
                    key = key.split("TLS ", 1)[-1]
                key = key.split("(", 1)[0]
                key = key.strip()
                supported_versions.append(key)
    if supported_versions:
        return supported_versions
    return None


def get_psk_key_exchange_modes(config):
    psk_key_exchange_modes = None
    extensions = config["tls"]["extensions"]
    for extension in extensions:
        if "psk_key_exchange_modes" in extension["name"]:
            if not psk_key_exchange_modes:
                psk_key_exchange_modes = []
            if extension.get("PSK_Key_Exchange_Mode", ""):
                if extension["PSK_Key_Exchange_Mode"].endswith("(0)"):
                    psk_key_exchange_modes.append("PskModePlain")
                else:
                    psk_key_exchange_modes.append("PskModeDHE")
    return psk_key_exchange_modes


# 没法实现
def get_signature_algorithms_cert(config):
    pass


def get_key_share_curves(config):
    key_share_curves = []
    extensions = config["tls"]["extensions"]
    for extension in extensions:
        if "key_share" in extension["name"]:
            shared_keys = extension["shared_keys"]
            for shared_key in shared_keys:
                key = list(shared_key.keys())[0]
                key = key.split("TLS_", 1)[-1]
                key = key.split("(", 1)[0]
                key = key.strip()
                key = key.replace("-", "")
                if key in ["GREASE", "P256", "P384", "P521", "X25519"]:
                    key_share_curves.append(key)
                else:
                    key = list(shared_key.keys())[0].split("(")[-1].rstrip(")")
                    if "0x" in key:
                        key_share_curves.append(str(int(key, 16)))
                    else:
                        key_share_curves.append(key)
    if key_share_curves:
        return key_share_curves
    return None


def get_not_used_grease(config):
    not_used_grease = False
    if "TLS_GREASE" not in config["tls"]["extensions"][0]["name"]:
        not_used_grease = True
    return not_used_grease


def get_h2_settings(config):
    settings = {}
    setting_list = []
    sent_frames = config["http2"]["sent_frames"]
    for sent_frame in sent_frames:
        if sent_frame["frame_type"] == "SETTINGS":
            setting_list = sent_frame["settings"]
    for setting in setting_list:
        key, value = setting.split("=", 1)
        key = key.strip()
        value = value.strip()
        settings[key] = int(value)
    if settings:
        return settings
    return None


def get_h2_settings_order(config):
    settings = get_h2_settings(config)
    return list(settings.keys())


def get_connection_flow(config):
    connection_flow = None
    sent_frames = config["http2"]["sent_frames"]
    for sent_frame in sent_frames:
        if sent_frame["frame_type"] == "WINDOW_UPDATE":
            connection_flow = sent_frame["increment"]
            break
    return connection_flow


def get_header_priority(config):
    header_priority = None
    sent_frames = config["http2"]["sent_frames"]
    for sent_frame in sent_frames:
        if sent_frame["frame_type"] == "HEADERS":
            if sent_frame.get("priority", False):
                priority = sent_frame["priority"]
                header_priority = {
                    "weight": priority["weight"],
                    "streamDep": priority["depends_on"],
                    "exclusive": True if priority["exclusive"] else False
                }
                break
    return header_priority


def get_priority_frames(config):
    priority_frames = []
    sent_frames = config["http2"]["sent_frames"]
    for sent_frame in sent_frames:
        if sent_frame["frame_type"] == "PRIORITY":
            priority = sent_frame["priority"]
            priority_frame = {
                "streamID": sent_frame["stream_id"],
                "priorityParam": {
                    "weight": priority["weight"],
                    "streamDep": priority["depends_on"],
                    "exclusive": True if priority["exclusive"] else False
                }
            }
            priority_frames.append(priority_frame)
    if priority_frames:
        return priority_frames
    return None
