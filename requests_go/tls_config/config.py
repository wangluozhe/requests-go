import uuid
import random

from .extensions import TLSExtensions, HTTP2Settings


class TLSConfig:
    def __init__(self):
        super(TLSConfig, self).__init__()
        self._keys = [
            "id",
            "ja3",
            "headers_order",
            "un_changed_header_key",
            "force_http1",
            "pseudo_header_order",
            "tls_extensions",
            "http2_settings",
        ]
        self.id: str = str(uuid.uuid4())  # session id, Used to maintain session
        self._ja3: str or JA3Random = None  # tls ja3 value
        self.headers_order: list[str] = None  # http headers order
        self.un_changed_header_key: list[str] = None  # http un changed header key
        self.force_http1: bool = False  # force http1 request
        # :method
        # :authority
        # :scheme
        # :path
        # Example:
        # [
        #     ":method",
        #     ":authority",
        #     ":scheme",
        #     ":path"
        # ]
        self.pseudo_header_order: list[str] = [
            ":method",
            ":authority",
            ":scheme",
            ":path"
        ]  # HTTP2 Pseudo header order
        self.tls_extensions: TLSExtensions = TLSExtensions()  # tls extensions
        self.http2_settings: HTTP2Settings = HTTP2Settings()  # http2 extensions

    def __str__(self):
        return str(self.toJSON())

    def __iter__(self):
        for key in self._keys:
            yield key, getattr(self, key)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __getitem__(self, item):
        return getattr(self, item)

    def __delitem__(self, key):
        setattr(self, key, None)

    def __delattr__(self, item):
        setattr(self, item, None)

    @property
    def ja3(self):
        if type(self._ja3) == JA3Random:
            return self._ja3.ja3
        return self._ja3

    @ja3.setter
    def ja3(self, ja3):
        self._ja3 = ja3

    # JSON转类
    def _fromJSON(self, config: dict):
        for key, value in config.items():
            if key in self._keys:
                setattr(self, key, value)

    # 类转JSON
    def toJSON(self):
        result = {}
        for key in self._keys:
            go_keys = key.split("_")
            go_key = ""
            for k in go_keys:
                if k == "tls" or k == "http2" or k == "http1":
                    go_key += k.upper()
                else:
                    go_key += k.title()
            if key in ["tls_extensions", "http2_settings"]:
                result[go_key] = getattr(self, key).toJSON()
            else:
                result[go_key] = getattr(self, key)
        return result


# 随机化ja3指纹
def random_ja3(ja3: str):
    ssl_version, ciphers, extensions, curves, orders = ja3.split(",")
    extensions_list = extensions.split("-")
    is_41 = False
    if "41" in extensions_list:
        is_41 = True
    if not is_41:
        random.shuffle(extensions_list)
    else:
        for index in range(len(extensions_list)):
            if extensions_list[index] == "41":
                del extensions_list[index]
        random.shuffle(extensions_list)
        extensions_list.append("41")
    extensions = "-".join(extensions_list)
    return ",".join([ssl_version, ciphers, extensions, curves, orders])


# 随机化ja3指纹
class JA3Random:
    def __init__(self, ja3: str):
        self._ja3 = ja3

    @property
    def ja3(self):
        return random_ja3(self._ja3)


TLS_CHROME_103 = TLSConfig()
TLS_CHROME_103.ja3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"
TLS_CHROME_103.pseudo_header_order = [
    ":method",
    ":authority",
    ":scheme",
    ":path"
]
TLS_CHROME_103.tls_extensions.supported_signature_algorithms = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512"
]
TLS_CHROME_103.tls_extensions.cert_compression_algo = [
    "brotli"
]
TLS_CHROME_103.tls_extensions.record_size_limit = 4001
TLS_CHROME_103.tls_extensions.supported_delegated_credentials_algorithms = None
TLS_CHROME_103.tls_extensions.supported_versions = [
    "GREASE",
    "1.3",
    "1.2"
]
TLS_CHROME_103.tls_extensions.psk_key_exchange_modes = [
    "PskModeDHE"
]
TLS_CHROME_103.tls_extensions.signature_algorithms_cert = None
TLS_CHROME_103.tls_extensions.key_share_curves = [
    "GREASE",
    "X25519"
]
TLS_CHROME_103.tls_extensions.not_used_grease = False
TLS_CHROME_103.http2_settings.settings = {
    "HEADER_TABLE_SIZE": 65536,
    "MAX_CONCURRENT_STREAMS": 1000,
    "INITIAL_WINDOW_SIZE": 6291456,
    "MAX_HEADER_LIST_SIZE": 262144
}
TLS_CHROME_103.http2_settings.settings_order = [
    "HEADER_TABLE_SIZE",
    "MAX_CONCURRENT_STREAMS",
    "INITIAL_WINDOW_SIZE",
    "MAX_HEADER_LIST_SIZE"
]
TLS_CHROME_103.http2_settings.connection_flow = 15663105
TLS_CHROME_103.http2_settings.header_priority = {
    "weight": 256,
    "streamDep": 0,
    "exclusive": True
}
TLS_CHROME_103.http2_settings.priority_frames = None


TLS_CHROME_110_LATEST = TLSConfig()
TLS_CHROME_110_LATEST.ja3 = JA3Random("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,65281-13-18-65037-11-0-43-16-51-27-21-5-23-10-17513-35-45-41,29-23-24,0")
TLS_CHROME_110_LATEST.pseudo_header_order = [
    ":method",
    ":authority",
    ":scheme",
    ":path"
]
TLS_CHROME_110_LATEST.tls_extensions.supported_signature_algorithms = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512"
]
TLS_CHROME_110_LATEST.tls_extensions.cert_compression_algo = [
    "brotli"
]
TLS_CHROME_110_LATEST.tls_extensions.record_size_limit = 4001
TLS_CHROME_110_LATEST.tls_extensions.supported_delegated_credentials_algorithms = None
TLS_CHROME_110_LATEST.tls_extensions.supported_versions = [
    "GREASE",
    "1.3",
    "1.2"
]
TLS_CHROME_110_LATEST.tls_extensions.psk_key_exchange_modes = [
    "PskModeDHE"
]
TLS_CHROME_110_LATEST.tls_extensions.signature_algorithms_cert = None
TLS_CHROME_110_LATEST.tls_extensions.key_share_curves = [
    "GREASE",
    "X25519"
]
TLS_CHROME_110_LATEST.tls_extensions.not_used_grease = False
TLS_CHROME_110_LATEST.http2_settings.settings = {
    "HEADER_TABLE_SIZE": 65536,
    "ENABLE_PUSH": 0,
    "MAX_CONCURRENT_STREAMS": 1000,
    "INITIAL_WINDOW_SIZE": 6291456,
    "MAX_HEADER_LIST_SIZE": 262144
}
TLS_CHROME_110_LATEST.http2_settings.settings_order = [
    "HEADER_TABLE_SIZE",
    "ENABLE_PUSH",
    "MAX_CONCURRENT_STREAMS",
    "INITIAL_WINDOW_SIZE",
    "MAX_HEADER_LIST_SIZE"
]
TLS_CHROME_110_LATEST.http2_settings.connection_flow = 15663105
TLS_CHROME_110_LATEST.http2_settings.header_priority = {
    "weight": 256,
    "streamDep": 0,
    "exclusive": True
}
TLS_CHROME_110_LATEST.http2_settings.priority_frames = None


TLS_FIREFOX_105 = TLSConfig()
TLS_FIREFOX_105.ja3 = "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-34-51-43-13-45-28-41,29-23-24-25-256-257,0"
TLS_FIREFOX_105.pseudo_header_order = [
    ":method",
    ":path",
    ":authority",
    ":scheme"
]
TLS_FIREFOX_105.tls_extensions.supported_signature_algorithms = [
    "ecdsa_secp256r1_sha256",
    "ecdsa_secp384r1_sha384",
    "ecdsa_secp521r1_sha512",
    "rsa_pss_rsae_sha256",
    "rsa_pss_rsae_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha256",
    "rsa_pkcs1_sha384",
    "rsa_pkcs1_sha512",
    "ecdsa_sha1",
    "rsa_pkcs1_sha1"
]
TLS_FIREFOX_105.tls_extensions.cert_compression_algo = None
TLS_FIREFOX_105.tls_extensions.record_size_limit = 4001
TLS_FIREFOX_105.tls_extensions.supported_delegated_credentials_algorithms = [
    "ecdsa_secp256r1_sha256",
    "ecdsa_secp384r1_sha384",
    "ecdsa_secp521r1_sha512",
    "ecdsa_sha1"
]
TLS_FIREFOX_105.tls_extensions.supported_versions = [
    "1.3",
    "1.2"
]
TLS_FIREFOX_105.tls_extensions.psk_key_exchange_modes = [
    "PskModeDHE"
]
TLS_FIREFOX_105.tls_extensions.signature_algorithms_cert = None
TLS_FIREFOX_105.tls_extensions.key_share_curves = [
    "X25519",
    "P256"
]
TLS_FIREFOX_105.tls_extensions.not_used_grease = True
TLS_FIREFOX_105.http2_settings.settings = {
    "HEADER_TABLE_SIZE": 65536,
    "INITIAL_WINDOW_SIZE": 131072,
    "MAX_FRAME_SIZE": 16384
}
TLS_FIREFOX_105.http2_settings.settings_order = [
    "HEADER_TABLE_SIZE",
    "INITIAL_WINDOW_SIZE",
    "MAX_FRAME_SIZE"
]
TLS_FIREFOX_105.http2_settings.connection_flow = 12517377
TLS_FIREFOX_105.http2_settings.header_priority = {
    "weight": 42,
    "streamDep": 13,
    "exclusive": False
}
TLS_FIREFOX_105.http2_settings.priority_frames = [
    {
        "streamID": 3,
        "priorityParam": {
            "weight": 201,
            "streamDep": 0,
            "exclusive": False
        }
    },
    {
        "streamID": 5,
        "priorityParam": {
            "weight": 101,
            "streamDep": 0,
            "exclusive": False
        }
    },
    {
        "streamID": 7,
        "priorityParam": {
            "weight": 1,
            "streamDep": 0,
            "exclusive": False
        }
    },
    {
        "streamID": 9,
        "priorityParam": {
            "weight": 1,
            "streamDep": 7,
            "exclusive": False
        }
    },
    {
        "streamID": 11,
        "priorityParam": {
            "weight": 1,
            "streamDep": 3,
            "exclusive": False
        }
    },
    {
        "streamID": 13,
        "priorityParam": {
            "weight": 241,
            "streamDep": 0,
            "exclusive": False
        }
    }
]
