import uuid
import random

from .extensions import TLSExtensions, HTTP2Settings


class TLSConfig:
    def __init__(self):
        super(TLSConfig, self).__init__()
        self.__keys = [
            "id",
            "ja3",
            "random_ja3",
            "headers_order",
            "un_changed_header_key",
            "force_http1",
            "pseudo_header_order",
            "tls_extensions",
            "http2_settings",
        ]
        self.id: str = str(uuid.uuid4())  # session id, Used to maintain session
        self.__ja3: JA3 = None  # tls ja3 value
        self.__random_ja3: bool = False  # ja3 is it random
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
        for key in self.__keys:
            yield key, getattr(self, key)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __getitem__(self, item):
        return getattr(self, item)

    def __delitem__(self, key):
        setattr(self, key, None)

    def __delattr__(self, item):
        setattr(self, item, None)

    def __eq__(self, other):
        if type(self) is not type(other):
            raise TypeError("Cannot compare {} to {}".format(type(self), type(other)))
        if self.ja3 != other.ja3:
            return False
        if self.pseudo_header_order != other.pseudo_header_order:
            return False
        if self.tls_extensions != other.tls_extensions:
            return False
        if self.http2_settings != other.http2_settings:
            return False
        return True

    def get(self, key, default=None):
        return getattr(self, key, default)

    @property
    def ja3(self):
        return self.__ja3

    @ja3.setter
    def ja3(self, ja3):
        if type(ja3) in [str, JA3]:
            if type(ja3) == str:
                self.__ja3 = JA3(ja3, random=self.random_ja3)
            else:
                self.__ja3 = ja3
        else:
            raise TypeError("Only str and JA3Random types can be defined")

    @property
    def random_ja3(self):
        return self.__random_ja3

    @random_ja3.setter
    def random_ja3(self, random_ja3):
        if type(random_ja3) is bool:
            if self.__ja3:
                self.__ja3.random = random_ja3
            self.__random_ja3 = random_ja3
        else:
            raise TypeError("Only bool type can be defined")

    # JSON转类
    def fromJSON(self, config: dict):
        for key, value in config.items():
            if key == "id":
                continue
            elif key == "tls_extensions":
                setattr(self, key, TLSExtensions().fromJSON(value))
            elif key == "http2_settings":
                setattr(self, key, HTTP2Settings().fromJSON(value))
            elif key in self.__keys:
                setattr(self, key, value)
        return self

    # 类转JSON
    def toJSON(self):
        result = {}
        for key in self.__keys:
            if key in ["tls_extensions", "http2_settings"]:
                result[key] = getattr(self, key).toJSON()
            elif key == "ja3":
                result[key] = str(getattr(self, key))
            else:
                result[key] = getattr(self, key)
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


# JA3指纹
class JA3:
    def __init__(self, ja3: str, random: bool = False):
        self.__ja3 = ja3
        self.__random = random

    def __str__(self):
        if self.__random:
            return random_ja3(self.__ja3)
        return self.__ja3

    def __eq__(self, other):
        if type(self) is not type(other):
            raise TypeError("Cannot compare {} to {}".format(type(self), type(other)))
        if self.random != other.random:
            return False
        ja1s = str(self).split(",")
        ja2s = str(other).split(",")
        for i, (ja1i, ja2i) in enumerate(zip(ja1s, ja2s)):
            if i == 2 and self.__random:
                ja1i_list = ja1i.split("-")
                ja2i_list = ja2i.split("-")
                ja1i_list.sort()
                ja2i_list.sort()
                if ja1i_list != ja2i_list:
                    return False
            elif ja1i != ja2i:
                return False
        return True

    @property
    def random(self):
        return self.__random

    @random.setter
    def random(self, random):
        if type(random) is bool:
            self.__random = random
        else:
            raise TypeError("Only bool type can be defined")


TLS_CHROME_131_LATEST = TLSConfig()
TLS_CHROME_131_LATEST.fromJSON({'id': '6125808d-ccc4-4f4b-9b26-e0c7abd3b279', 'ja3': '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-10-23-35-27-16-18-13-17513-65037-11-51-65281-5-0-43-41,4588-29-23-24,0', 'random_ja3': True, 'headers_order': ['cache-control', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'upgrade-insecure-requests', 'user-agent', 'accept', 'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-user', 'sec-fetch-dest', 'accept-encoding', 'accept-language', 'priority'], 'un_changed_header_key': None, 'force_http1': False, 'pseudo_header_order': [':method', ':authority', ':scheme', ':path'], 'tls_extensions': {'supported_signature_algorithms': ['ecdsa_secp256r1_sha256', 'rsa_pss_rsae_sha256', 'rsa_pkcs1_sha256', 'ecdsa_secp384r1_sha384', 'rsa_pss_rsae_sha384', 'rsa_pkcs1_sha384', 'rsa_pss_rsae_sha512', 'rsa_pkcs1_sha512'], 'cert_compression_algo': ['brotli'], 'record_size_limit': None, 'supported_delegated_credentials_algorithms': None, 'supported_versions': ['GREASE', '1.3', '1.2'], 'psk_key_exchange_modes': ['PskModeDHE'], 'signature_algorithms_cert': None, 'key_share_curves': ['GREASE', '4588', 'X25519'], 'not_used_grease': False}, 'http2_settings': {'settings': {'HEADER_TABLE_SIZE': 65536, 'ENABLE_PUSH': 0, 'INITIAL_WINDOW_SIZE': 6291456, 'MAX_HEADER_LIST_SIZE': 262144}, 'settings_order': ['HEADER_TABLE_SIZE', 'ENABLE_PUSH', 'INITIAL_WINDOW_SIZE', 'MAX_HEADER_LIST_SIZE'], 'connection_flow': 15663105, 'header_priority': {'weight': 256, 'streamDep': 0, 'exclusive': True}, 'priority_frames': None}})


TLS_CHROME_130 = TLSConfig()
TLS_CHROME_130.fromJSON({'id': '78b3ba07-26e5-45e4-8a9b-26ab80831c57', 'ja3': '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,27-13-18-0-65037-51-10-65281-16-11-23-17513-35-43-45-5-41,25497-29-23-24,0', 'random_ja3': True, 'headers_order': ['cache-control', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'upgrade-insecure-requests', 'user-agent', 'accept', 'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-user', 'sec-fetch-dest', 'accept-encoding', 'accept-language', 'priority'], 'un_changed_header_key': None, 'force_http1': False, 'pseudo_header_order': [':method', ':authority', ':scheme', ':path'], 'tls_extensions': {'supported_signature_algorithms': ['ecdsa_secp256r1_sha256', 'rsa_pss_rsae_sha256', 'rsa_pkcs1_sha256', 'ecdsa_secp384r1_sha384', 'rsa_pss_rsae_sha384', 'rsa_pkcs1_sha384', 'rsa_pss_rsae_sha512', 'rsa_pkcs1_sha512'], 'cert_compression_algo': ['brotli'], 'record_size_limit': None, 'supported_delegated_credentials_algorithms': None, 'supported_versions': ['GREASE', '1.3', '1.2'], 'psk_key_exchange_modes': ['PskModeDHE'], 'signature_algorithms_cert': None, 'key_share_curves': ['GREASE', '25497', 'X25519'], 'not_used_grease': False}, 'http2_settings': {'settings': {'HEADER_TABLE_SIZE': 65536, 'ENABLE_PUSH': 0, 'INITIAL_WINDOW_SIZE': 6291456, 'MAX_HEADER_LIST_SIZE': 262144}, 'settings_order': ['HEADER_TABLE_SIZE', 'ENABLE_PUSH', 'INITIAL_WINDOW_SIZE', 'MAX_HEADER_LIST_SIZE'], 'connection_flow': 15663105, 'header_priority': {'weight': 256, 'streamDep': 0, 'exclusive': True}, 'priority_frames': None}})


TLS_CHROME_111_129 = TLSConfig()
TLS_CHROME_111_129.fromJSON({'id': '3cd22dbf-f54e-4e9b-9903-44405c14eaf5', 'ja3': '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,23-0-5-18-35-17513-65281-16-11-13-43-65037-45-51-27-10-41,25497-29-23-24,0', 'random_ja3': True, 'headers_order': ['cache-control', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'upgrade-insecure-requests', 'user-agent', 'accept', 'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-user', 'sec-fetch-dest', 'accept-encoding', 'accept-language'], 'un_changed_header_key': None, 'force_http1': False, 'pseudo_header_order': [':method', ':authority', ':scheme', ':path'], 'tls_extensions': {'supported_signature_algorithms': ['ecdsa_secp256r1_sha256', 'rsa_pss_rsae_sha256', 'rsa_pkcs1_sha256', 'ecdsa_secp384r1_sha384', 'rsa_pss_rsae_sha384', 'rsa_pkcs1_sha384', 'rsa_pss_rsae_sha512', 'rsa_pkcs1_sha512'], 'cert_compression_algo': ['brotli'], 'record_size_limit': None, 'supported_delegated_credentials_algorithms': None, 'supported_versions': ['GREASE', '1.3', '1.2'], 'psk_key_exchange_modes': ['PskModeDHE'], 'signature_algorithms_cert': None, 'key_share_curves': ['GREASE', '25497', 'X25519'], 'not_used_grease': False}, 'http2_settings': {'settings': {'HEADER_TABLE_SIZE': 65536, 'ENABLE_PUSH': 0, 'INITIAL_WINDOW_SIZE': 6291456, 'MAX_HEADER_LIST_SIZE': 262144}, 'settings_order': ['HEADER_TABLE_SIZE', 'ENABLE_PUSH', 'INITIAL_WINDOW_SIZE', 'MAX_HEADER_LIST_SIZE'], 'connection_flow': 15663105, 'header_priority': {'weight': 256, 'streamDep': 0, 'exclusive': True}, 'priority_frames': None}})


TLS_CHROME_122 = TLSConfig()
TLS_CHROME_122.fromJSON({'id': '21d82810-982f-4816-9614-e17746728ae5', 'ja3': '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,11-16-13-5-51-23-0-45-65281-27-35-65037-17513-18-10-43-41,29-23-24,0', 'random_ja3': True, 'headers_order': ['cache-control', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'upgrade-insecure-requests', 'user-agent', 'accept', 'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-user', 'sec-fetch-dest', 'accept-encoding', 'accept-language'], 'un_changed_header_key': None, 'force_http1': False, 'pseudo_header_order': [':method', ':authority', ':scheme', ':path'], 'tls_extensions': {'supported_signature_algorithms': ['ecdsa_secp256r1_sha256', 'rsa_pss_rsae_sha256', 'rsa_pkcs1_sha256', 'ecdsa_secp384r1_sha384', 'rsa_pss_rsae_sha384', 'rsa_pkcs1_sha384', 'rsa_pss_rsae_sha512', 'rsa_pkcs1_sha512'], 'cert_compression_algo': ['brotli'], 'record_size_limit': None, 'supported_delegated_credentials_algorithms': None, 'supported_versions': ['GREASE', '1.3', '1.2'], 'psk_key_exchange_modes': ['PskModeDHE'], 'signature_algorithms_cert': None, 'key_share_curves': ['GREASE', 'X25519'], 'not_used_grease': False}, 'http2_settings': {'settings': {'HEADER_TABLE_SIZE': 65536, 'ENABLE_PUSH': 0, 'INITIAL_WINDOW_SIZE': 6291456, 'MAX_HEADER_LIST_SIZE': 262144}, 'settings_order': ['HEADER_TABLE_SIZE', 'ENABLE_PUSH', 'INITIAL_WINDOW_SIZE', 'MAX_HEADER_LIST_SIZE'], 'connection_flow': 15663105, 'header_priority': {'weight': 256, 'streamDep': 0, 'exclusive': True}, 'priority_frames': None}})


TLS_CHROME_110_LATEST = TLSConfig()
TLS_CHROME_110_LATEST.fromJSON({'id': 'f5e378c9-838e-45f8-98ee-012c9f6b4e7f', 'ja3': '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,35-23-0-21-27-13-65281-65037-17513-45-10-43-5-16-18-51-11-41,29-23-24,0', 'random_ja3': True, 'headers_order': None, 'un_changed_header_key': None, 'force_http1': False, 'pseudo_header_order': [':method', ':authority', ':scheme', ':path'], 'tls_extensions': {'supported_signature_algorithms': ['ecdsa_secp256r1_sha256', 'rsa_pss_rsae_sha256', 'rsa_pkcs1_sha256', 'ecdsa_secp384r1_sha384', 'rsa_pss_rsae_sha384', 'rsa_pkcs1_sha384', 'rsa_pss_rsae_sha512', 'rsa_pkcs1_sha512'], 'cert_compression_algo': ['brotli'], 'record_size_limit': 4001, 'supported_delegated_credentials_algorithms': None, 'supported_versions': ['GREASE', '1.3', '1.2'], 'psk_key_exchange_modes': ['PskModeDHE'], 'signature_algorithms_cert': None, 'key_share_curves': ['GREASE', 'X25519'], 'not_used_grease': False}, 'http2_settings': {'settings': {'HEADER_TABLE_SIZE': 65536, 'ENABLE_PUSH': 0, 'MAX_CONCURRENT_STREAMS': 1000, 'INITIAL_WINDOW_SIZE': 6291456, 'MAX_HEADER_LIST_SIZE': 262144}, 'settings_order': ['HEADER_TABLE_SIZE', 'ENABLE_PUSH', 'MAX_CONCURRENT_STREAMS', 'INITIAL_WINDOW_SIZE', 'MAX_HEADER_LIST_SIZE'], 'connection_flow': 15663105, 'header_priority': {'weight': 256, 'streamDep': 0, 'exclusive': True}, 'priority_frames': None}})
TLS_CHROME_110 = TLS_CHROME_110_LATEST


TLS_CHROME_103 = TLSConfig()
TLS_CHROME_103.fromJSON({'id': '3bac8a11-37c0-4789-8d0d-6180fa4ae9b9', 'ja3': '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0', 'random_ja3': False, 'headers_order': None, 'un_changed_header_key': None, 'force_http1': False, 'pseudo_header_order': [':method', ':authority', ':scheme', ':path'], 'tls_extensions': {'supported_signature_algorithms': ['ecdsa_secp256r1_sha256', 'rsa_pss_rsae_sha256', 'rsa_pkcs1_sha256', 'ecdsa_secp384r1_sha384', 'rsa_pss_rsae_sha384', 'rsa_pkcs1_sha384', 'rsa_pss_rsae_sha512', 'rsa_pkcs1_sha512'], 'cert_compression_algo': ['brotli'], 'record_size_limit': 4001, 'supported_delegated_credentials_algorithms': None, 'supported_versions': ['GREASE', '1.3', '1.2'], 'psk_key_exchange_modes': ['PskModeDHE'], 'signature_algorithms_cert': None, 'key_share_curves': ['GREASE', 'X25519'], 'not_used_grease': False}, 'http2_settings': {'settings': {'HEADER_TABLE_SIZE': 65536, 'MAX_CONCURRENT_STREAMS': 1000, 'INITIAL_WINDOW_SIZE': 6291456, 'MAX_HEADER_LIST_SIZE': 262144}, 'settings_order': ['HEADER_TABLE_SIZE', 'MAX_CONCURRENT_STREAMS', 'INITIAL_WINDOW_SIZE', 'MAX_HEADER_LIST_SIZE'], 'connection_flow': 15663105, 'header_priority': {'weight': 256, 'streamDep': 0, 'exclusive': True}, 'priority_frames': None}})


TLS_EDGE_131_LATEST = TLSConfig()
TLS_EDGE_131_LATEST.fromJSON({'id': '3122d7de-081b-44d0-b68d-8ac227d3fcb7', 'ja3': '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,65281-17513-13-65037-43-5-35-16-11-10-23-51-0-18-45-27-41,4588-29-23-24,0', 'random_ja3': True, 'headers_order': ['cache-control', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'upgrade-insecure-requests', 'user-agent', 'accept', 'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-user', 'sec-fetch-dest', 'accept-encoding', 'accept-language', 'priority'], 'un_changed_header_key': None, 'force_http1': False, 'pseudo_header_order': [':method', ':authority', ':scheme', ':path'], 'tls_extensions': {'supported_signature_algorithms': ['ecdsa_secp256r1_sha256', 'rsa_pss_rsae_sha256', 'rsa_pkcs1_sha256', 'ecdsa_secp384r1_sha384', 'rsa_pss_rsae_sha384', 'rsa_pkcs1_sha384', 'rsa_pss_rsae_sha512', 'rsa_pkcs1_sha512'], 'cert_compression_algo': ['brotli'], 'record_size_limit': None, 'supported_delegated_credentials_algorithms': None, 'supported_versions': ['GREASE', '1.3', '1.2'], 'psk_key_exchange_modes': ['PskModeDHE'], 'signature_algorithms_cert': None, 'key_share_curves': ['GREASE', '4588', 'X25519'], 'not_used_grease': False}, 'http2_settings': {'settings': {'HEADER_TABLE_SIZE': 65536, 'ENABLE_PUSH': 0, 'INITIAL_WINDOW_SIZE': 6291456, 'MAX_HEADER_LIST_SIZE': 262144}, 'settings_order': ['HEADER_TABLE_SIZE', 'ENABLE_PUSH', 'INITIAL_WINDOW_SIZE', 'MAX_HEADER_LIST_SIZE'], 'connection_flow': 15663105, 'header_priority': {'weight': 256, 'streamDep': 0, 'exclusive': True}, 'priority_frames': None}})


TLS_FIREFOX_135 = TLSConfig()
TLS_FIREFOX_135.fromJSON({'id': '4b2020df-0a3c-4c9c-b73e-2ba48246593e', 'ja3': '771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,51-10-23-34-65281-13-18-35-11-27-43-5-0-45-16-65037-28,4588-29-23-24-25-256-257,0', 'random_ja3': True, 'headers_order': ['user-agent', 'accept', 'accept-language', 'accept-encoding', 'upgrade-insecure-requests', 'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'sec-fetch-user', 'priority', 'te'], 'un_changed_header_key': None, 'force_http1': False, 'pseudo_header_order': [':method', ':path', ':authority', ':scheme'], 'tls_extensions': {'supported_signature_algorithms': ['ecdsa_secp256r1_sha256', 'ecdsa_secp384r1_sha384', 'ecdsa_secp521r1_sha512', 'rsa_pss_rsae_sha256', 'rsa_pss_rsae_sha384', 'rsa_pss_rsae_sha512', 'rsa_pkcs1_sha256', 'rsa_pkcs1_sha384', 'rsa_pkcs1_sha512', 'ecdsa_sha1', 'rsa_pkcs1_sha1'], 'cert_compression_algo': ['zlib', 'brotli', 'zstd'], 'record_size_limit': 4001, 'supported_delegated_credentials_algorithms': ['ecdsa_secp256r1_sha256', 'ecdsa_secp384r1_sha384', 'ecdsa_secp521r1_sha512', 'ecdsa_sha1'], 'supported_versions': ['1.3', '1.2'], 'psk_key_exchange_modes': ['PskModeDHE'], 'signature_algorithms_cert': None, 'key_share_curves': ['4588', 'X25519', 'P256'], 'not_used_grease': True}, 'http2_settings': {'settings': {'HEADER_TABLE_SIZE': 65536, 'ENABLE_PUSH': 0, 'INITIAL_WINDOW_SIZE': 131072, 'MAX_FRAME_SIZE': 16384}, 'settings_order': ['HEADER_TABLE_SIZE', 'ENABLE_PUSH', 'INITIAL_WINDOW_SIZE', 'MAX_FRAME_SIZE'], 'connection_flow': 12517377, 'header_priority': {'weight': 42, 'streamDep': 0, 'exclusive': False}, 'priority_frames': None}})


TLS_FIREFOX_134 = TLSConfig()
TLS_FIREFOX_134.fromJSON({'id': '267254b7-0636-47f0-bf90-ac7539d1d3b5', 'ja3': '771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,13-51-34-65037-23-35-16-27-0-65281-45-5-11-10-43-28,4588-29-23-24-25-256-257,0', 'random_ja3': True, 'headers_order': ['user-agent', 'accept', 'accept-language', 'accept-encoding', 'upgrade-insecure-requests', 'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'sec-fetch-user', 'priority', 'te'], 'un_changed_header_key': None, 'force_http1': False, 'pseudo_header_order': [':method', ':path', ':authority', ':scheme'], 'tls_extensions': {'supported_signature_algorithms': ['ecdsa_secp256r1_sha256', 'ecdsa_secp384r1_sha384', 'ecdsa_secp521r1_sha512', 'rsa_pss_rsae_sha256', 'rsa_pss_rsae_sha384', 'rsa_pss_rsae_sha512', 'rsa_pkcs1_sha256', 'rsa_pkcs1_sha384', 'rsa_pkcs1_sha512', 'ecdsa_sha1', 'rsa_pkcs1_sha1'], 'cert_compression_algo': ['zlib', 'brotli', 'zstd'], 'record_size_limit': 4001, 'supported_delegated_credentials_algorithms': ['ecdsa_secp256r1_sha256', 'ecdsa_secp384r1_sha384', 'ecdsa_secp521r1_sha512', 'ecdsa_sha1'], 'supported_versions': ['1.3', '1.2'], 'psk_key_exchange_modes': ['PskModeDHE'], 'signature_algorithms_cert': None, 'key_share_curves': ['4588', 'X25519', 'P256'], 'not_used_grease': True}, 'http2_settings': {'settings': {'HEADER_TABLE_SIZE': 65536, 'ENABLE_PUSH': 0, 'INITIAL_WINDOW_SIZE': 131072, 'MAX_FRAME_SIZE': 16384}, 'settings_order': ['HEADER_TABLE_SIZE', 'ENABLE_PUSH', 'INITIAL_WINDOW_SIZE', 'MAX_FRAME_SIZE'], 'connection_flow': 12517377, 'header_priority': {'weight': 42, 'streamDep': 0, 'exclusive': False}, 'priority_frames': None}})


TLS_FIREFOX_126 = TLSConfig()
TLS_FIREFOX_126.fromJSON({'id': 'c53ec2ba-ddfb-4e62-b53d-201db0c95edf', 'ja3': '771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-34-18-51-43-13-45-28-27-65037-41,4588-29-23-24-25-256-257,0', 'random_ja3': True, 'headers_order': ['user-agent', 'accept', 'accept-language', 'accept-encoding', 'upgrade-insecure-requests', 'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'sec-fetch-user', 'priority', 'te'], 'un_changed_header_key': None, 'force_http1': False, 'pseudo_header_order': [':method', ':path', ':authority', ':scheme'], 'tls_extensions': {'supported_signature_algorithms': ['ecdsa_secp256r1_sha256', 'ecdsa_secp384r1_sha384', 'ecdsa_secp521r1_sha512', 'rsa_pss_rsae_sha256', 'rsa_pss_rsae_sha384', 'rsa_pss_rsae_sha512', 'rsa_pkcs1_sha256', 'rsa_pkcs1_sha384', 'rsa_pkcs1_sha512', 'ecdsa_sha1', 'rsa_pkcs1_sha1'], 'cert_compression_algo': ['zlib', 'brotli', 'zstd'], 'record_size_limit': 4001, 'supported_delegated_credentials_algorithms': ['ecdsa_secp256r1_sha256', 'ecdsa_secp384r1_sha384', 'ecdsa_secp521r1_sha512', 'ecdsa_sha1'], 'supported_versions': ['1.3', '1.2'], 'psk_key_exchange_modes': ['PskModeDHE'], 'signature_algorithms_cert': None, 'key_share_curves': ['4588', 'X25519', 'P256'], 'not_used_grease': True}, 'http2_settings': {'settings': {'HEADER_TABLE_SIZE': 65536, 'ENABLE_PUSH': 0, 'INITIAL_WINDOW_SIZE': 131072, 'MAX_FRAME_SIZE': 16384}, 'settings_order': ['HEADER_TABLE_SIZE', 'ENABLE_PUSH', 'INITIAL_WINDOW_SIZE', 'MAX_FRAME_SIZE'], 'connection_flow': 12517377, 'header_priority': {'weight': 42, 'streamDep': 0, 'exclusive': False}, 'priority_frames': None}})


TLS_FIREFOX_105 = TLSConfig()
TLS_FIREFOX_105.fromJSON({'id': 'd5247c24-e65f-45bd-bee9-8996f754cd3c', 'ja3': '771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-34-51-43-13-45-28-41,29-23-24-25-256-257,0', 'random_ja3': False, 'headers_order': None, 'un_changed_header_key': None, 'force_http1': False, 'pseudo_header_order': [':method', ':path', ':authority', ':scheme'], 'tls_extensions': {'supported_signature_algorithms': ['ecdsa_secp256r1_sha256', 'ecdsa_secp384r1_sha384', 'ecdsa_secp521r1_sha512', 'rsa_pss_rsae_sha256', 'rsa_pss_rsae_sha384', 'rsa_pss_rsae_sha512', 'rsa_pkcs1_sha256', 'rsa_pkcs1_sha384', 'rsa_pkcs1_sha512', 'ecdsa_sha1', 'rsa_pkcs1_sha1'], 'cert_compression_algo': None, 'record_size_limit': 4001, 'supported_delegated_credentials_algorithms': ['ecdsa_secp256r1_sha256', 'ecdsa_secp384r1_sha384', 'ecdsa_secp521r1_sha512', 'ecdsa_sha1'], 'supported_versions': ['1.3', '1.2'], 'psk_key_exchange_modes': ['PskModeDHE'], 'signature_algorithms_cert': None, 'key_share_curves': ['X25519', 'P256'], 'not_used_grease': True}, 'http2_settings': {'settings': {'HEADER_TABLE_SIZE': 65536, 'INITIAL_WINDOW_SIZE': 131072, 'MAX_FRAME_SIZE': 16384}, 'settings_order': ['HEADER_TABLE_SIZE', 'INITIAL_WINDOW_SIZE', 'MAX_FRAME_SIZE'], 'connection_flow': 12517377, 'header_priority': {'weight': 42, 'streamDep': 13, 'exclusive': False}, 'priority_frames': [{'streamID': 3, 'priorityParam': {'weight': 201, 'streamDep': 0, 'exclusive': False}}, {'streamID': 5, 'priorityParam': {'weight': 101, 'streamDep': 0, 'exclusive': False}}, {'streamID': 7, 'priorityParam': {'weight': 1, 'streamDep': 0, 'exclusive': False}}, {'streamID': 9, 'priorityParam': {'weight': 1, 'streamDep': 7, 'exclusive': False}}, {'streamID': 11, 'priorityParam': {'weight': 1, 'streamDep': 3, 'exclusive': False}}, {'streamID': 13, 'priorityParam': {'weight': 241, 'streamDep': 0, 'exclusive': False}}]}})
