class TLSExtensions:
    def __init__(self):
        super(TLSExtensions, self).__init__()
        self.__keys = [
            "supported_signature_algorithms",
            "cert_compression_algo",
            "record_size_limit",
            "supported_delegated_credentials_algorithms",
            "supported_versions",
            "psk_key_exchange_modes",
            "signature_algorithms_cert",
            "key_share_curves",
            "not_used_grease",
        ]
        # PKCS1WithSHA256
        # PKCS1WithSHA384
        # PKCS1WithSHA512
        # PSSWithSHA256
        # PSSWithSHA384
        # PSSWithSHA512
        # ECDSAWithP256AndSHA256
        # ECDSAWithP384AndSHA384
        # ECDSAWithP521AndSHA512
        # Ed25519
        # PKCS1WithSHA1
        # ECDSAWithSHA1
        # rsa_pkcs1_sha1
        # Reserved for backward compatibility
        # ecdsa_sha1
        # rsa_pkcs1_sha256
        # ecdsa_secp256r1_sha256
        # rsa_pkcs1_sha256_legacy
        # rsa_pkcs1_sha384
        # ecdsa_secp384r1_sha384
        # rsa_pkcs1_sha384_legacy
        # rsa_pkcs1_sha512
        # ecdsa_secp521r1_sha512
        # rsa_pkcs1_sha512_legacy
        # eccsi_sha256
        # iso_ibs1
        # iso_ibs2
        # iso_chinese_ibs
        # sm2sig_sm3
        # gostr34102012_256a
        # gostr34102012_256b
        # gostr34102012_256c
        # gostr34102012_256d
        # gostr34102012_512a
        # gostr34102012_512b
        # gostr34102012_512c
        # rsa_pss_rsae_sha256
        # rsa_pss_rsae_sha384
        # rsa_pss_rsae_sha512
        # ed25519
        # ed448
        # rsa_pss_pss_sha256
        # rsa_pss_pss_sha384
        # rsa_pss_pss_sha512
        # ecdsa_brainpoolP256r1tls13_sha256
        # ecdsa_brainpoolP384r1tls13_sha384
        # ecdsa_brainpoolP512r1tls13_sha512
        # Or hexadecimal value, for example:
        # 0x402
        # Example:
        # [
        #     "ecdsa_secp256r1_sha256",
        #     "rsa_pss_rsae_sha256",
        #     "rsa_pkcs1_sha256",
        #     "ecdsa_secp384r1_sha384",
        #     "rsa_pss_rsae_sha384",
        #     "rsa_pkcs1_sha384",
        #     "rsa_pss_rsae_sha512",
        #     "rsa_pkcs1_sha512",
        #     "0x402",
        #     "0x302",
        # ]
        self.supported_signature_algorithms: list[str] = [
            "ECDSAWithP256AndSHA256",
            "PSSWithSHA256",
            "PKCS1WithSHA256",
            "ECDSAWithP384AndSHA384",
            "PSSWithSHA384",
            "PKCS1WithSHA384",
            "PSSWithSHA512",
            "PKCS1WithSHA512"
        ]  # Supported signature algorithms
        # zlib
        # brotli
        # zstd
        # Example:
        # [
        #     "brotli",
        # ]
        self.cert_compression_algo: list[str] = ["brotli"]  # Certificate compression algorithm
        self.record_size_limit: int = 4001  # Record Size Limit
        # PKCS1WithSHA256
        # PKCS1WithSHA384
        # PKCS1WithSHA512
        # PSSWithSHA256
        # PSSWithSHA384
        # PSSWithSHA512
        # ECDSAWithP256AndSHA256
        # ECDSAWithP384AndSHA384
        # ECDSAWithP521AndSHA512
        # Ed25519
        # PKCS1WithSHA1
        # ECDSAWithSHA1
        # rsa_pkcs1_sha1
        # Reserved for backward compatibility
        # ecdsa_sha1
        # rsa_pkcs1_sha256
        # ecdsa_secp256r1_sha256
        # rsa_pkcs1_sha256_legacy
        # rsa_pkcs1_sha384
        # ecdsa_secp384r1_sha384
        # rsa_pkcs1_sha384_legacy
        # rsa_pkcs1_sha512
        # ecdsa_secp521r1_sha512
        # rsa_pkcs1_sha512_legacy
        # eccsi_sha256
        # iso_ibs1
        # iso_ibs2
        # iso_chinese_ibs
        # sm2sig_sm3
        # gostr34102012_256a
        # gostr34102012_256b
        # gostr34102012_256c
        # gostr34102012_256d
        # gostr34102012_512a
        # gostr34102012_512b
        # gostr34102012_512c
        # rsa_pss_rsae_sha256
        # rsa_pss_rsae_sha384
        # rsa_pss_rsae_sha512
        # ed25519
        # ed448
        # rsa_pss_pss_sha256
        # rsa_pss_pss_sha384
        # rsa_pss_pss_sha512
        # ecdsa_brainpoolP256r1tls13_sha256
        # ecdsa_brainpoolP384r1tls13_sha384
        # ecdsa_brainpoolP512r1tls13_sha512
        # Or hexadecimal value, for example:
        # 0x402
        # Example:
        # [
        #     "ecdsa_secp256r1_sha256",
        #     "rsa_pss_rsae_sha256",
        #     "rsa_pkcs1_sha256",
        #     "ecdsa_secp384r1_sha384",
        #     "rsa_pss_rsae_sha384",
        #     "rsa_pkcs1_sha384",
        #     "rsa_pss_rsae_sha512",
        #     "rsa_pkcs1_sha512",
        #     "0x402",
        #     "0x302",
        # ]
        self.supported_delegated_credentials_algorithms: list[str] = [
            "ECDSAWithP256AndSHA256",
            "ECDSAWithP384AndSHA384",
            "ECDSAWithP521AndSHA512",
            "ECDSAWithSHA1",
        ]  # Supported Delegated Voucher Algorithms
        # GREASE
        # 1.3
        # 1.2
        # 1.1
        # 1.0
        # Example:
        # [
        #     "GREASE",
        #     "1.3",
        #     "1.2",
        # ]
        self.supported_versions: list[str] = [
            "1.3",
            "1.2"
        ]  # Supported versions
        # PskModeDHE
        # PskModePlain
        # Example:
        # [
        #     "PskModeDHE",
        # ]
        self.psk_key_exchange_modes: list[str] = [
            "PskModeDHE"
        ]  # PSK Key Exchange Modes
        # PKCS1WithSHA256
        # PKCS1WithSHA384
        # PKCS1WithSHA512
        # PSSWithSHA256
        # PSSWithSHA384
        # PSSWithSHA512
        # ECDSAWithP256AndSHA256
        # ECDSAWithP384AndSHA384
        # ECDSAWithP521AndSHA512
        # Ed25519
        # PKCS1WithSHA1
        # ECDSAWithSHA1
        # rsa_pkcs1_sha1
        # Reserved for backward compatibility
        # ecdsa_sha1
        # rsa_pkcs1_sha256
        # ecdsa_secp256r1_sha256
        # rsa_pkcs1_sha256_legacy
        # rsa_pkcs1_sha384
        # ecdsa_secp384r1_sha384
        # rsa_pkcs1_sha384_legacy
        # rsa_pkcs1_sha512
        # ecdsa_secp521r1_sha512
        # rsa_pkcs1_sha512_legacy
        # eccsi_sha256
        # iso_ibs1
        # iso_ibs2
        # iso_chinese_ibs
        # sm2sig_sm3
        # gostr34102012_256a
        # gostr34102012_256b
        # gostr34102012_256c
        # gostr34102012_256d
        # gostr34102012_512a
        # gostr34102012_512b
        # gostr34102012_512c
        # rsa_pss_rsae_sha256
        # rsa_pss_rsae_sha384
        # rsa_pss_rsae_sha512
        # ed25519
        # ed448
        # rsa_pss_pss_sha256
        # rsa_pss_pss_sha384
        # rsa_pss_pss_sha512
        # ecdsa_brainpoolP256r1tls13_sha256
        # ecdsa_brainpoolP384r1tls13_sha384
        # ecdsa_brainpoolP512r1tls13_sha512
        # Or hexadecimal value, for example:
        # 0x402
        # Example:
        # [
        #     "ecdsa_secp256r1_sha256",
        #     "rsa_pss_rsae_sha256",
        #     "rsa_pkcs1_sha256",
        #     "ecdsa_secp384r1_sha384",
        #     "rsa_pss_rsae_sha384",
        #     "rsa_pkcs1_sha384",
        #     "rsa_pss_rsae_sha512",
        #     "rsa_pkcs1_sha512",
        #     "0x402",
        #     "0x302",
        # ]
        self.signature_algorithms_cert: list[str] = [
            "ECDSAWithP256AndSHA256",
            "ECDSAWithP384AndSHA384",
            "ECDSAWithP521AndSHA512",
            "PSSWithSHA256",
            "PSSWithSHA384",
            "PSSWithSHA512",
            "PKCS1WithSHA256",
            "PKCS1WithSHA384",
            "PKCS1WithSHA512",
            "ECDSAWithSHA1",
            "PKCS1WithSHA1",
        ]  # Signature Algorithms Cert
        # GREASE
        # P256
        # P384
        # P521
        # X25519
        # Example:
        # [
        #     "GREASE",
        #     "X25519"
        # ]
        self.key_share_curves: list[str] = [
            "GREASE",
            "X25519"
        ]  # Key Shared Curve
        self.not_used_grease: bool = False  # not Used Grease

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
        if self.supported_signature_algorithms != other.supported_signature_algorithms:
            return False
        if self.cert_compression_algo != other.cert_compression_algo:
            return False
        if self.record_size_limit != other.record_size_limit:
            return False
        if self.supported_delegated_credentials_algorithms != other.supported_delegated_credentials_algorithms:
            return False
        if self.supported_versions != other.supported_versions:
            return False
        if self.psk_key_exchange_modes != other.psk_key_exchange_modes:
            return False
        if self.signature_algorithms_cert != other.signature_algorithms_cert:
            return False
        if self.key_share_curves != other.key_share_curves:
            return False
        if self.not_used_grease != other.not_used_grease:
            return False
        return True

    # JSON转类
    def fromJSON(self, config: dict):
        for key, value in config.items():
            if key in self.__keys:
                setattr(self, key, value)
        return self

    # 类转JSON
    def toJSON(self):
        result = {}
        for key in self.__keys:
            result[key] = getattr(self, key)
        return result

    # 类转JSON
    def toMap(self):
        result = {}
        for key in self.__keys:
            go_keys = key.split("_")
            go_key = ""
            for k in go_keys:
                go_key += k.title()
            result[go_key] = getattr(self, key)
        return result


class HTTP2Settings:
    def __init__(self):
        super(HTTP2Settings, self).__init__()
        self.__keys = [
            "settings",
            "settings_order",
            "connection_flow",
            "header_priority",
            "priority_frames",
        ]
        # HEADER_TABLE_SIZE
        # ENABLE_PUSH
        # MAX_CONCURRENT_STREAMS
        # INITIAL_WINDOW_SIZE
        # MAX_FRAME_SIZE
        # MAX_HEADER_LIST_SIZE
        # Example:
        # {
        #     "HEADER_TABLE_SIZE": 65536,
        #     "MAX_CONCURRENT_STREAMS": 1000,
        #     "INITIAL_WINDOW_SIZE": 6291456,
        #     "MAX_HEADER_LIST_SIZE": 262144
        # }
        self.settings: dict[str, int] = {
            "HEADER_TABLE_SIZE": 65536,
            "MAX_CONCURRENT_STREAMS": 1000,
            "INITIAL_WINDOW_SIZE": 6291456,
            "MAX_HEADER_LIST_SIZE": 262144
        }  # HTTP2 Header Frame Settings
        # HEADER_TABLE_SIZE
        # ENABLE_PUSH
        # MAX_CONCURRENT_STREAMS
        # INITIAL_WINDOW_SIZE
        # MAX_FRAME_SIZE
        # MAX_HEADER_LIST_SIZE
        # Example:
        # [
        #     "HEADER_TABLE_SIZE",
        #     "MAX_CONCURRENT_STREAMS",
        #     "INITIAL_WINDOW_SIZE",
        #     "MAX_HEADER_LIST_SIZE",
        # ]
        self.settings_order: list[str] = [
            "HEADER_TABLE_SIZE",
            "MAX_CONCURRENT_STREAMS",
            "INITIAL_WINDOW_SIZE",
            "MAX_HEADER_LIST_SIZE"
        ]  # HTTP2 Header Frame Setting Order
        self.connection_flow: int = 15663105  # HTTP2 Window Update increment
        # Header Priority
        # Example:
        # {
        #   "streamDep": 1,
        #   "exclusive": true,
        #   "weight": 1
        # }
        self.header_priority: dict[str, any] = {
            "streamDep": 0,
            "exclusive": True,
            "weight": 256
        }  # HTTP2 Header Priority
        # Example:
        # [
        #   {
        #     "streamID": 3,
        #     "priorityParam": {
        #       "weight": 201,
        #       "streamDep": 0,
        #       "exclusive": false
        #     }
        #   },
        #   {
        #     "streamID": 5,
        #     "priorityParam": {
        #       "weight": 101,
        #       "streamDep": false,
        #       "exclusive": 0
        #     }
        #   }
        # ]
        self.priority_frames: list[dict[str, any]] = None  # HTTP2 Priority Frames

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
        if self.settings != other.settings:
            return False
        if self.settings_order != other.settings_order:
            return False
        if self.connection_flow != other.connection_flow:
            return False
        if self.header_priority != other.header_priority:
            return False
        if self.priority_frames != other.priority_frames:
            return False
        return True

    # JSON转类
    def fromJSON(self, config: dict):
        for key, value in config.items():
            if key in self.__keys:
                setattr(self, key, value)
        return self

    # 类转JSON
    def toJSON(self):
        result = {}
        for key in self.__keys:
            result[key] = getattr(self, key)
        return result

    # 类转JSON
    def toMap(self):
        result = {}
        for key in self.__keys:
            go_keys = key.split("_")
            go_key = ""
            for k in go_keys:
                go_key += k.title()
            result[go_key] = getattr(self, key)
        return result
