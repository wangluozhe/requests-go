try:
    from tls_config import *
except ImportError:
    from .config import (TLSConfig, JA3, random_ja3, TLS_CHROME_LATEST, TLS_CHROME_131_LATEST, TLS_CHROME_131, TLS_CHROME_130_SAFE, TLS_CHROME_130,
                         TLS_CHROME_111_129_SAFE, TLS_CHROME_111_129, TLS_CHROME_122, TLS_CHROME_110_LATEST, TLS_CHROME_110, TLS_CHROME_103,
                         TLS_CHROME_101, TLS_EDGE_131_LATEST, TLS_EDGE_131, TLS_FIREFOX_LATEST, TLS_FIREFOX_135_LATEST, TLS_FIREFOX_135,
                         TLS_FIREFOX_134,
                         TLS_FIREFOX_126, TLS_FIREFOX_105, TLS_SAFARI_MAC_OS_18_3, TLS_SAFARI_IOS_18_3_1)
    from .convert_config import to_tls_config
    from .extensions import TLSExtensions, HTTP2Settings
    from .ciphers import cipher_suite_to_decimal, cipher_suites_to_decimals, decimal_to_cipher_suite, decimals_to_cipher_suites
    from .algorithms import charles_to_tls_signature_algorithms
