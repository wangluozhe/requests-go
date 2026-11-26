try:
    from tls_config import *
    from tls_config import TLSConfig as _PrivateConfig, to_tls_config as _private_to_tls_config
except ImportError:
    from .config import (TLS_CHROME_LATEST, TLS_CHROME_131_LATEST, TLS_CHROME_131, TLS_CHROME_130_SAFE, TLS_CHROME_130,
                         TLS_CHROME_111_129_SAFE, TLS_CHROME_111_129, TLS_CHROME_122, TLS_CHROME_110_LATEST, TLS_CHROME_110, TLS_CHROME_103,
                         TLS_CHROME_101, TLS_EDGE_131_LATEST, TLS_EDGE_131, TLS_FIREFOX_LATEST, TLS_FIREFOX_135_LATEST, TLS_FIREFOX_135,
                         TLS_FIREFOX_134,
                         TLS_FIREFOX_126, TLS_FIREFOX_105, TLS_SAFARI_MAC_OS_18_3, TLS_SAFARI_IOS_18_3_1)
    from .convert_config import to_tls_config
    from .ciphers import cipher_suite_to_decimal, cipher_suites_to_decimals, decimal_to_cipher_suite, decimals_to_cipher_suites
    from .algorithms import charles_to_tls_signature_algorithms
else:
    # Keep private preset aliases pointing to the same, v1.6-capable config.
    from .config import TLSConfig

    def _convert_presets():
        converted = {}
        for name, preset in list(globals().items()):
            if isinstance(preset, _PrivateConfig):
                if id(preset) not in converted:
                    converted[id(preset)] = TLSConfig.from_config(preset)
                globals()[name] = converted[id(preset)]

    _convert_presets()

    def to_tls_config(config):
        return TLSConfig.from_config(_private_to_tls_config(config))

from .config import TLSConfig, JA3, random_ja3
from .extensions import TLSExtensions, HTTP2Settings
