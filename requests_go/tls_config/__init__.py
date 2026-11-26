from . import config as _config, extensions as _extensions, utls as _utls

# Import native presets first so the existing project and optional presets take precedence.
from .utls import (
    TLS_FIREFOX_55, TLS_FIREFOX_56, TLS_FIREFOX_63, TLS_FIREFOX_65,
    TLS_FIREFOX_99, TLS_FIREFOX_102, TLS_FIREFOX_105, TLS_FIREFOX_120,
    TLS_FIREFOX_148, TLS_FIREFOX_LATEST,
    TLS_CHROME_58, TLS_CHROME_62, TLS_CHROME_70, TLS_CHROME_72, TLS_CHROME_83,
    TLS_CHROME_87, TLS_CHROME_96, TLS_CHROME_100, TLS_CHROME_102, TLS_CHROME_106,
    TLS_CHROME_100_PSK, TLS_CHROME_112_PSK, TLS_CHROME_114_PSK,
    TLS_CHROME_115_PQ, TLS_CHROME_115_PQ_PSK, TLS_CHROME_120, TLS_CHROME_120_PQ,
    TLS_CHROME_131, TLS_CHROME_133, TLS_CHROME_155, TLS_CHROME_LATEST,
    TLS_IOS_11_1, TLS_IOS_12_1, TLS_IOS_13, TLS_IOS_14, TLS_IOS_LATEST,
    TLS_ANDROID_11_OKHTTP,
    TLS_EDGE_85, TLS_EDGE_106, TLS_EDGE_LATEST,
    TLS_SAFARI_16_0, TLS_SAFARI_26_3, TLS_SAFARI_LATEST,
    TLS_360BROWSER_7_5, TLS_360BROWSER_11_0, TLS_360BROWSER_LATEST,
    TLS_QQBROWSER_11_1, TLS_QQBROWSER_LATEST,
    TLS_RANDOMIZED, TLS_RANDOMIZED_ALPN, TLS_RANDOMIZED_NO_ALPN,
)

try:
    from tls_config import *
    from tls_config import TLSConfig as _PrivateConfig, to_tls_config as _private_to_tls_config
except ImportError:
    from .config import (TLS_CHROME_LATEST, TLS_CHROME_131_LATEST, TLS_CHROME_131, TLS_CHROME_130_SAFE, TLS_CHROME_130,
                         TLS_CHROME_111_129_SAFE, TLS_CHROME_111_129, TLS_CHROME_122, TLS_CHROME_110_LATEST, TLS_CHROME_110, TLS_CHROME_103,
                         TLS_CHROME_101, TLS_EDGE_LATEST, TLS_EDGE_131_LATEST, TLS_EDGE_131, TLS_FIREFOX_LATEST, TLS_FIREFOX_135_LATEST, TLS_FIREFOX_135,
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
# The optional package's wildcard import may also export its own modules.
config, extensions, utls = _config, _extensions, _utls
