"""ClientHello presets provided by the v1.6.0 native library's uTLS dependency."""

from .config import TLSConfig as _TLSConfig


def _preset(name, client, version):
    config = _TLSConfig(name)
    config.client_hello_id = {"Client": client, "Version": version}
    return config


TLS_FIREFOX_55 = _preset("TLS_FIREFOX_55", "Firefox", "55")
TLS_FIREFOX_56 = _preset("TLS_FIREFOX_56", "Firefox", "56")
TLS_FIREFOX_63 = _preset("TLS_FIREFOX_63", "Firefox", "63")
TLS_FIREFOX_65 = _preset("TLS_FIREFOX_65", "Firefox", "65")
TLS_FIREFOX_99 = _preset("TLS_FIREFOX_99", "Firefox", "99")
TLS_FIREFOX_102 = _preset("TLS_FIREFOX_102", "Firefox", "102")
TLS_FIREFOX_105 = _preset("TLS_FIREFOX_105", "Firefox", "105")
TLS_FIREFOX_120 = _preset("TLS_FIREFOX_120", "Firefox", "120")
TLS_FIREFOX_148 = _preset("TLS_FIREFOX_148", "Firefox", "148")
TLS_FIREFOX_LATEST = TLS_FIREFOX_148

TLS_CHROME_58 = _preset("TLS_CHROME_58", "Chrome", "58")
TLS_CHROME_62 = _preset("TLS_CHROME_62", "Chrome", "62")
TLS_CHROME_70 = _preset("TLS_CHROME_70", "Chrome", "70")
TLS_CHROME_72 = _preset("TLS_CHROME_72", "Chrome", "72")
TLS_CHROME_83 = _preset("TLS_CHROME_83", "Chrome", "83")
TLS_CHROME_87 = _preset("TLS_CHROME_87", "Chrome", "87")
TLS_CHROME_96 = _preset("TLS_CHROME_96", "Chrome", "96")
TLS_CHROME_100 = _preset("TLS_CHROME_100", "Chrome", "100")
TLS_CHROME_102 = _preset("TLS_CHROME_102", "Chrome", "102")
TLS_CHROME_106 = _preset("TLS_CHROME_106", "Chrome", "106")
TLS_CHROME_100_PSK = _preset("TLS_CHROME_100_PSK", "Chrome", "100_PSK")
TLS_CHROME_112_PSK = _preset("TLS_CHROME_112_PSK", "Chrome", "112_PSK")
TLS_CHROME_114_PSK = _preset("TLS_CHROME_114_PSK", "Chrome", "114_PSK")
TLS_CHROME_115_PQ = _preset("TLS_CHROME_115_PQ", "Chrome", "115_PQ")
TLS_CHROME_115_PQ_PSK = _preset("TLS_CHROME_115_PQ_PSK", "Chrome", "115_PQ_PSK")
TLS_CHROME_120 = _preset("TLS_CHROME_120", "Chrome", "120")
TLS_CHROME_120_PQ = _preset("TLS_CHROME_120_PQ", "Chrome", "120_PQ")
TLS_CHROME_131 = _preset("TLS_CHROME_131", "Chrome", "131")
TLS_CHROME_133 = _preset("TLS_CHROME_133", "Chrome", "133")
TLS_CHROME_155 = _preset("TLS_CHROME_155", "Chrome", "155")
TLS_CHROME_LATEST = TLS_CHROME_155

TLS_IOS_11_1 = _preset("TLS_IOS_11_1", "iOS", "111")
TLS_IOS_12_1 = _preset("TLS_IOS_12_1", "iOS", "12.1")
TLS_IOS_13 = _preset("TLS_IOS_13", "iOS", "13")
TLS_IOS_14 = _preset("TLS_IOS_14", "iOS", "14")
TLS_IOS_LATEST = TLS_IOS_14

TLS_ANDROID_11_OKHTTP = _preset("TLS_ANDROID_11_OKHTTP", "Android", "11")

TLS_EDGE_85 = _preset("TLS_EDGE_85", "Edge", "85")
TLS_EDGE_106 = _preset("TLS_EDGE_106", "Edge", "106")
TLS_EDGE_LATEST = TLS_EDGE_85

TLS_SAFARI_16_0 = _preset("TLS_SAFARI_16_0", "Safari", "16.0")
TLS_SAFARI_26_3 = _preset("TLS_SAFARI_26_3", "Safari", "26.3")
TLS_SAFARI_LATEST = TLS_SAFARI_26_3

TLS_360BROWSER_7_5 = _preset("TLS_360BROWSER_7_5", "360Browser", "7.5")
TLS_360BROWSER_11_0 = _preset("TLS_360BROWSER_11_0", "360Browser", "11.0")
TLS_360BROWSER_LATEST = TLS_360BROWSER_7_5

TLS_QQBROWSER_11_1 = _preset("TLS_QQBROWSER_11_1", "QQBrowser", "11.1")
TLS_QQBROWSER_LATEST = TLS_QQBROWSER_11_1

TLS_RANDOMIZED = _preset("TLS_RANDOMIZED", "Randomized", "0")
TLS_RANDOMIZED_ALPN = _preset("TLS_RANDOMIZED_ALPN", "Randomized-ALPN", "0")
TLS_RANDOMIZED_NO_ALPN = _preset("TLS_RANDOMIZED_NO_ALPN", "Randomized-NoALPN", "0")
