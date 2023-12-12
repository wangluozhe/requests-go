from requests_go.tls_config import ciphers

print(ciphers.cipher_suite_to_decimal("TLS_AES_128_GCM_SHA256"))    # cipher_suite转十进制
print(ciphers.decimal_to_cipher_suite(4865))    # 十进制转cipher_suite

cipher_suites = """
TLS_GREASE 0x4a 0x4a
TLS_AES_128_GCM_SHA256
TLS_AES_256_GCM_SHA384
TLS_CHACHA20_POLY1305_SHA256
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
TLS_RSA_WITH_AES_128_GCM_SHA256
TLS_RSA_WITH_AES_256_GCM_SHA384
TLS_RSA_WITH_AES_128_CBC_SHA
TLS_RSA_WITH_AES_256_CBC_SHA
"""
decimals = ciphers.cipher_suites_to_decimals(cipher_suites)  # cipher_suite列表转十进制
print(decimals)

print("-".join([str(decimal) for decimal in decimals]))
print(ciphers.decimals_to_cipher_suites("-".join([str(decimal) for decimal in decimals])))   # 十进制字符串转cipher_suite列表
print("\n".join([str(decimal) for decimal in decimals]))
print(ciphers.decimals_to_cipher_suites("\n".join([str(decimal) for decimal in decimals]), split_str="\n"))   # split_str分割字符串，默认为-

cipher_suites = ciphers.decimals_to_cipher_suites(decimals)  # 十进制列表转cipher_suite列表
print(cipher_suites)
