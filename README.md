# requests-go
**requests-go**是一个支持tls指纹修改（如ja3）和http2的http请求库，本项目基于[requests](https://github.com/psf/requests)和[requests(go版)](https://github.com/wangluozhe/requests)，使用[requests](https://github.com/psf/requests)做为上层请求参数处理库，[requests(go版)](https://github.com/wangluozhe/requests)作为底层进行网络请求。



### 使用requests-go

**requests-go**使用方法跟requests一模一样，与之唯一不同的就是多了一个tls_config参数，此参数是用于修改tls指纹信息的。

`custom_tls:`

```python
import requests_go

url = "https://tls.peet.ws/api/all"
headers = {
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"
}
tls = requests_go.tls_config.TLSConfig()
tls.ja3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,16-18-5-27-0-13-11-43-45-35-51-23-10-65281-17513-21,29-23-24,0"
tls.pseudo_header_order = [
    ":method",
    ":authority",
    ":scheme",
    ":path",
]
tls.tls_extensions.cert_compression_algo = ["brotli"]
tls.tls_extensions.supported_signature_algorithms = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512"
]
tls.tls_extensions.supported_versions = [
    "GREASE",
    "1.3",
    "1.2"
]
tls.tls_extensions.psk_key_exchange_modes = [
    "PskModeDHE"
]
tls.tls_extensions.key_share_curves = [
    "GREASE",
    "X25519"
]
tls.http2_settings.settings = {
    "HEADER_TABLE_SIZE": 65536,
    "ENABLE_PUSH": 0,
    "MAX_CONCURRENT_STREAMS": 1000,
    "INITIAL_WINDOW_SIZE": 6291456,
    "MAX_HEADER_LIST_SIZE": 262144
}
tls.http2_settings.settings_order = [
    "HEADER_TABLE_SIZE",
    "ENABLE_PUSH",
    "MAX_CONCURRENT_STREAMS",
    "INITIAL_WINDOW_SIZE",
    "MAX_HEADER_LIST_SIZE"
]
tls.http2_settings.connection_flow = 15663105
response = requests_go.get(url=url, headers=headers, tls_config=tls)
print(response.url)
print(response.text)
print(response.headers)
print(response.cookies)

```

## 常见错误
1. `单独设置ja3报404错误`的解决方法：默认使用http2，必须搭配pseudo_header_order伪标题顺序去使用，否则会访问失败404，或force_http1强制使用http1（0.3版本会更新）。
2. `挂上VPN后报EOF错误`的解决方法：默认requests-go跟requests一样会去读取系统环境变量中的代理，默认代理会使用https协议，需手动修改proxies的代理为http协议即可。

`兼容requests:`

```python
import requests_go as requests	# 想要兼容requests改变requests_go的包名为requests即可
```



### tls_config指纹信息

`tls_config`指纹信息每项指纹的作用可以参考[config.py](https://github.com/wangluozhe/requests-go/blob/main/requests_go/tls_config/config.py)的源码。

如若不知，可直接使用`to_tls_config`函数将访问[https://tls.peet.ws/api/all](https://tls.peet.ws/api/all)后的json结果转换为`TLSConfig`即可。

```python
import requests_go as requests
from requests_go import tls_config

url = "https://tls.peet.ws/api/all"
tc = {
    ...
}   # tc is browser access https://tls.peet.ws/api/all json result
tls_conf = tls_config.to_tls_config(tc)
response = requests.get(url, tls_config=tls_conf)
print(response.text)

# or

tc = {
	"Ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
}
response = requests.get(url, tls_config=tc)  # default tls_config is dict class the convert TLSConfig class
# response = requests.get(url, tls_config=tls_config.TLSConfig(config=tc))  # default tls_config is dict class the convert TLSConfig class
print(response.text)

```

`注意：不能自行设置content-length，否则会出现未知错误！`


### ciphers使用
`ciphers`可以帮助你还原`ja3`中的`CipherSuites`部分和`charles`中的`CipherSuites`部分，可以快速的查找到自己所需的`CipherSuite`。

```python
from requests_go.tls_config import ciphers

print(ciphers.cipher_suite_to_decimal("TLS_AES_128_GCM_SHA256"))    # cipher_suite转十进制
# 输出结果: 4865
print(ciphers.decimal_to_cipher_suite(4865))    # 十进制转cipher_suite
# 输出结果: TLS_AES_128_GCM_SHA256

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
# 输出结果: [4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53]

print("-".join([str(decimal) for decimal in decimals]))
# 输出结果: 4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53
print(ciphers.decimals_to_cipher_suites("-".join([str(decimal) for decimal in decimals])))   # 十进制字符串转cipher_suite列表
# 输出结果: ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_AES_128_GCM_SHA256', 'TLS_RSA_WITH_AES_256_GCM_SHA384', 'TLS_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA']
print("\n".join([str(decimal) for decimal in decimals]))
# 输出结果: 
"""
4865
4866
4867
49195
49199
49196
49200
52393
52392
49171
49172
156
157
47
53
"""
print(ciphers.decimals_to_cipher_suites("\n".join([str(decimal) for decimal in decimals]), split_str="\n"))   # split_str分割字符串，默认为-
# 输出结果: ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_AES_128_GCM_SHA256', 'TLS_RSA_WITH_AES_256_GCM_SHA384', 'TLS_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA']

cipher_suites = ciphers.decimals_to_cipher_suites(decimals)  # 十进制列表转cipher_suite列表
print(cipher_suites)
# 输出结果: ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_AES_128_GCM_SHA256', 'TLS_RSA_WITH_AES_256_GCM_SHA384', 'TLS_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA']

```


### JA3指纹随机化
现在高版本浏览器都会将ja3的指纹随机化，但是其随机化原理仅仅是对extensions部分进行随机化。

```python
import requests_go

config = {
    ...
}
tls_config = requests_go.tls_config.to_tls_config(config)
tls_config.ja3 = requests_go.tls_config.JA3Random(tls_config.ja3)
for i in range(10):
    print(tls_config.ja3)

# 输出结果:
# 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,18-13-21-17513-43-11-0-10-45-27-51-5-65281-35-23-16,29-23-24,0
# 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,13-23-18-51-10-11-17513-65281-45-43-16-35-0-5-27-21,29-23-24,0
# 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,23-16-17513-18-0-43-10-35-21-5-51-65281-13-45-11-27,29-23-24,0
# 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,18-51-43-35-27-23-0-21-17513-13-45-5-11-10-65281-16,29-23-24,0
# 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-11-21-10-65281-35-16-18-51-23-13-17513-45-27-43-5,29-23-24,0
# 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,43-65281-17513-13-35-16-0-51-27-18-21-5-11-23-45-10,29-23-24,0
# 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,16-27-11-21-10-5-18-0-35-65281-45-51-13-43-23-17513,29-23-24,0
# 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,43-23-21-17513-35-27-0-18-11-5-65281-45-10-16-13-51,29-23-24,0
# 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,5-45-65281-43-17513-11-0-10-27-21-13-35-16-51-18-23,29-23-24,0
# 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,45-23-27-43-18-21-13-5-65281-11-10-16-35-17513-51-0,29-23-24,0
```


### 打包python项目
```bash
python setup.py install
python setup.py build
python setup.py sdist
```