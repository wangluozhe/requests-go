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
tls.http2_extensions.settings = {
    "HEADER_TABLE_SIZE": 65536,
    "ENABLE_PUSH": 0,
    "MAX_CONCURRENT_STREAMS": 1000,
    "INITIAL_WINDOW_SIZE": 6291456,
    "MAX_HEADER_LIST_SIZE": 262144
}
tls.http2_extensions.settings_order = [
    "HEADER_TABLE_SIZE",
    "ENABLE_PUSH",
    "MAX_CONCURRENT_STREAMS",
    "INITIAL_WINDOW_SIZE",
    "MAX_HEADER_LIST_SIZE"
]
tls.http2_extensions.connection_flow = 15663105
response = requests_go.get(url=url, headers=headers, tls_config=tls)


```

`兼容requests:`

```python
import requests_go as requests	# 想要兼容requests改变requests_go的包名为requests即可
```



### tls_config指纹信息

`tls_config`指纹信息每项指纹的作用可以参考[config.py](https://github.com/wangluozhe/requests-go/blob/main/requests_go/tls_config/config.py)的源码，如若不知可直接使用`to_tls_config`函数将访问https://tls.peet.ws/api/all后的json结果转换为`TLSConfig`即可（暂不支持）。

`注意：不能自行设置content-length，否则会出现未知错误！`



### 打包python项目
```bash
python setup.py install
python setup.py build
python setup.py sdist
```