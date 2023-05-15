# requests-go
**requests-go**是一个支持tls指纹修改（如ja3）和http2的http请求库，本项目基于[requests](https://github.com/psf/requests)和[tls-client](https://github.com/FlorianREGAZ/Python-Tls-Client)，使用[requests](https://github.com/psf/requests)做为上层请求参数处理库，[tls-client](https://github.com/FlorianREGAZ/Python-Tls-Client)作为底层进行网络请求。



### 使用requests-go

**requests-go**使用方法跟requests一模一样，与之唯一不同的就是多了一个tls_config参数，此参数是用于修改tls指纹信息的。

`get:`

```python
import requests_go

url = "https://tls.peet.ws/api/all"
response = requests_go.get(url)	# 默认是随机tls指纹
print(response.text)

# or

import requests_go
from requests_go import tls_config
url = "https://tls.peet.ws/api/all"
tc = {...}   # tc为浏览器访问https://tls.peet.ws/api/all后的json结果
tls_conf = tls_config.to_tls_config(tc)
tls_conf.additional_decode = None	# 如果对方支持gzip、deflate、br则为gzip、deflate、br，否则会报错或少数据
response = requests_go.get(url, tls_config=tls_conf)	# 访问https://tls.peet.ws/api/all后的json结果需要使用to_tls_config进行转换为TLSConfig类
print(response.text)

# or

tc = {
	"ja3_string": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
}
response = requests_go.get(url, tls_config=tc)  # 默认tls_config为dict类则会自动进行转换为TLSConfig类
# response = requests_go.get(url, tls_config=tls_config.TLSConfig(config=tc))  # 默认tls_config为dict类则会自动进行转换为TLSConfig类
print(response.text)

```

`session:`

```python
import requests_go
from requests_go import tls_config

url = "https://tls.peet.ws/api/all"
tc = {...}	# tc为浏览器访问https://tls.peet.ws/api/all后的json结果
session = requests_go.session()
# No.1
session.tls_config = tls_config.to_tls_config(tc)  # or session.get(url), default random tls
print(session.tls_config)
response = session.get(url)

# No.2
# response = session.get(url, tls_config=tls_config.to_tls_config(tc))

print(response.text)
print(session.cookies)
```

`兼容requests:`

```python
import requests_go as requests	# 想要兼容requests改变requests_go的包名为requests即可
```



### tls_config指纹信息

`tls_config`指纹信息每项指纹的作用可以参考[tls-client](https://github.com/FlorianREGAZ/Python-Tls-Client)的文档，如若不知可直接使用`to_tls_config`函数将访问https://tls.peet.ws/api/all后的json结果转换为`TLSConfig`即可。

`注意：需要注意的一个地方是headers中的Accept-Encoding和tls_config中的additional_decode必须保持一致，如果Accept-Encoding=gzip的话，那么目标服务器也必须支持gzip压缩，否则会报错。`

```json
{
    "ja3_string": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-51-45-16-10-65281-5-11-35-23-43-27-13-18-17513-21,29-23-24,0",
    "h2_settings": {
        "HEADER_TABLE_SIZE": 65536,
        "ENABLE_PUSH": 0,
        "MAX_CONCURRENT_STREAMS": 1000,
        "INITIAL_WINDOW_SIZE": 6291456,
        "MAX_HEADER_LIST_SIZE": 262144
    },
    "h2_settings_order": [
        "HEADER_TABLE_SIZE",
        "ENABLE_PUSH",
        "MAX_CONCURRENT_STREAMS",
        "INITIAL_WINDOW_SIZE",
        "MAX_HEADER_LIST_SIZE"
    ],
    "supported_signature_algorithms": [
        "ECDSAWithP256AndSHA256",
        "PSSWithSHA256",
        "PKCS1WithSHA256",
        "ECDSAWithP384AndSHA384",
        "PSSWithSHA384",
        "PKCS1WithSHA384",
        "PSSWithSHA512",
        "PKCS1WithSHA512"
    ],
    "supported_delegated_credentials_algorithms": null,
    "supported_versions": [
        "GREASE",
        "1.3",
        "1.2"
    ],
    "key_share_curves": [
        "GREASE",
        "X25519"
    ],
    "cert_compression_algo": "brotli",
    "additional_decode": null,
    "pseudo_header_order": [
        ":method",
        ":authority",
        ":scheme",
        ":path"
    ],
    "connection_flow": 15663105,
    "priority_frames": null,
    "header_order": [
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
        "upgrade-insecure-requests",
        "user-agent",
        "accept",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-user",
        "sec-fetch-dest",
        "accept-encoding",
        "accept-language"
    ],
    "header_priority": {
        "weight": 255,
        "streamDep": 0,
        "exclusive": true
    },
    "random_tls_extension_order": false,
    "force_http1": false,
    "catch_panics": false
}
```



### 打包python项目
```bash
python setup.py install
python setup.py build
python setup.py sdist
```