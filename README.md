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

`tls_config`指纹信息每项指纹的作用可以参考[config.py](https://github.com/wangluozhe/requests-go/blob/main/requests_go/tls_config/config.py)的源码，如若不知，可直接使用`to_tls_config`函数将访问https://tls.peet.ws/api/all后的json结果转换为`TLSConfig`即可。

```python
import requests_go as requests
from requests_go import tls_config

url = "https://tls.peet.ws/api/all"
tc = {
	"ip": "xxx.xxx.xxx.xxx:xxx",
	"http_version": "h2",
	"method": "GET",
	"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
	"tls": {
		"ciphers": [
			"TLS_AES_128_GCM_SHA256",
			"TLS_CHACHA20_POLY1305_SHA256",
			"TLS_AES_256_GCM_SHA384",
			"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
			"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
			"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
			"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
			"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
			"TLS_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_RSA_WITH_AES_128_CBC_SHA",
			"TLS_RSA_WITH_AES_256_CBC_SHA"
		],
		"extensions": [
			{
				"name": "server_name (0)",
				"server_name": "tls.peet.ws"
			},
			{
				"name": "extended_master_secret (23)",
				"master_secret_data": "",
				"extended_master_secret_data": ""
			},
			{
				"name": "extensionRenegotiationInfo (boringssl) (65281)",
				"data": "00"
			},
			{
				"name": "supported_groups (10)",
				"supported_groups": [
					"X25519 (29)",
					"P-256 (23)",
					"P-384 (24)",
					"P-521 (25)",
					"ffdhe2048 (256)",
					"ffdhe3072 (257)"
				]
			},
			{
				"name": "ec_point_formats (11)",
				"elliptic_curves_point_formats": [
					"0x00"
				]
			},
			{
				"name": "session_ticket (35)",
				"data": ""
			},
			{
				"name": "application_layer_protocol_negotiation (16)",
				"protocols": [
					"h2",
					"http/1.1"
				]
			},
			{
				"name": "status_request (5)",
				"status_request": {
					"certificate_status_type": "OSCP (1)",
					"responder_id_list_length": 0,
					"request_extensions_length": 0
				}
			},
			{
				"name": "delegated_credentials (34)",
				"signature_hash_algorithms": [
					"ecdsa_secp256r1_sha256",
					"ecdsa_secp384r1_sha384",
					"ecdsa_secp521r1_sha512",
					"ecdsa_sha1"
				]
			},
			{
				"name": "key_share (51)",
				"shared_keys": [
					{
						"X25519 (29)": "318c61501ecc8cbb47e9f29e508e71eae0819128737c2d6a59d5cd175fc12a64"
					},
					{
						"P-256 (23)": "04c39fb8c4c41aa3abf877bf6561bafbbd133aedf872a6d7201a3f51075862298571c8fe27a5d60d579afe63a968341b95e452cd03be7dd2d054b2cf42d92006c9"
					}
				]
			},
			{
				"name": "supported_versions (43)",
				"versions": [
					"TLS 1.3",
					"TLS 1.2"
				]
			},
			{
				"name": "signature_algorithms (13)",
				"signature_algorithms": [
					"ecdsa_secp256r1_sha256",
					"ecdsa_secp384r1_sha384",
					"ecdsa_secp521r1_sha512",
					"rsa_pss_rsae_sha256",
					"rsa_pss_rsae_sha384",
					"rsa_pss_rsae_sha512",
					"rsa_pkcs1_sha256",
					"rsa_pkcs1_sha384",
					"rsa_pkcs1_sha512",
					"ecdsa_sha1",
					"rsa_pkcs1_sha1"
				]
			},
			{
				"name": "psk_key_exchange_modes (45)",
				"PSK_Key_Exchange_Mode": "PSK with (EC)DHE key establishment (psk_dhe_ke) (1)"
			},
			{
				"name": "record_size_limit (28)",
				"data": "4001"
			},
			{
				"name": "padding (21)",
				"padding_data_length": 278
			}
		],
		"tls_version_record": "771",
		"tls_version_negotiated": "772",
		"ja3": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0",
		"ja3_hash": "579ccef312d18482fc42e2b822ca2430",
		"peetprint (WIP)": "772-771|2-1.1|29-23-24-25-256-257|1027-1283-1539-2052-2053-2054-1025-1281-1537-515-513|1||4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53|0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21",
		"peetprint_hash (WIP)": "d75170eced1bd1f0c8c20421793cddf3",
		"client_random": "aa97bfe6002bbcd474e46c22d533ba5e2c4410bef096dc417631c81fcc039bed",
		"session_id": "049b5a40406b27fb6f53bfe1b6e9a3012d71813f2fc5a1e2588951703c3fdac7"
	},
	"http2": {
		"akamai_fingerprint": "1:65536,4:131072,5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s",
		"akamai_fingerprint_hash": "fd4f649c50a64e33cc9e2407055bafbe",
		"sent_frames": [
			{
				"frame_type": "SETTINGS",
				"length": 18,
				"settings": [
					"HEADER_TABLE_SIZE = 65536",
					"INITIAL_WINDOW_SIZE = 131072",
					"MAX_FRAME_SIZE = 16384"
				]
			},
			{
				"frame_type": "WINDOW_UPDATE",
				"length": 4,
				"increment": 12517377
			},
			{
				"frame_type": "PRIORITY",
				"stream_id": 3,
				"length": 5,
				"priority": {
					"weight": 201,
					"depends_on": 0,
					"exclusive": 0
				}
			},
			{
				"frame_type": "PRIORITY",
				"stream_id": 5,
				"length": 5,
				"priority": {
					"weight": 101,
					"depends_on": 0,
					"exclusive": 0
				}
			},
			{
				"frame_type": "PRIORITY",
				"stream_id": 7,
				"length": 5,
				"priority": {
					"weight": 1,
					"depends_on": 0,
					"exclusive": 0
				}
			},
			{
				"frame_type": "PRIORITY",
				"stream_id": 9,
				"length": 5,
				"priority": {
					"weight": 1,
					"depends_on": 7,
					"exclusive": 0
				}
			},
			{
				"frame_type": "PRIORITY",
				"stream_id": 11,
				"length": 5,
				"priority": {
					"weight": 1,
					"depends_on": 3,
					"exclusive": 0
				}
			},
			{
				"frame_type": "PRIORITY",
				"stream_id": 13,
				"length": 5,
				"priority": {
					"weight": 241,
					"depends_on": 0,
					"exclusive": 0
				}
			},
			{
				"frame_type": "HEADERS",
				"stream_id": 15,
				"length": 320,
				"headers": [
					":method: GET",
					":path: /api/all",
					":authority: tls.peet.ws",
					":scheme: https",
					"user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
					"accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
					"accept-language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
					"accept-encoding: deflate, br",
					"upgrade-insecure-requests: 1",
					"sec-fetch-dest: document",
					"sec-fetch-mode: navigate",
					"sec-fetch-site: none",
					"sec-fetch-user: ?1",
					"te: trailers"
				],
				"flags": [
					"EndStream (0x1)",
					"EndHeaders (0x4)",
					"Priority (0x20)"
				],
				"priority": {
					"weight": 42,
					"depends_on": 13,
					"exclusive": 0
				}
			}
		]
	}
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



### 打包python项目
```bash
python setup.py install
python setup.py build
python setup.py sdist
```