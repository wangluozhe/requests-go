import requests_go as requests
from requests_go import tls_config

url = "https://tls.peet.ws/api/all"
tc = {
	"ip": "1.203.179.156:54971",
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
		"ja3": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21-41,29-23-24-25-256-257,0",
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
					"accept-encoding: gzip, deflate, br",
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
}
session = requests.session()
# No.1
session.tls_config = tls_config.to_tls_config(tc)  # or session.get(url), default random tls
print(session.tls_config)
response = session.get(url)

# No.2
response = session.get(url)

print(response.text)
print(session.cookies)
