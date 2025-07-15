import requests_go

config = {
  "ip": "104.223.97.2:27030",
  "http_version": "h2",
  "method": "GET",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
  "tls": {
    "ciphers": [
      "TLS_GREASE (0x2A2A)",
      "TLS_AES_128_GCM_SHA256",
      "TLS_AES_256_GCM_SHA384",
      "TLS_CHACHA20_POLY1305_SHA256",
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
      "TLS_RSA_WITH_AES_128_GCM_SHA256",
      "TLS_RSA_WITH_AES_256_GCM_SHA384",
      "TLS_RSA_WITH_AES_128_CBC_SHA",
      "TLS_RSA_WITH_AES_256_CBC_SHA"
    ],
    "extensions": [
      {
        "name": "TLS_GREASE (0xfafa)"
      },
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
          "TLS_GREASE (0xfafa)",
          "X25519 (29)",
          "P-256 (23)",
          "P-384 (24)"
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
        "name": "signature_algorithms (13)",
        "signature_algorithms": [
          "ecdsa_secp256r1_sha256",
          "rsa_pss_rsae_sha256",
          "rsa_pkcs1_sha256",
          "ecdsa_secp384r1_sha384",
          "rsa_pss_rsae_sha384",
          "rsa_pkcs1_sha384",
          "rsa_pss_rsae_sha512",
          "rsa_pkcs1_sha512"
        ]
      },
      {
        "name": "signed_certificate_timestamp (18)"
      },
      {
        "name": "key_share (51)",
        "shared_keys": [
          {
            "TLS_GREASE (0xfafa)": "00"
          },
          {
            "X25519 (29)": "593f100c77a9e73de3a4c32bf1d2f2f812f09c89bddd31de295003405cdb8f07"
          }
        ]
      },
      {
        "name": "psk_key_exchange_modes (45)",
        "PSK_Key_Exchange_Mode": "PSK with (EC)DHE key establishment (psk_dhe_ke) (1)"
      },
      {
        "name": "supported_versions (43)",
        "versions": [
          "TLS_GREASE (0xfafa)",
          "TLS 1.3",
          "TLS 1.2"
        ]
      },
      {
        "name": "compress_certificate (27)",
        "algorithms": [
          "brotli (2)"
        ]
      },
      {
        "name": "application_settings (17513)",
        "protocols": [
          "h2"
        ]
      },
      {
        "name": "TLS_GREASE (0xdada)"
      },
      {
        "name": "padding (21)",
        "padding_data_length": 408
      }
    ],
    "tls_version_record": "771",
    "tls_version_negotiated": "772",
    "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
    "ja3_hash": "cd08e31494f9531f560d64c695473da9",
    "ja4": "t13d1516h2_8daaf6152771_5fb3489db586",
    "peetprint": "GREASE-772-771|2-1.1|GREASE-29-23-24|1027-2052-1025-1283-2053-1281-2054-1537|1|2|GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53|0-10-11-13-16-17513-18-21-23-27-35-43-45-5-51-65281-GREASE-GREASE",
    "peetprint_hash": "22a4f858cc83b9144c829ca411948a88",
    "client_random": "dd043f156c0de3702ab310f32dbe61103cff231b6f27e3a00aab2871c1fa14dd",
    "session_id": "5893fb2a4f6c17480dcc5c079bacfe860c0f04327c4c2cd482bba0662078f8fa"
  },
  "http2": {
    "akamai_fingerprint": "1:65536,3:1000,4:6291456,6:262144|15663105|0|m,a,s,p",
    "akamai_fingerprint_hash": "7ad845f20fc17cc8088a0d9312b17da1",
    "sent_frames": [
      {
        "frame_type": "SETTINGS",
        "length": 24,
        "settings": [
          "HEADER_TABLE_SIZE = 65536",
          "MAX_CONCURRENT_STREAMS = 1000",
          "INITIAL_WINDOW_SIZE = 6291456",
          "MAX_HEADER_LIST_SIZE = 262144"
        ]
      },
      {
        "frame_type": "WINDOW_UPDATE",
        "length": 4,
        "increment": 15663105
      },
      {
        "frame_type": "HEADERS",
        "stream_id": 1,
        "length": 451,
        "headers": [
          ":method: GET",
          ":authority: tls.peet.ws",
          ":scheme: https",
          ":path: /api/all",
          "cache-control: max-age=0",
          "sec-ch-ua: \\\".Not/A)Brand\\\";v=\\\"99\\\", \\\"Google Chrome\\\";v=\\\"103\\\", \\\"Chromium\\\";v=\\\"103\\",
          "sec-ch-ua-mobile: ?0",
          "sec-ch-ua-platform: \\\"Windows\\",
          "upgrade-insecure-requests: 1",
          "user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
          "accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
          "sec-fetch-site: none",
          "sec-fetch-mode: navigate",
          "sec-fetch-user: ?1",
          "sec-fetch-dest: document",
          "accept-encoding: gzip, deflate, br",
          "accept-language: zh-CN,zh;q=0.9"
        ],
        "flags": [
          "EndStream (0x1)",
          "EndHeaders (0x4)",
          "Priority (0x20)"
        ],
        "priority": {
          "weight": 256,
          "depends_on": 0,
          "exclusive": 1
        }
      }
    ]
  },
  "tcpip": {
    "cap_length": 118,
    "dst_port": 443,
    "src_port": 27030,
    "ip": {
      "id": 31647,
      "tos": 40,
      "ttl": 54,
      "ip_version": 4,
      "dst_ip": "205.185.123.167",
      "src_ip": "104.223.97.2"
    },
    "tcp": {
      "ack": 1717732738,
      "checksum": 37045,
      "seq": 3971567081,
      "window": 40
    }
  }
}
tls_config = requests_go.tls_config.to_tls_config(config)
tls_config.random_ja3 = True
for i in range(10):
    print(tls_config.ja3)
