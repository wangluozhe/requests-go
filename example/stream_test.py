# -*- coding: utf-8 -*-
"""
Test HTTP/2 stream operations with TLS fingerprinting.

Tests three modes:
  1. Normal request (no stream)
  2. stream=True with iter_content
  3. stream=True with iter_lines
"""
import sys
import os

# Force use local version
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Disable system proxy
os.environ.pop("HTTP_PROXY", None)
os.environ.pop("HTTPS_PROXY", None)
os.environ.pop("ALL_PROXY", None)
os.environ.pop("http_proxy", None)
os.environ.pop("https_proxy", None)
os.environ.pop("all_proxy", None)
os.environ["NO_PROXY"] = "*"

import requests_go

# Verify we're using the local module
print(f"requests_go path: {requests_go.__file__}")

url = "https://tls.peet.ws/api/all"
headers = {
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"
}

# TLS fingerprint config (same as tls_config_test.py)
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

# Create session with trust_env=False to avoid system proxy
session = requests_go.Session()
session.tls_config = tls
session.trust_env = False

print("=" * 60)
print("Test 1: Normal request (no stream)")
print("=" * 60)
try:
    response = session.get(url=url, headers=headers, tls_config=tls)
    print(f"Status Code: {response.status_code}")
    print(f"URL: {response.url}")
    print(f"Headers: {dict(response.headers)}")
    print(f"Content Length: {len(response.content)}")
    print(f"response.raw type: {type(response.raw)}")
    print(f"response.raw repr: {repr(response.raw)[:300]}")
    print(f"Text (first 200 chars): {response.text[:200]}...")
    print("[PASS] Normal request succeeded!")
except Exception as e:
    print(f"[FAIL] Normal request failed: {e}")
    import traceback
    traceback.print_exc()

print()
print("=" * 60)
print("Test 2: stream=True request with iter_content")
print("=" * 60)
try:
    response = session.get(url=url, headers=headers, tls_config=tls, stream=True)
    print(f"Status Code: {response.status_code}")
    print(f"URL: {response.url}")
    print(f"Headers: {dict(response.headers)}")
    print(f"response.raw type: {type(response.raw)}")
    print(f"response.raw repr: {repr(response.raw)[:300]}")

    # Check for stream_id (set by our stream implementation)
    if hasattr(response, "stream_id"):
        print(f"Stream ID: {response.stream_id}")

    # Test iter_content streaming
    print("\n--- iter_content streaming ---")
    total_bytes = 0
    chunk_count = 0
    for chunk in response.iter_content(chunk_size=1024):
        if chunk:
            chunk_count += 1
            total_bytes += len(chunk)
            print(f"  Chunk {chunk_count}: {len(chunk)} bytes")
    print(f"  Total: {chunk_count} chunks, {total_bytes} bytes")

    print("[PASS] stream=True request succeeded!")
except Exception as e:
    print(f"[FAIL] stream=True request failed: {e}")
    import traceback
    traceback.print_exc()

print()
print("=" * 60)
print("Test 3: stream=True + iter_lines")
print("=" * 60)
try:
    response = session.get(url=url, headers=headers, tls_config=tls, stream=True)
    print(f"Status Code: {response.status_code}")

    print("\n--- iter_lines (first 10 lines) ---")
    line_count = 0
    for line in response.iter_lines(decode_unicode=True):
        line_count += 1
        if line_count <= 10:
            line_str = line if isinstance(line, str) else line.decode("utf-8", errors="replace")
            print(f"  Line {line_count}: {line_str[:100]}")
        if line_count > 10:
            break
    print(f"  ... total {line_count}+ lines read")

    print("[PASS] stream=True + iter_lines succeeded!")
except Exception as e:
    print(f"[FAIL] stream=True + iter_lines failed: {e}")
    import traceback
    traceback.print_exc()

print()
print("=" * 60)
print("Test 4: stream=True -> write to file")
print("=" * 60)
output_file = os.path.join(os.path.dirname(__file__), "stream_output.bin")
try:
    response = session.get(url=url, headers=headers, tls_config=tls, stream=True)
    print(f"Status Code: {response.status_code}")

    # 用 iter_content 把流内容写入文件
    total_bytes = 0
    chunk_count = 0
    with open(output_file, "wb") as f:
        for chunk in response.iter_content(chunk_size=4096):
            if chunk:
                chunk_count += 1
                total_bytes += len(chunk)
                f.write(chunk)
    print(f"  Wrote {chunk_count} chunks, {total_bytes} bytes -> {output_file}")

    # 读回来看一下内容
    with open(output_file, "rb") as f:
        file_content = f.read()
    print(f"  File size: {len(file_content)} bytes")
    print(f"  Preview (first 200 chars): {file_content[:200]}")

    # 对比：用普通请求拿到的完整内容
    print("\n  --- Comparing with normal request ---")
    normal_resp = session.get(url=url, headers=headers, tls_config=tls)
    normal_content = normal_resp.content
    print(f"  Normal content size: {len(normal_content)} bytes")
    print(f"  Stream file size:    {len(file_content)} bytes")
    # 注意：由于是不同请求，动态接口返回内容可能不同，
    #       这里只比较大小是否在合理范围内
    if len(file_content) > 0:
        print("[PASS] Stream content written to file successfully!")
    else:
        print("[WARN] Stream file is empty!")

except Exception as e:
    print(f"[FAIL] Stream write to file failed: {e}")
    import traceback
    traceback.print_exc()

print()
print("=" * 60)
print("All tests complete")
print("=" * 60)
