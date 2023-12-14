CHARLES_SIGNATURE_ALGORITHMS_TO_TLS1_3_Identifier = {
    "ECDSA with SHA-256": "ecdsa_secp256r1_sha256",
    "ECDSA with SHA-384": "ecdsa_secp384r1_sha384",
    "ECDSA with SHA-512": "ecdsa_secp521r1_sha512",
    "RSASSA-PSS with SHA-256": "rsa_pss_rsae_sha256",
    "RSASSA-PSS with SHA-384": "rsa_pss_rsae_sha384",
    "RSASSA-PSS with SHA-512": "rsa_pss_rsae_sha512",
    "unknown signature [9] with Intrinsic": "rsa_pss_rsae_sha256",
    "unknown signature [10] with Intrinsic": "rsa_pss_pss_sha384",
    "unknown signature [11] with Intrinsic": "rsa_pss_pss_sha512",
    "RSASSA-PKCS1-v1_5 with SHA-1": "rsa_pkcs1_sha1",
    "RSASSA-PKCS1-v1_5 with SHA-256": "rsa_pkcs1_sha256",
    "RSASSA-PKCS1-v1_5 with SHA-384": "rsa_pkcs1_sha384",
    "RSASSA-PKCS1-v1_5 with SHA-512": "rsa_pkcs1_sha512",
    "DSA with SHA-1": "0x202",
    "RSASSA-PKCS1-v1_5 with SHA-224": "0x301",
    "DSA with SHA-224": "0x302",
    "ECDSA with SHA-224": "0x303",
    "DSA with SHA-256": "0x402",
    "ECDSA with SHA-1": "ecdsa_sha1",
}


# charles的signature_algorithms转换为TLS1.3的signature_algorithms
def charles_to_tls_signature_algorithms(charles_signature_algorithms: str) -> list[str]:
    signature_algorithm_list = []
    charles_signature_algorithms = charles_signature_algorithms.strip()
    for signature_algorithm in charles_signature_algorithms.split("\n"):
        signature_algorithm_list.append(CHARLES_SIGNATURE_ALGORITHMS_TO_TLS1_3_Identifier[signature_algorithm])
    return signature_algorithm_list
