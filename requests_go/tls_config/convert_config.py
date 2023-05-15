from .config import TLSConfig


# X.509证书数字签名算法英文形式标识符
TLS1_3_Identifier = {
	'rsa_pkcs1_sha512': 'PKCS1WithSHA512',
	'rsa_pkcs1_sha384': 'PKCS1WithSHA384',
	'rsa_pkcs1_sha256': 'PKCS1WithSHA256',
	'rsa_pkcs1_sha224': 'PKCS1WithSHA224',
	'rsa_pkcs1_sha1': 'PKCS1WithSHA1',
	'dsa_sha512': 'DSAWithSHA512',
	'dsa_sha384': 'DSAWithSHA384',
	'dsa_sha256': 'DSAWithSHA256',
	'dsa_sha224': 'DSAWithSHA224',
	'dsa_sha1': 'DSAWithSHA1',
	'ecdsa_sha512': 'ECDSAWithSHA512',
	'ecdsa_sha384': 'ECDSAWithSHA384',
	'ecdsa_sha256': 'ECDSAWithSHA256',
	'ecdsa_sha224': 'ECDSAWithSHA224',
	'ecdsa_sha1': 'ECDSAWithSHA1',
	'rsa_pss_rsae_sha512': 'PSSWithSHA512',
	'rsa_pss_rsae_sha384': 'PSSWithSHA384',
	'rsa_pss_rsae_sha256': 'PSSWithSHA256',
	'rsa_pss_rsae_sha224': 'PSSWithSHA224',
	'rsa_pss_rsae_sha1': 'PSSWithSHA1',
	'ecdsa_secp521r1_sha512': 'ECDSAWithP521AndSHA512',
	'ecdsa_secp384r1_sha384': 'ECDSAWithP384AndSHA384',
	'ecdsa_secp256r1_sha256': 'ECDSAWithP256AndSHA256',
	'ecdsa_secp224r1_sha224': 'ECDSAWithP224AndSHA224',
}


def to_tls_config(config: dict, name: str = "") -> TLSConfig:
	tls_config = {
		'ja3_string': get_ja3_string(config),
		'h2_settings': get_h2_settings(config),
		'h2_settings_order': get_h2_settings_order(config),
		'supported_signature_algorithms': get_supported_signature_algorithms(config),
		'supported_delegated_credentials_algorithms': get_supported_delegated_credentials_algorithms(config),
		'supported_versions': get_supported_versions(config),
		'key_share_curves': get_key_share_curves(config),
		'cert_compression_algo': get_cert_compression_algo(config),
		'additional_decode': get_additionalDecode(config),
		'pseudo_header_order': get_pseudo_header_order(config),
		'connection_flow': get_connection_flow(config),
		'priority_frames': get_priority_frames(config),
		'header_order': get_header_order(config),
		'header_priority': get_header_priority(config),
		'random_tls_extension_order': False,
		'force_http1': False,
		'catch_panics': False,
	}
	return TLSConfig(name, tls_config)


def get_ja3_string(config):
	ja3_string = config["tls"]["ja3"]
	ja3s = ja3_string.split(",")
	if "41" in ja3s[-3].split("-"):
		raise Exception('failed to do request: Get URL: remote error: tls: unexpected message')
	return ja3_string


def get_h2_settings(config):
	settings = {}
	setting_list = []
	sent_frames = config["http2"]["sent_frames"]
	for sent_frame in sent_frames:
		if sent_frame["frame_type"] == "SETTINGS":
			setting_list = sent_frame["settings"]
	for setting in setting_list:
		key, value = setting.split("=", 1)
		key = key.strip()
		value = value.strip()
		settings[key] = int(value)
	if settings:
		return settings
	return None


def get_h2_settings_order(config):
	settings = get_h2_settings(config)
	return list(settings.keys())


def get_supported_signature_algorithms(config):
	supported_signature_algorithms = []
	extensions = config["tls"]["extensions"]
	for extension in extensions:
		if "signature_algorithms" in extension["name"]:
			signature_algorithms = extension["signature_algorithms"]
			for signature_algorithm in signature_algorithms:
				supported_signature_algorithms.append(TLS1_3_Identifier[signature_algorithm])
	if supported_signature_algorithms:
		return supported_signature_algorithms
	return None


def get_supported_delegated_credentials_algorithms(config):
	pass


def get_supported_versions(config):
	supported_versions = []
	extensions = config["tls"]["extensions"]
	for extension in extensions:
		if "supported_versions" in extension["name"]:
			versions = extension["versions"]
			for version in versions:
				key = version
				if "TLS_" in key:
					key = key.split("TLS_", 1)[-1]
				elif "TLS " in key:
					key = key.split("TLS ", 1)[-1]
				key = key.split("(", 1)[0]
				key = key.strip()
				supported_versions.append(key)
	if supported_versions:
		return supported_versions
	return None


def get_key_share_curves(config):
	key_share_curves = []
	extensions = config["tls"]["extensions"]
	for extension in extensions:
		if "key_share" in extension["name"]:
			shared_keys = extension["shared_keys"]
			for shared_key in shared_keys:
				key = list(shared_key.keys())[0]
				key = key.split("TLS_", 1)[-1]
				key = key.split("(", 1)[0]
				key = key.strip()
				key = key.replace("-", "")
				key_share_curves.append(key)
	if key_share_curves:
		return key_share_curves
	return None


def get_cert_compression_algo(config):
	cert_compression_algo = None
	extensions = config["tls"]["extensions"]
	for extension in extensions:
		if "compress_certificate" in extension["name"]:
			cert_compression_algo = extension["algorithms"][0].split("(", 1)[0].strip()
	return cert_compression_algo


def get_additionalDecode(config):
	additionalDecode = None
	sent_frames = config["http2"]["sent_frames"]
	for sent_frame in sent_frames:
		if sent_frame["frame_type"] == "HEADERS":
			headers_list = sent_frame["headers"]
			break
	for header in headers_list:
		if header[0] == ":":
			continue
		key, value = header.split(":", 1)
		if "accept-encoding" == key.lower():
			values = value.split(",")
			additionalDecode = values[0].strip()
	return additionalDecode


def get_pseudo_header_order(config):
	headers = {}
	headers_list = []
	sent_frames = config["http2"]["sent_frames"]
	for sent_frame in sent_frames:
		if sent_frame["frame_type"] == "HEADERS":
			headers_list = sent_frame["headers"]
			break
	for header in headers_list:
		if header[0] == ":":
			key, value = header.split(":")[1:]
			key = ":" + key.strip()
			value = value.strip()
			headers[key] = value
	return list(headers.keys())


def get_connection_flow(config):
	connection_flow = None
	sent_frames = config["http2"]["sent_frames"]
	for sent_frame in sent_frames:
		if sent_frame["frame_type"] == "WINDOW_UPDATE":
			connection_flow = sent_frame["increment"]
			break
	return connection_flow


def get_priority_frames(config):
	priority_frames = []
	sent_frames = config["http2"]["sent_frames"]
	for sent_frame in sent_frames:
		if sent_frame["frame_type"] == "PRIORITY":
			priority = sent_frame["priority"]
			priority_frame = {
				"streamID": sent_frame["stream_id"],
				"priorityParam": {
					"weight": priority["weight"] - 1,
					"streamDep": priority["depends_on"],
					"exclusive": True if priority["exclusive"] else False
				}
			}
			priority_frames.append(priority_frame)
	if priority_frames:
		return priority_frames
	return None


def get_header_order(config):
	headers = {}
	headers_list = []
	sent_frames = config["http2"]["sent_frames"]
	for sent_frame in sent_frames:
		if sent_frame["frame_type"] == "HEADERS":
			headers_list = sent_frame["headers"]
			break
	for header in headers_list:
		if header[0] == ":":
			continue
		key, value = header.split(":", 1)
		key = key.strip()
		value = value.strip()
		headers[key] = value
	return list(headers.keys())


def get_header_priority(config):
	header_priority = None
	sent_frames = config["http2"]["sent_frames"]
	for sent_frame in sent_frames:
		if sent_frame["frame_type"] == "HEADERS":
			priority = sent_frame["priority"]
			header_priority = {
				"weight": priority["weight"] - 1,
				"streamDep": priority["depends_on"],
				"exclusive": True if priority["exclusive"] else False
			}
			break
	return header_priority
