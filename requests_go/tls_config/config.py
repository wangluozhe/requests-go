from .extensions import TLSExtensions, HTTP2Settings


class TLSConfig:
    def __init__(self):
        super(TLSConfig, self).__init__()
        self._keys = [
            "ja3",
            "headers_order",
            "force_http1",
            "pseudo_header_order",
            "tls_extensions",
            "http2_settings",
        ]
        self.ja3: str = None  # tls ja3 value
        self.headers_order: list[str] = None  # http headers order
        self.force_http1: bool = False  # force http1 request
        # :method
        # :authority
        # :scheme
        # :path
        # Example:
        # [
        #     ":method",
        #     ":authority",
        #     ":scheme",
        #     ":path"
        # ]
        self.pseudo_header_order: list[str] = None  # HTTP2 Pseudo header order
        self.tls_extensions: TLSExtensions = TLSExtensions()  # tls extensions
        self.http2_settings: HTTP2Settings = HTTP2Settings()  # http2 extensions

    def __str__(self):
        return str(self.toJSON())

    def __iter__(self):
        for key in self._keys:
            yield key, getattr(self, key)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __getitem__(self, item):
        return getattr(self, item)

    def __delitem__(self, key):
        setattr(self, key, None)

    def __delattr__(self, item):
        setattr(self, item, None)

    # JSON转类
    def _fromJSON(self, config: dict):
        for key, value in config.items():
            if key in self._keys:
                setattr(self, key, value)

    # 类转JSON
    def toJSON(self):
        result = {}
        for key in self._keys:
            go_keys = key.split("_")
            go_key = ""
            for k in go_keys:
                if k == "tls" or k == "http2" or k == "http1":
                    go_key += k.upper()
                else:
                    go_key += k.title()
            if key in ["tls_extensions", "http2_settings"]:
                result[go_key] = getattr(self, key).toJSON()
            else:
                result[go_key] = getattr(self, key)
        return result
