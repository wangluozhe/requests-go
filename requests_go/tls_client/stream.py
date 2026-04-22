"""
Stream support for requests-go.

This module provides a file-like StreamBody object that wraps the Go DLL's
stream_request / stream_read / stream_close API, allowing requests' iter_content
and iter_lines to work transparently with streaming responses.
"""
import base64
import io
from json import dumps, loads

from .client import stream_request as _stream_request
from .client import stream_read as _stream_read
from .client import stream_close as _stream_close
from .exceptions import TLSClientExeption


class StreamBody(io.RawIOBase):
    """A file-like object that reads from the Go DLL stream_read API.

    Implements io.RawIOBase so it can be used as the ``body`` parameter
    for urllib3.HTTPResponse, which in turn is set as ``response.raw`` on a
    ``requests.Response``.  The standard ``iter_content`` / ``iter_lines``
    helpers then Just Work™.
    """

    def __init__(self, stream_id: str):
        super().__init__()
        self._stream_id = stream_id
        self._eof = False
        self._closed = False
        # Buffer for leftover data from previous reads
        self._buffer = b""

    # ---- io.RawIOBase interface ----

    def readable(self) -> bool:
        return True

    def writable(self) -> bool:
        return False

    def seekable(self) -> bool:
        return False

    def read(self, size: int = -1) -> bytes:
        """Read up to *size* bytes.  ``-1`` means read until EOF."""
        if self._closed or self._eof:
            return b""

        if size == -1 or size is None:
            # Read everything
            chunks = []
            if self._buffer:
                chunks.append(self._buffer)
                self._buffer = b""
            while not self._eof:
                chunk = self._read_chunk(65536)
                if chunk:
                    chunks.append(chunk)
            return b"".join(chunks)

        # If we already have enough buffered data, return from buffer
        if len(self._buffer) >= size:
            result = self._buffer[:size]
            self._buffer = self._buffer[size:]
            return result

        # Otherwise, collect so far and keep reading
        result = self._buffer
        self._buffer = b""
        while len(result) < size and not self._eof:
            chunk = self._read_chunk(size - len(result))
            if chunk:
                result += chunk

        return result

    def readinto(self, b):
        """Read up to len(b) bytes into the buffer *b*."""
        data = self.read(len(b))
        n = len(data)
        b[:n] = data
        return n

    def close(self):
        if not self._closed:
            self._closed = True
            try:
                _stream_close(self._stream_id.encode("utf-8"))
            except Exception:
                pass
            super().close()

    @property
    def closed(self):
        return self._closed

    # ---- internal ----

    def _read_chunk(self, size: int) -> bytes:
        """Call DLL stream_read once, returns decoded bytes (may be empty)."""
        if self._eof:
            return b""

        try:
            raw = _stream_read(
                self._stream_id.encode("utf-8"),
                size,
            )
            result = loads(raw.decode("utf-8"))
        except Exception as e:
            self._eof = True
            raise TLSClientExeption(f"stream_read failed: {e}")

        if result.get("err"):
            self._eof = True
            raise TLSClientExeption(f"stream_read error: {result['err']}")

        data = b""
        if result.get("data"):
            data = base64.b64decode(result["data"])

        if result.get("eof"):
            self._eof = True

        return data


def open_stream(request_params: dict):
    """Send a stream_request to the DLL and return ``(meta_dict, StreamBody)``.

    *request_params* is the same JSON-serialisable dict that would be sent to
    the normal ``request`` export, with the ``Stream`` flag set automatically.

    Returns
    -------
    meta : dict
        Contains ``stream_id``, ``status_code``, ``url``, ``headers``, ``cookies``.
    body : StreamBody
        A file-like object for reading the response body incrementally.
    """
    request_params["Stream"] = True
    payload = dumps(request_params).encode("utf-8")

    raw = _stream_request(payload)
    meta = loads(raw.decode("utf-8"))

    if meta.get("err"):
        raise TLSClientExeption(f"stream_request error: {meta['err']}")

    stream_id = meta["stream_id"]
    return meta, StreamBody(stream_id)
