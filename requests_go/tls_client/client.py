import os
import ctypes
from sys import platform
from platform import machine
from sysconfig import get_platform


def _bundled_library_path():
    if platform == "win32":
        # Use the Python build architecture, including under Windows emulation.
        arch = get_platform().lower().split("-")[-1]
    else:
        arch = machine().lower()
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(arch, arch)
    filename = {
        ("win32", "amd64"): "requests-go-win64.dll",
        ("cygwin", "amd64"): "requests-go-win64.dll",
        ("linux", "amd64"): "requests-go-amd64.so",
        ("linux", "arm64"): "requests-go-arm64.so",
        ("darwin", "amd64"): "requests-go-x86.dylib",
        ("darwin", "arm64"): "requests-go-arm64.dylib",
    }.get((platform, arch))

    bits = ctypes.sizeof(ctypes.c_void_p) * 8
    if not filename or bits != 64:
        raise OSError(
            f"No bundled requests-go library for {platform} ({arch}, {bits}-bit Python). "
            "Set REQUESTGO_DEPPATH to a compatible shared library."
        )
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "dependencies", filename)


library_path = os.environ.get("REQUESTGO_DEPPATH") or _bundled_library_path()
library = ctypes.cdll.LoadLibrary(library_path)

request = library.request
request.argtypes = [ctypes.c_char_p]
request.restype = ctypes.c_char_p

freeMemory = library.freeMemory
freeMemory.argtypes = [ctypes.c_char_p]

freeSession = library.freeSession
freeSession.argtypes = [ctypes.c_char_p]

# Stream API
stream_request = library.stream_request
stream_request.argtypes = [ctypes.c_char_p]
stream_request.restype = ctypes.c_char_p

stream_read = library.stream_read
stream_read.argtypes = [ctypes.c_char_p, ctypes.c_int]
stream_read.restype = ctypes.c_char_p

stream_close = library.stream_close
stream_close.argtypes = [ctypes.c_char_p]
