import os
import ctypes
from sys import platform
from platform import machine

if platform == 'darwin':
    file_ext = '-arm64.dylib' if machine() == "arm64" else '-x86.dylib'
elif platform in ('win32', 'cygwin'):
    file_ext = '-win64.dll' if 8 == ctypes.sizeof(ctypes.c_voidp) else '-win32.dll'
else:
    if machine() == "aarch64":
        file_ext = '-arm64.so'
    elif "x86" in machine():
        file_ext = '-x86.so'
    else:
        file_ext = '-amd64.so'

root_dir = os.path.abspath(os.path.dirname(__file__))
library = ctypes.cdll.LoadLibrary(f'{root_dir}/dependencies/requests-go{file_ext}')
if os.environ.get("REQUESTGO_DEPPATH"):
    library = ctypes.cdll.LoadLibrary(os.environ.get("REQUESTGO_DEPPATH"))

request = library.request
request.argtypes = [ctypes.c_char_p]
request.restype = ctypes.c_char_p

freeMemory = library.freeMemory
freeMemory.argtypes = [ctypes.c_char_p]
