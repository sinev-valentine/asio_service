import ctypes
import os

cpp = ctypes.CDLL('./libclient.so')

class request_t(ctypes.Structure):
    _fields_ = [('cmd', ctypes.c_char_p),
                ('params', ctypes.c_char_p)]
class response_t(ctypes.Structure):
    _fields_ = [('res', ctypes.c_bool),
                ('params', ctypes.c_char_p)]

cpp.send_message.restype = ctypes.POINTER(response_t)
cpp.send_message.argtypes = [ctypes.POINTER(request_t)]

with open(os.path.join(os.path.dirname(__file__), './src.xml'), 'r') as file:
    xml = file.read()

request = request_t("xml_sign".encode('utf-8'), xml.encode('utf-8'))
response = cpp.send_message(ctypes.byref(request))

if response.contents.res==True:
    mes = "signature verify OK"
else:
    mes = "failed"

print ('{}\n{}'.format(response.contents.params.decode("utf-8"), mes))