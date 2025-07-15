import requests_go


params = {
    "abc": ["123", "456", "789"],
}
headers = {
    "content-type": "application/x-protobuf"
}
phone = '27840809284'
data = b'\n\r\n\x0b{}\xba\x01\n\n\x08STANDARD'.replace(b'{}', phone.encode())
response = requests_go.post('https://httpbin.org/post', params=params, headers=headers, data=data, tls_config=requests_go.tls_config.TLS_CHROME_131_LATEST)
print(response.text)
