import requests_go


data = {
    "abc": "123",
    "def": "456",
    "keys": ["abc", "def"],
}
response = requests_go.post('https://httpbin.org/post', data=data, tls_config=requests_go.tls_config.TLS_CHROME_131_LATEST)
print(response.text)
