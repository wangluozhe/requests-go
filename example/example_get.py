import requests_go as requests

url = "https://tls.peet.ws/api/all"
response = requests.get(url)
print(response.text)
