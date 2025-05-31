import requests

url = "http://172.30.26.44:5000/register"

# Optional: include headers if needed
headers = {
    'Origin': 'http://localhost',
    'Access-Control-Request-Method': 'POST',
    'Access-Control-Request-Headers': 'Content-Type, Authorization',
}

response = requests.options(url, headers=headers)

print('Status Code:', response.status_code)
print('Headers:', response.headers)
print('Body:', response.text)
