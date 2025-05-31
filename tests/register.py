import requests

url = "http://172.30.26.44:5000/register"

data = {
    "username": "aliali",
    "password": "aliali",
    "email": "aliali@gmail.com",
}

response = requests.post(url, json=data)

if response.status_code == 200 or response.status_code == 201:
    print("Success:", response.json())
else:
    print("Error:", response.json())
