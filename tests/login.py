import requests

url = "http://172.30.26.44:8000/login"

data = {
    "username": "modos",
    "password": "modosmodos",
}




response = requests.post(url, json=data)

if response.status_code == 200 or response.status_code == 201:
    print("Success:", response.json())
else:
    print("Error:", response.json())
