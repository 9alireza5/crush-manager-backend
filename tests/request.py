import requests

url = "http://172.30.27.202:5000/crushes"

data = {
    "first_name": "tina",
    "last_name": "kouchak",
    "gender": 'male',
    "acquaintance_date": '2025-01-11',
    "age": 25,
    "phone_number": "09124055714",
    "instagram_id": "@tina",
    "relationship_status": "kiri",
    "interaction_level": 2,
    "feelings_level": 1,
    "future_plan": "kardan",
    "notes": "ey joon"
}

response = requests.post(url, json=data)

if response.status_code == 200 or response.status_code == 201:
    print("Success:", response.json())
else:
    print("Error:", response.status_code)
