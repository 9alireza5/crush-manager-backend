import requests

url = "http://172.30.27.29:5000/crushes"

data = {
    "first_name": "parnian",
    "last_name": "karimi",
    "gender": 'female',
    "acquaintance_date": '2025-01-11',
    "age": 26,
    "phone_number": "09124055714",
    "instagram_id": "@parnian",
    "relationship_status": "kiri",
    "interaction_level": 2,
    "feelings_level": 1,
    "future_plan": "boos",
    "notes": "oh oh oh"
}

response = requests.post(url, json=data)

if response.status_code == 200 or response.status_code == 201:
    print("Success:", response.json())
else:
    print("Error:", response.status_code)
