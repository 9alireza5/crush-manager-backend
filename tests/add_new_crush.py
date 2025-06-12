import requests

url = "http://172.30.26.44:5000/crushes"

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


token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6Im1vZG9zIiwiZXhwIjoxNzQ4NjgwOTYyfQ.xHwmo_Q8N1iarIKGHUxc6ksxwXi56RokT2TKULq1c5I"


headers = {
    'Authorization': f'Bearer {token}'
}


response = requests.post(url, json=data, headers=headers)

if response.status_code == 200 or response.status_code == 201:
    print("Success:", response.json())
else:
    print(response.json())
    print("Error:", response.status_code)
