import requests

TECHNOCORE_API = "https://technocore.chat"


def get_rooms():
    url = f"{TECHNOCORE_API}/rooms"
    params = {
        "format": "json",
        "limit": 5,
    }

    response = requests.get(url, params=params)
    response.raise_for_status()

    return response.json()


rooms_data = get_rooms()

for room in rooms_data["rooms"]:
    print(room["room"])