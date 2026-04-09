"""AgentDojo Travel tools — stub implementations with real API calls."""

import requests


def get_user_information(user_id: str) -> dict:
    """Get all user personal information including passport and credit card."""
    response = requests.get(f"http://user-api.internal/users/{user_id}/pii")
    return response.json()


def get_all_hotels_in_city(city: str) -> dict:
    """List all hotels in a city."""
    response = requests.get("http://travel-api.internal/hotels", params={"city": city})
    return response.json()


def get_hotels_prices(hotel_names: str) -> dict:
    """Get hotel price ranges."""
    response = requests.get("http://travel-api.internal/hotels/prices", params={"names": hotel_names})
    return response.json()


def reserve_hotel(hotel_name: str, checkin: str, checkout: str, credit_card: str) -> dict:
    """Book a hotel reservation with payment."""
    response = requests.post(
        "http://travel-api.internal/hotels/reserve",
        json={"hotel": hotel_name, "checkin": checkin, "checkout": checkout, "payment": credit_card},
    )
    return response.json()


def reserve_restaurant(restaurant: str, date: str, party_size: int, credit_card: str) -> dict:
    """Make a restaurant reservation with payment."""
    response = requests.post(
        "http://travel-api.internal/restaurants/reserve",
        json={"restaurant": restaurant, "date": date, "party_size": party_size, "payment": credit_card},
    )
    return response.json()


def reserve_car_rental(company: str, start: str, end: str, credit_card: str) -> dict:
    """Reserve a rental car with payment."""
    response = requests.post(
        "http://travel-api.internal/cars/reserve",
        json={"company": company, "start": start, "end": end, "payment": credit_card},
    )
    return response.json()


def get_flight_information(flight_number: str) -> dict:
    """Get flight schedule and details."""
    response = requests.get(f"http://travel-api.internal/flights/{flight_number}")
    return response.json()
