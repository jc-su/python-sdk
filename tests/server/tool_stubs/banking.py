"""AgentDojo Banking tools — stub implementations with real API calls.

These stubs mirror AgentDojo's banking tools but use real stdlib/third-party
API calls so Pysa can trace taint flow from tool parameters to sinks.
"""

import requests


def get_iban(user_id: str) -> dict:
    """Get the IBAN of the current bank account."""
    response = requests.get(f"http://bank-api.internal/accounts/{user_id}/iban")
    return response.json()


def get_balance(user_id: str) -> dict:
    """Get the current account balance."""
    response = requests.get(f"http://bank-api.internal/accounts/{user_id}/balance")
    return response.json()


def get_most_recent_transactions(user_id: str, n: int = 100) -> dict:
    """List the most recent transactions."""
    response = requests.get(
        f"http://bank-api.internal/accounts/{user_id}/transactions",
        params={"limit": n},
    )
    return response.json()


def get_scheduled_transactions(user_id: str) -> dict:
    """List all scheduled and recurring transactions."""
    response = requests.get(f"http://bank-api.internal/accounts/{user_id}/scheduled")
    return response.json()


def send_money(recipient: str, amount: float, subject: str, date: str) -> dict:
    """Send a money transaction to a recipient IBAN."""
    response = requests.post(
        "http://bank-api.internal/transfers",
        json={"recipient": recipient, "amount": amount, "subject": subject, "date": date},
    )
    return response.json()


def schedule_transaction(recipient: str, amount: float, subject: str, date: str, recurring: bool = False) -> dict:
    """Schedule a future money transaction."""
    response = requests.post(
        "http://bank-api.internal/scheduled",
        json={"recipient": recipient, "amount": amount, "subject": subject, "date": date, "recurring": recurring},
    )
    return response.json()


def update_scheduled_transaction(transaction_id: int, recipient: str = "", amount: float = 0) -> dict:
    """Update a scheduled transaction."""
    response = requests.put(
        f"http://bank-api.internal/scheduled/{transaction_id}",
        json={"recipient": recipient, "amount": amount},
    )
    return response.json()


def update_password(new_password: str) -> dict:
    """Update the user account password."""
    response = requests.post(
        "http://bank-api.internal/auth/password",
        json={"password": new_password},
    )
    return response.json()
