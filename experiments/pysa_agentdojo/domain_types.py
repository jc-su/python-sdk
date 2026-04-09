"""AgentDojo domain types with explicit wrapper methods for Pysa taint analysis.

AgentDojo tools mutate Pydantic models via C-extension methods (list.append,
dict.pop, dict.__setitem__) that Pysa cannot trace. This module provides
equivalent domain types with Python-level methods that Pysa CAN trace.

Each wrapper method does the same operation as the original C-extension call
but through a Python method that Pysa can model as a taint sink.
"""

from typing import Any


# ---------------------------------------------------------------------------
# Banking domain
# ---------------------------------------------------------------------------

class Transaction:
    def __init__(
        self, id: int = 0, sender: str = "", recipient: str = "",
        amount: float = 0.0, subject: str = "", date: str = "", recurring: bool = False,
    ):
        self.id = id
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.subject = subject
        self.date = date
        self.recurring = recurring


class BankAccount:
    balance: float = 0.0
    iban: str = ""
    transactions: list[Any] = []
    scheduled_transactions: list[Any] = []

    def record_transaction(self, transaction: Transaction) -> None:
        """Wrapper: account.transactions.append(t)"""
        self.transactions.append(transaction)

    def record_scheduled_transaction(self, transaction: Transaction) -> None:
        """Wrapper: account.scheduled_transactions.append(t)"""
        self.scheduled_transactions.append(transaction)

    def get_recent_transactions(self, n: int) -> list[Any]:
        """Read access: return recent transactions."""
        return self.transactions[-n:]

    def get_all_scheduled(self) -> list[Any]:
        """Read access: return all scheduled transactions."""
        return self.scheduled_transactions

    def update_scheduled_transaction_fields(
        self, transaction: Transaction,
        recipient: str = "", amount: float = 0, subject: str = "",
        date: str = "", recurring: bool = False,
    ) -> None:
        """Wrapper for field-level updates on scheduled transactions."""
        if recipient:
            transaction.recipient = recipient
        if amount:
            transaction.amount = amount
        if subject:
            transaction.subject = subject
        if date:
            transaction.date = date


# ---------------------------------------------------------------------------
# Email domain
# ---------------------------------------------------------------------------

class Email:
    def __init__(
        self, id_: int = 0, sender: str = "", body: str = "", subject: str = "",
        recipients: list[str] | None = None, status: str = "", timestamp: Any = None,
        cc: list[str] | None = None, bcc: list[str] | None = None,
        attachments: list[Any] | None = None, read: bool = False,
    ):
        self.id_ = id_
        self.sender = sender
        self.body = body
        self.subject = subject
        self.recipients = recipients or []
        self.cc = cc or []
        self.bcc = bcc or []
        self.attachments = attachments or []


class Inbox:
    account_email: str = ""
    emails: dict[int, Any] = {}
    trash: dict[int, Any] = {}

    def get_all_emails(self) -> list[Email]:
        """Read access: return all emails."""
        return list(self.emails.values())

    def get_emails_by_status(self, status: str) -> list[Email]:
        """Read access: return emails filtered by status."""
        return list(self.emails.values())

    def dispatch_email(self, recipients: list[str], subject: str, body: str,
                       cc: list[str] | None = None, bcc: list[str] | None = None,
                       attachments: list[Any] | None = None) -> Email:
        """Wrapper: creates and stores a sent email."""
        new_email = Email(
            id_=0, sender=self.account_email, body=body, subject=subject,
            recipients=recipients, status="sent", cc=cc or [], bcc=bcc or [],
            attachments=attachments or [],
        )
        self.emails[0] = new_email
        return new_email

    def remove_email(self, email_id: int) -> Email:
        """Wrapper: inbox.emails.pop(email_id) + trash."""
        email = self.emails.pop(email_id, None)
        if email:
            self.trash[email_id] = email
        return email  # type: ignore

    def query_emails(self, query: str, sender: str = "") -> list[Email]:
        """Wrapper: search emails by query."""
        return [e for e in self.emails.values() if query.lower() in str(e)]


# ---------------------------------------------------------------------------
# Calendar domain
# ---------------------------------------------------------------------------

class CalendarEvent:
    def __init__(self, **kwargs: Any):
        for k, v in kwargs.items():
            setattr(self, k, v)


class Calendar:
    events: dict[str, Any] = {}

    def get_events_for_day(self, day: str) -> list[Any]:
        """Read access: return events for a day."""
        return list(self.events.values())

    def search(self, query: str, date: str = "") -> list[Any]:
        """Read access: search events."""
        return list(self.events.values())

    def add_event(self, event_id: str, event: CalendarEvent) -> None:
        """Wrapper: calendar.events[id] = event"""
        self.events[event_id] = event

    def remove_event(self, event_id: str) -> None:
        """Wrapper: del calendar.events[id]"""
        self.events.pop(event_id, None)

    def update_event(self, event_id: str, **kwargs: Any) -> None:
        """Wrapper: update event fields."""
        event = self.events.get(event_id)
        if event:
            for k, v in kwargs.items():
                setattr(event, k, v)


# ---------------------------------------------------------------------------
# Cloud Drive domain
# ---------------------------------------------------------------------------

class CloudDriveFile:
    id_: str = ""
    content: str = ""
    shared_with: dict[str, bool] = {}

    def grant_share(self, email: str, permission: str = "read") -> None:
        """Wrapper: file.shared_with[email] = True"""
        self.shared_with[email] = True


class CloudDrive:
    files: dict[str, CloudDriveFile] = {}

    def store_file(self, file_id: str, filename: str, content: str) -> CloudDriveFile:
        """Wrapper: cloud_drive.files[id] = new_file"""
        f = CloudDriveFile()
        f.id_ = file_id
        f.content = content
        self.files[file_id] = f
        return f

    def remove_file(self, file_id: str) -> None:
        """Wrapper: cloud_drive.files.pop(id)"""
        self.files.pop(file_id, None)

    def retrieve_file(self, file_id: str) -> CloudDriveFile:
        """Wrapper: cloud_drive.files[id]"""
        return self.files.get(file_id, CloudDriveFile())

    def write_to_file(self, file_id: str, content: str) -> None:
        """Wrapper: append content to file."""
        f = self.files.get(file_id)
        if f:
            f.content += content

    def find_files(self, query: str) -> list[CloudDriveFile]:
        """Wrapper: search files by query."""
        return [f for f in self.files.values() if query in f.content or query in f.id_]

    def find_files_by_name(self, filename: str) -> list[CloudDriveFile]:
        """Wrapper: search files by filename."""
        return [f for f in self.files.values() if filename in f.id_]


# ---------------------------------------------------------------------------
# Slack domain
# ---------------------------------------------------------------------------

class Message:
    def __init__(self, sender: str = "", recipient: str = "", body: str = ""):
        self.sender = sender
        self.recipient = recipient
        self.body = body


class Slack:
    users: list[str] = []
    channels: list[str] = []
    user_channels: dict[str, list[str]] = {}
    user_inbox: dict[str, list[Any]] = {}
    channel_inbox: dict[str, list[Any]] = {}

    def list_channels(self) -> list[str]:
        """Read access: return channels."""
        return self.channels

    def list_users_in_channel(self, channel: str) -> list[str]:
        """Read access: return users in channel."""
        return [u for u, chs in self.user_channels.items() if channel in chs]

    def deliver_direct_message(self, sender: str, recipient: str, body: str) -> None:
        """Wrapper: create Message and add to user_inbox."""
        msg = Message(sender=sender, recipient=recipient, body=body)
        self.user_inbox.setdefault(recipient, [])

    def deliver_channel_message(self, sender: str, channel: str, body: str) -> None:
        """Wrapper: create Message and add to channel_inbox."""
        msg = Message(sender=sender, recipient=channel, body=body)
        self.channel_inbox.setdefault(channel, [])

    def enroll_user(self, user: str) -> None:
        """Wrapper: slack.users.append(user)"""
        self.users.append(user)

    def expel_user(self, user: str) -> None:
        """Wrapper: slack.users.remove(user)"""
        if user in self.users:
            self.users.remove(user)

    def assign_channel(self, user: str, channel: str) -> None:
        """Wrapper: slack.user_channels[user].append(channel)"""
        self.user_channels.setdefault(user, [])

    def read_channel(self, channel: str) -> list[Message]:
        """Wrapper: slack.channel_inbox.get(channel)"""
        return self.channel_inbox.get(channel, [])

    def read_user_inbox(self, user: str) -> list[Message]:
        """Wrapper: slack.user_inbox.get(user)"""
        return self.user_inbox.get(user, [])


# ---------------------------------------------------------------------------
# Web domain
# ---------------------------------------------------------------------------

class Web:
    web_content: dict[str, str] = {}
    web_requests: list[str] = []

    def publish(self, url: str, content: str) -> None:
        """Wrapper: web.web_content[url] = content"""
        self.web_content[url] = content

    def fetch(self, url: str) -> str:
        """Wrapper: web.web_content.get(url)"""
        return self.web_content.get(url, "404 Not Found")


# ---------------------------------------------------------------------------
# Travel domain
# ---------------------------------------------------------------------------

class User:
    first_name: str = ""
    passport_number: str = ""
    credit_card_number: str = ""
    bank_account_number: str = ""


class Hotels:
    data: dict[str, Any] = {}

    def query(self, city: str) -> list[Any]:
        """Read access: get hotels for query."""
        return list(self.data.values())

    def get_prices(self, hotel_names: list[str]) -> dict[str, Any]:
        """Read access: get hotel prices."""
        return {}

    def get_info(self, hotel_name: str) -> Any:
        """Read access: get hotel info."""
        return {}


class Restaurants:
    data: dict[str, Any] = {}

    def query(self, city: str) -> list[Any]:
        """Read access: get restaurants."""
        return list(self.data.values())

    def get_info(self, restaurant_names: list[str]) -> dict[str, Any]:
        """Read access: get restaurant info."""
        return {}


class CarRental:
    data: dict[str, Any] = {}

    def query(self, city: str) -> list[Any]:
        """Read access: get car rentals."""
        return list(self.data.values())

    def get_info(self, company_name: str) -> Any:
        """Read access: get car rental info."""
        return {}


class Flights:
    data: dict[str, Any] = {}

    def query(self, departure: str, arrival: str) -> list[Any]:
        """Read access: get flights."""
        return list(self.data.values())


class Reservation:
    hotel_reservations: list[Any] = []
    restaurant_reservations: list[Any] = []
    car_rental_reservations: list[Any] = []

    def book_hotel(self, hotel: str, start_day: str, end_day: str) -> None:
        """Wrapper: reservation.hotel_reservations.append(...)"""
        self.hotel_reservations.append({"hotel": hotel, "start": start_day, "end": end_day})

    def book_restaurant(self, restaurant: str, start_time: str) -> None:
        """Wrapper: reservation.restaurant_reservations.append(...)"""
        self.restaurant_reservations.append({"restaurant": restaurant, "time": start_time})

    def book_car(self, company: str, start_time: str, end_time: str) -> None:
        """Wrapper: reservation.car_rental_reservations.append(...)"""
        self.car_rental_reservations.append({"company": company, "start": start_time, "end": end_time})


# ---------------------------------------------------------------------------
# User account domain
# ---------------------------------------------------------------------------

class UserAccount:
    password: str = ""
    first_name: str = ""
    last_name: str = ""

    def change_password(self, new_password: str) -> None:
        """Wrapper: user_account.password = new_password"""
        self.password = new_password

    def change_info(self, first_name: str = "", last_name: str = "", **kwargs: Any) -> None:
        """Wrapper: update user info fields."""
        if first_name:
            self.first_name = first_name
        if last_name:
            self.last_name = last_name


# ---------------------------------------------------------------------------
# Filesystem domain
# ---------------------------------------------------------------------------

class Filesystem:
    files: dict[str, str] = {}

    def read(self, file_path: str) -> str:
        """Wrapper: filesystem.files[path]"""
        return self.files.get(file_path, "")
