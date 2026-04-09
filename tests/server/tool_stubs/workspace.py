"""AgentDojo Workspace tools — stub implementations with real API calls.

Covers email, calendar, and cloud drive tools.
"""

import os
import smtplib

import requests

# --- Email ---


def send_email(recipient: str, subject: str, body: str) -> dict:
    """Send an email to recipients with subject and body."""
    server = smtplib.SMTP("mail.internal", 587)
    msg = f"Subject: {subject}\n\n{body}"
    server.sendmail("agent@internal", recipient, msg)
    server.quit()
    return {"status": "sent", "to": recipient}


def delete_email(email_id: str) -> dict:
    """Delete an email by moving it to trash."""
    os.remove(f"/var/mail/spool/{email_id}.eml")
    return {"status": "deleted", "id": email_id}


def get_unread_emails(user_id: str) -> dict:
    """Get all unread emails from inbox."""
    response = requests.get(f"http://mail-api.internal/inbox/{user_id}/unread")
    return response.json()


def get_received_emails(user_id: str) -> dict:
    """Get all received emails."""
    response = requests.get(f"http://mail-api.internal/inbox/{user_id}/received")
    return response.json()


def get_sent_emails(user_id: str) -> dict:
    """Get all sent emails."""
    response = requests.get(f"http://mail-api.internal/inbox/{user_id}/sent")
    return response.json()


def search_emails(query: str, sender: str = "") -> dict:
    """Search emails by query string."""
    response = requests.get("http://mail-api.internal/search", params={"q": query, "sender": sender})
    return response.json()


def search_contacts_by_name(name: str) -> dict:
    """Find contacts by name."""
    response = requests.get("http://mail-api.internal/contacts", params={"name": name})
    return response.json()


# --- Calendar ---


def get_day_calendar_events(date: str) -> dict:
    """Get all events for a specific day."""
    response = requests.get("http://calendar-api.internal/events", params={"date": date})
    return response.json()


def search_calendar_events(query: str) -> dict:
    """Search calendar events by title."""
    response = requests.get("http://calendar-api.internal/events/search", params={"q": query})
    return response.json()


def create_calendar_event(title: str, start: str, end: str, participants: str) -> dict:
    """Create a new calendar event and send invites to participants."""
    response = requests.post(
        "http://calendar-api.internal/events",
        json={"title": title, "start": start, "end": end, "participants": participants},
    )
    # Send invite emails
    server = smtplib.SMTP("mail.internal", 587)
    server.sendmail("agent@internal", participants, f"Subject: Invite: {title}\n\n{start}-{end}")
    server.quit()
    return response.json()


def cancel_calendar_event(event_id: str) -> dict:
    """Cancel a calendar event."""
    os.remove(f"/var/calendar/events/{event_id}.ics")
    return {"status": "cancelled", "id": event_id}


# --- Cloud Drive ---


def create_file(filename: str, content: str) -> dict:
    """Create a new file with content in cloud drive."""
    response = requests.post(
        "http://drive-api.internal/files",
        json={"filename": filename, "content": content},
    )
    return response.json()


def delete_file(file_id: str) -> dict:
    """Delete a file from cloud drive by ID."""
    os.remove(f"/var/drive/files/{file_id}")
    return {"status": "deleted", "id": file_id}


def get_file_by_id(file_id: str) -> dict:
    """Get file content by ID from cloud drive."""
    response = requests.get(f"http://drive-api.internal/files/{file_id}")
    return response.json()


def list_files(folder: str = "/") -> dict:
    """List all files in the cloud drive."""
    response = requests.get("http://drive-api.internal/files", params={"folder": folder})
    return response.json()


def search_files(query: str) -> dict:
    """Search files by content in cloud drive."""
    response = requests.get("http://drive-api.internal/files/search", params={"q": query})
    return response.json()


def share_file(file_id: str, user_email: str, permission: str) -> dict:
    """Share a file granting read or write permissions to another user."""
    response = requests.post(
        f"http://drive-api.internal/files/{file_id}/share",
        json={"user": user_email, "permission": permission},
    )
    return response.json()
