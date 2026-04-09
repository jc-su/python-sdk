"""AgentDojo Slack tools — stub implementations with real API calls."""

import os

import requests


def get_channels(workspace_id: str) -> dict:
    """Get list of all Slack channels."""
    response = requests.get(f"http://slack-api.internal/{workspace_id}/channels")
    return response.json()


def read_channel_messages(channel: str) -> dict:
    """Read all messages in a Slack channel."""
    response = requests.get(f"http://slack-api.internal/channels/{channel}/messages")
    return response.json()


def read_inbox(user_id: str) -> dict:
    """Read direct messages for a user."""
    response = requests.get(f"http://slack-api.internal/dm/{user_id}")
    return response.json()


def send_direct_message(recipient: str, body: str) -> dict:
    """Send a direct message to a user."""
    response = requests.post(
        "http://slack-api.internal/dm/send",
        json={"recipient": recipient, "body": body},
    )
    return response.json()


def send_channel_message(channel: str, body: str) -> dict:
    """Send a message to a Slack channel."""
    response = requests.post(
        f"http://slack-api.internal/channels/{channel}/send",
        json={"body": body},
    )
    return response.json()


def post_webpage(url: str, content: str) -> dict:
    """Post content to a URL via webhook."""
    response = requests.post(url, json={"content": content})
    return response.json()


def invite_user_to_slack(user_email: str, workspace_id: str) -> dict:
    """Invite a new user to the Slack workspace."""
    response = requests.post(
        f"http://slack-api.internal/{workspace_id}/invite",
        json={"email": user_email},
    )
    return response.json()


def remove_user_from_slack(user_id: str, workspace_id: str) -> dict:
    """Remove a user from the Slack workspace."""
    os.remove(f"/var/slack/users/{workspace_id}/{user_id}.json")
    return {"status": "removed", "user": user_id}


def get_webpage(url: str) -> dict:
    """Fetch content from a webpage URL."""
    response = requests.get(url)
    return {"content": response.text}
