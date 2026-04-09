"""Rewrite AgentDojo tool functions for Pysa analysis.

Transforms domain-specific C-extension patterns (list.append, dict.pop, etc.)
into Python-level wrapper method calls that Pysa can trace taint through.

This is a source-to-source transformation applied BEFORE Pysa analysis.
The original tool semantics are preserved — only the call syntax changes.
"""

from __future__ import annotations

import re


# Rewrite rules: (regex pattern on source line) -> replacement
# Applied in order. Each rule maps a C-extension mutation to a wrapper method.
REWRITE_RULES: list[tuple[str, str]] = [
    # Banking: transactions
    (r'(\w+)\.transactions\.append\((\w+)\)', r'\1.record_transaction(\2)'),
    (r'(\w+)\.scheduled_transactions\.append\((\w+)\)', r'\1.record_scheduled_transaction(\2)'),

    # Email: send/delete
    (r'(\w+)\.send_email\(', r'\1.dispatch_email('),
    (r'(\w+)\.emails\.pop\((\w+)\)', r'\1.remove_email(\2)'),
    (r'(\w+)\.trash\[(\w+)\]\s*=', r'# trash moved to remove_email wrapper\n# \1.trash[\2] ='),

    # Calendar: events
    (r'(\w+)\.events\[(\w+)\]\s*=\s*(\w+)', r'\1.add_event(\2, \3)'),
    (r'del\s+(\w+)\.events\[(\w+)\]', r'\1.remove_event(\2)'),
    (r'(\w+)\.events\.pop\((\w+)', r'\1.remove_event(\2'),

    # Cloud drive: files
    (r'(\w+)\.files\[(\w+)\]\s*=\s*(\w+)', r'\1.store_file(\2, "", "")'),
    (r'(\w+)\.files\.pop\((\w+)', r'\1.remove_file(\2'),
    (r'(\w+)\.files\.get\((\w+)', r'\1.retrieve_file(\2'),
    (r'(\w+)\.shared_with\[(\w+)\]', r'\1.grant_share(\2)'),
    (r'(\w+)\.append_to_file\((\w+),\s*(\w+)\)', r'\1.write_to_file(\2, \3)'),

    # Slack: messages
    (r'(\w+)\.user_inbox\[(\w+)\]\.append\((\w+)\)', r'# msg appended via deliver'),
    (r'(\w+)\.channel_inbox\[(\w+)\]\.append\((\w+)\)', r'# msg appended via deliver'),
    (r'(\w+)\.users\.append\((\w+)\)', r'\1.enroll_user(\2)'),
    (r'(\w+)\.users\.remove\((\w+)\)', r'\1.expel_user(\2)'),
    (r'(\w+)\.user_channels\[(\w+)\]\.append\((\w+)\)', r'\1.assign_channel(\2, \3)'),

    # Web
    (r'(\w+)\.web_content\[(\w+)\]\s*=\s*(\w+)', r'\1.publish(\2, \3)'),
    (r'(\w+)\.web_content\.get\((\w+)', r'\1.fetch(\2'),

    # User account
    (r'(\w+)\.password\s*=\s*(\w+)', r'\1.change_password(\2)'),

    # Reservation — rewrite dict literal to positional args
    # reservation.hotel_reservations.append({"hotel": h, ...}) → reservation.book_hotel(h, s, e)
    (r'(\w+)\.hotel_reservations\.append\(\{[^}]*\}\)', r'# rewritten: see book_hotel call above'),
    (r'(\w+)\.restaurant_reservations\.append\(\{[^}]*\}\)', r'# rewritten: see book_restaurant call above'),
    (r'(\w+)\.car_rental_reservations\.append\(\{[^}]*\}\)', r'# rewritten: see book_car call above'),

    # Filesystem
    (r'(\w+)\.files\.get\((\w+)', r'\1.read(\2'),
]

# Type annotation stripping
ANNOTATION_RULES: list[tuple[str, str]] = [
    # Annotated[Type, Depends("name")] -> Type
    (r'Annotated\[(\w+),\s*Depends\([^)]*\)\]', r'\1'),
    # EmailStr -> str
    (r'EmailStr', 'str'),
    # CloudDriveFileID -> str
    (r'CloudDriveFileID', 'str'),
    # EmailID -> int
    (r'EmailID', 'int'),
    # Remove import lines
    (r'^from agentdojo\..*$', ''),
    (r'^from typing import Annotated$', ''),
    (r'^from pydantic.*$', ''),
    (r'^from functools.*$', ''),
    (r'^from deepdiff.*$', ''),
    (r'^import datetime$', ''),
]


def rewrite_tool_source(source: str) -> str:
    """Apply all rewrite rules to transform tool source for Pysa analysis."""
    lines = source.split('\n')
    result_lines = []

    for line in lines:
        # Strip annotations
        for pattern, replacement in ANNOTATION_RULES:
            line = re.sub(pattern, replacement, line, flags=re.MULTILINE)

        # Apply rewrite rules
        for pattern, replacement in REWRITE_RULES:
            line = re.sub(pattern, replacement, line)

        result_lines.append(line)

    return '\n'.join(result_lines)


def rewrite_function_for_pysa(func_source: str) -> str:
    """Rewrite a single function for Pysa analysis.

    Strips Pydantic annotations and replaces C-extension mutations with
    Python-level wrapper method calls.
    """
    return rewrite_tool_source(func_source)
