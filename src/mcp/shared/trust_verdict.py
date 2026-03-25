"""Trust verdict constants used across attestation and trust management.

Using str enum so TrustVerdict.TRUSTED == "trusted" is True,
preserving backward compatibility with existing string comparisons.
"""

import enum


class TrustVerdict(str, enum.Enum):
    """Trust status for an attestation subject."""

    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    STALE = "stale"
    UNKNOWN = "unknown"
