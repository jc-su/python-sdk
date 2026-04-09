"""Minimal type stubs for stripe — enables Pysa sink resolution."""

from typing import Any

class Charge:
    @staticmethod
    def create(amount: Any, currency: str, **kwargs: Any) -> Any: ...

class PaymentIntent:
    @staticmethod
    def create(amount: Any, currency: str, **kwargs: Any) -> Any: ...

class Transfer:
    @staticmethod
    def create(amount: Any, currency: str, destination: str, **kwargs: Any) -> Any: ...

class Refund:
    @staticmethod
    def create(charge: Any, **kwargs: Any) -> Any: ...
