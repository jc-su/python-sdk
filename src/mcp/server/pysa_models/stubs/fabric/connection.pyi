from typing import Any

class Connection:
    def run(self, command: str, **kwargs: Any) -> Any: ...
