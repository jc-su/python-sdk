from typing import Any

class SSHClient:
    def exec_command(self, command: str, **kwargs: Any) -> Any: ...
