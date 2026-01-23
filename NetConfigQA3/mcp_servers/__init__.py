from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional, Union

@dataclass
class MCPToolCall:
    tool_name: str
    params: Dict[str, Any]

@dataclass
class ConfigExportResult:
    status: Literal["success", "failure"]
    message: str
    details: Optional[Dict[str, Any]] = None
