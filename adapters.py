"""Safe adapter contracts for ReverseAI.

This module intentionally contains no subprocess, debugger, Frida, Ghidra or
LLM client code. Production adapters must implement these contracts behind an
isolated worker and an explicit allowlist. The local server uses NullAdapter so
an unconfigured environment cannot accidentally execute a sample or mutate a
reverse-engineering project.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping, Protocol


@dataclass(frozen=True)
class AdapterStatus:
    name: str
    version: str
    status: str
    capabilities: tuple[str, ...]
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class Adapter(Protocol):
    status: AdapterStatus

    def inspect(self, request: Mapping[str, Any]) -> dict[str, Any]:
        """Return evidence metadata without executing an untrusted sample."""

    def annotate(self, request: Mapping[str, Any]) -> dict[str, Any]:
        """Return a proposed write operation; never apply it implicitly."""


class AdapterNotConfigured(RuntimeError):
    """Raised when a real worker has not been explicitly configured."""


class NullAdapter:
    """Fail-closed adapter used by the local development service."""

    def __init__(self, name: str, reason: str, capabilities: tuple[str, ...] = ()) -> None:
        self.status = AdapterStatus(name, "contract-v1", "not_configured", capabilities, reason)

    def inspect(self, request: Mapping[str, Any]) -> dict[str, Any]:
        raise AdapterNotConfigured(self.status.reason)

    def annotate(self, request: Mapping[str, Any]) -> dict[str, Any]:
        raise AdapterNotConfigured("写入适配器未配置；只能先提交人工复核提案")


class AdapterRegistry:
    def __init__(self, adapters: Mapping[str, Adapter]) -> None:
        self._adapters = dict(adapters)

    def statuses(self) -> dict[str, dict[str, Any]]:
        return {name: adapter.status.as_dict() for name, adapter in self._adapters.items()}

    def get(self, name: str) -> Adapter:
        try:
            return self._adapters[name]
        except KeyError as exc:
            raise AdapterNotConfigured(f"适配器不存在: {name}") from exc


def default_registry() -> AdapterRegistry:
    return AdapterRegistry({
        "ghidra_mcp": NullAdapter(
            "ghidra_mcp", "未配置 Ghidra worker；不会连接项目或执行 MCP 工具",
            ("read-only inspection (future)", "proposal-only annotations"),
        ),
        "frida": NullAdapter(
            "frida", "未配置隔离动态分析 worker；不会附加进程或运行样本",
            ("isolated trace (future)",),
        ),
        "llm": NullAdapter(
            "llm", "未配置模型 provider；当前仅使用本地规则助手",
            ("evidence summarization (future)",),
        ),
        "sandbox": NullAdapter(
            "sandbox", "未部署隔离执行环境；不会运行样本或附加进程",
            ("isolated execution (future)",),
        ),
    })
