"""
LangChain Integration for VibeGuard.

Provides callbacks and wrappers for securing LangChain applications.

Usage:
    from vibeguard.integrations.langchain import VibeGuardCallback
    
    chain = your_langchain_chain
    chain.invoke(
        {"input": user_message},
        config={"callbacks": [VibeGuardCallback()]}
    )
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from vibeguard.guard import Guard
from vibeguard.models import CheckResult


class VibeGuardCallback:
    """
    LangChain callback handler for VibeGuard security scanning.
    
    Scans inputs and outputs at various stages of the LangChain pipeline.
    """
    
    def __init__(
        self,
        guard: Guard | None = None,
        block_on_issues: bool = True,
        scan_prompts: bool = True,
        scan_outputs: bool = True,
        scan_tool_inputs: bool = True,
        scan_tool_outputs: bool = True,
    ):
        self.guard = guard or Guard()
        self.block_on_issues = block_on_issues
        self.scan_prompts = scan_prompts
        self.scan_outputs = scan_outputs
        self.scan_tool_inputs = scan_tool_inputs
        self.scan_tool_outputs = scan_tool_outputs
        self.results: list[CheckResult] = []
    
    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        if not self.scan_prompts:
            return
        
        for prompt in prompts:
            result = self.guard.check_input(prompt)
            self.results.append(result)
            
            if result.blocked and self.block_on_issues:
                raise SecurityException(f"LLM input blocked: {result.reason}")
    
    def on_llm_end(
        self,
        response: Any,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        if not self.scan_outputs:
            return
        
        try:
            if hasattr(response, 'generations'):
                for gen_list in response.generations:
                    for gen in gen_list:
                        if hasattr(gen, 'text'):
                            result = self.guard.check_output(gen.text)
                            self.results.append(result)
        except Exception:
            pass
    
    def on_chain_start(
        self,
        serialized: Dict[str, Any],
        inputs: Dict[str, Any],
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        if not self.scan_prompts:
            return
        
        for key, value in inputs.items():
            if isinstance(value, str):
                result = self.guard.check_input(value)
                self.results.append(result)
                
                if result.blocked and self.block_on_issues:
                    raise SecurityException(f"Chain input '{key}' blocked: {result.reason}")
    
    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        if not self.scan_tool_inputs:
            return
        
        result = self.guard.check_input(input_str)
        self.results.append(result)
        
        if result.blocked and self.block_on_issues:
            tool_name = serialized.get("name", "unknown")
            raise SecurityException(f"Tool '{tool_name}' input blocked: {result.reason}")
    
    def get_results(self) -> list[CheckResult]:
        return self.results
    
    def clear_results(self) -> None:
        self.results = []


class SecurityException(Exception):
    """Exception raised when VibeGuard blocks an operation."""
    pass


def create_guarded_chain(chain: Any, guard: Guard | None = None, **kwargs: Any) -> Any:
    """Wrap a LangChain chain with VibeGuard protection."""
    callback = VibeGuardCallback(guard=guard, **kwargs)
    
    class GuardedChain:
        def __init__(self, chain, callback):
            self._chain = chain
            self._callback = callback
        
        def invoke(self, input: Any, config: dict | None = None, **kw):
            config = config or {}
            callbacks = config.get("callbacks", [])
            callbacks.append(self._callback)
            config["callbacks"] = callbacks
            return self._chain.invoke(input, config=config, **kw)
        
        def get_security_results(self) -> list[CheckResult]:
            return self._callback.get_results()
        
        def __getattr__(self, name):
            return getattr(self._chain, name)
    
    return GuardedChain(chain, callback)
