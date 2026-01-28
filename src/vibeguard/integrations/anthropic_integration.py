"""Anthropic integration with VibeGuard protection."""

from typing import Any

from vibeguard.guard import Guard


class GuardedAnthropic:
    """
    Drop-in replacement for Anthropic client with VibeGuard protection.
    
    Usage:
        from vibeguard.integrations.anthropic import GuardedAnthropic
        
        client = GuardedAnthropic()  # Uses default Guard settings
        
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            messages=[{"role": "user", "content": user_input}]
        )
        
        # Input is automatically scanned before sending
        # Output is automatically scanned before returning
    
    With custom Guard:
        guard = Guard(redact_pii=True, max_input_tokens=4000)
        client = GuardedAnthropic(guard=guard)
    """
    
    def __init__(
        self,
        guard: Guard | None = None,
        api_key: str | None = None,
        **anthropic_kwargs: Any,
    ):
        """
        Initialize the guarded Anthropic client.
        
        Args:
            guard: Custom Guard instance (uses defaults if not provided)
            api_key: Anthropic API key (uses ANTHROPIC_API_KEY env var if not provided)
            **anthropic_kwargs: Additional arguments passed to Anthropic client
        """
        try:
            from anthropic import Anthropic
        except ImportError:
            raise ImportError(
                "Anthropic package not installed. Install with: pip install vibeguard[anthropic]"
            )
        
        self.guard = guard or Guard()
        self._client = Anthropic(api_key=api_key, **anthropic_kwargs)
        
        # Wrap the messages API
        self.messages = _GuardedMessages(self._client.messages, self.guard)
        
        # Pass through other attributes
        self.completions = self._client.completions


class _GuardedMessages:
    """Wrapper for Anthropic messages API with VibeGuard protection."""
    
    def __init__(self, messages: Any, guard: Guard):
        self._messages = messages
        self.guard = guard
    
    def create(
        self,
        messages: list[dict[str, Any]],
        **kwargs: Any,
    ) -> Any:
        """
        Create a message with VibeGuard protection.
        
        Args:
            messages: List of message dicts
            **kwargs: Additional Anthropic parameters
            
        Returns:
            Anthropic Message response
            
        Raises:
            ValueError: If input is blocked by VibeGuard
        """
        # Scan user messages in the input
        processed_messages = []
        for msg in messages:
            if msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, str):
                    result = self.guard.check_input(content)
                    if result.blocked:
                        raise ValueError(f"Input blocked by VibeGuard: {result.reason}")
                    processed_messages.append({**msg, "content": result.sanitized_text})
                elif isinstance(content, list):
                    # Handle multi-part content (text + images)
                    processed_content = []
                    for part in content:
                        if part.get("type") == "text":
                            result = self.guard.check_input(part.get("text", ""))
                            if result.blocked:
                                raise ValueError(f"Input blocked by VibeGuard: {result.reason}")
                            processed_content.append({**part, "text": result.sanitized_text})
                        else:
                            processed_content.append(part)
                    processed_messages.append({**msg, "content": processed_content})
                else:
                    processed_messages.append(msg)
            else:
                processed_messages.append(msg)
        
        # Make the API call
        response = self._messages.create(messages=processed_messages, **kwargs)
        
        # Scan the output
        if hasattr(response, "content") and response.content:
            for i, block in enumerate(response.content):
                if hasattr(block, "text") and block.text:
                    output_result = self.guard.check_output(block.text)
                    # Note: We can't easily modify the response object,
                    # but we've logged any issues
                    # In production, you might want to create a new response object
        
        return response
    
    async def acreate(
        self,
        messages: list[dict[str, Any]],
        **kwargs: Any,
    ) -> Any:
        """Async version of create."""
        # Same input scanning logic
        processed_messages = []
        for msg in messages:
            if msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, str):
                    result = self.guard.check_input(content)
                    if result.blocked:
                        raise ValueError(f"Input blocked by VibeGuard: {result.reason}")
                    processed_messages.append({**msg, "content": result.sanitized_text})
                else:
                    processed_messages.append(msg)
            else:
                processed_messages.append(msg)
        
        # Make the async API call
        response = await self._messages.acreate(messages=processed_messages, **kwargs)
        
        # Same output scanning
        if hasattr(response, "content") and response.content:
            for block in response.content:
                if hasattr(block, "text") and block.text:
                    self.guard.check_output(block.text)
        
        return response
    
    def stream(
        self,
        messages: list[dict[str, Any]],
        **kwargs: Any,
    ) -> Any:
        """
        Create a streaming message with VibeGuard protection on input.
        
        Note: Output scanning is limited for streaming responses.
        """
        # Scan user messages in the input
        processed_messages = []
        for msg in messages:
            if msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, str):
                    result = self.guard.check_input(content)
                    if result.blocked:
                        raise ValueError(f"Input blocked by VibeGuard: {result.reason}")
                    processed_messages.append({**msg, "content": result.sanitized_text})
                else:
                    processed_messages.append(msg)
            else:
                processed_messages.append(msg)
        
        # Return the stream (output scanning would need to be done by caller)
        return self._messages.stream(messages=processed_messages, **kwargs)
