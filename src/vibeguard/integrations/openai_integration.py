"""OpenAI integration with VibeGuard protection."""

from typing import Any, Iterator

from vibeguard.guard import Guard


class GuardedOpenAI:
    """
    Drop-in replacement for OpenAI client with VibeGuard protection.
    
    Usage:
        from vibeguard.integrations.openai import GuardedOpenAI
        
        client = GuardedOpenAI()  # Uses default Guard settings
        
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": user_input}]
        )
        
        # Input is automatically scanned before sending
        # Output is automatically scanned before returning
    
    With custom Guard:
        guard = Guard(redact_pii=True, max_input_tokens=4000)
        client = GuardedOpenAI(guard=guard)
    """
    
    def __init__(
        self,
        guard: Guard | None = None,
        api_key: str | None = None,
        **openai_kwargs: Any,
    ):
        """
        Initialize the guarded OpenAI client.
        
        Args:
            guard: Custom Guard instance (uses defaults if not provided)
            api_key: OpenAI API key (uses OPENAI_API_KEY env var if not provided)
            **openai_kwargs: Additional arguments passed to OpenAI client
        """
        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError(
                "OpenAI package not installed. Install with: pip install vibeguard[openai]"
            )
        
        self.guard = guard or Guard()
        self._client = OpenAI(api_key=api_key, **openai_kwargs)
        
        # Wrap the chat completions API
        self.chat = _GuardedChat(self._client.chat, self.guard)
        
        # Pass through other attributes
        self.models = self._client.models
        self.embeddings = self._client.embeddings
        self.files = self._client.files
        self.images = self._client.images
        self.audio = self._client.audio
        self.moderations = self._client.moderations


class _GuardedChat:
    """Wrapper for OpenAI chat API with VibeGuard protection."""
    
    def __init__(self, chat: Any, guard: Guard):
        self._chat = chat
        self.guard = guard
        self.completions = _GuardedCompletions(chat.completions, guard)


class _GuardedCompletions:
    """Wrapper for OpenAI completions with input/output scanning."""
    
    def __init__(self, completions: Any, guard: Guard):
        self._completions = completions
        self.guard = guard
    
    def create(
        self,
        messages: list[dict[str, Any]],
        **kwargs: Any,
    ) -> Any:
        """
        Create a chat completion with VibeGuard protection.
        
        Args:
            messages: List of message dicts
            **kwargs: Additional OpenAI parameters
            
        Returns:
            OpenAI ChatCompletion response
            
        Raises:
            ValueError: If input is blocked by VibeGuard
        """
        # Scan user messages in the input
        for i, msg in enumerate(messages):
            if msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, str):
                    result = self.guard.check_input(content)
                    if result.blocked:
                        raise ValueError(f"Input blocked by VibeGuard: {result.reason}")
                    # Replace with sanitized content
                    messages[i] = {**msg, "content": result.sanitized_text}
        
        # Make the API call
        response = self._completions.create(messages=messages, **kwargs)
        
        # Scan the output
        if hasattr(response, "choices") and response.choices:
            for choice in response.choices:
                if hasattr(choice, "message") and hasattr(choice.message, "content"):
                    content = choice.message.content
                    if content:
                        output_result = self.guard.check_output(content)
                        # Note: We don't block output, just scan it
                        # You could modify this behavior if needed
                        if output_result.sanitized_text != content:
                            choice.message.content = output_result.sanitized_text
        
        return response
    
    async def acreate(
        self,
        messages: list[dict[str, Any]],
        **kwargs: Any,
    ) -> Any:
        """Async version of create."""
        # Same input scanning logic
        for i, msg in enumerate(messages):
            if msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, str):
                    result = self.guard.check_input(content)
                    if result.blocked:
                        raise ValueError(f"Input blocked by VibeGuard: {result.reason}")
                    messages[i] = {**msg, "content": result.sanitized_text}
        
        # Make the async API call
        response = await self._completions.acreate(messages=messages, **kwargs)
        
        # Same output scanning
        if hasattr(response, "choices") and response.choices:
            for choice in response.choices:
                if hasattr(choice, "message") and hasattr(choice.message, "content"):
                    content = choice.message.content
                    if content:
                        output_result = self.guard.check_output(content)
                        if output_result.sanitized_text != content:
                            choice.message.content = output_result.sanitized_text
        
        return response
