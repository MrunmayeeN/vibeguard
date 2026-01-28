"""
ML-Enhanced Prompt Injection Detection Scanner.

Combines fast regex-based detection with ML models for higher accuracy
and confidence scoring.

Usage:
    # Fast mode (regex only)
    scanner = PromptInjectionScanner(use_ml=False)
    
    # ML mode (regex + transformer model)
    scanner = PromptInjectionScanner(use_ml=True)
    
    # Hybrid mode (regex first, ML for uncertain cases)
    scanner = PromptInjectionScanner(use_ml=True, hybrid_mode=True)
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import ClassVar

from vibeguard.models import Issue, IssueSeverity, IssueType, ScanDirection
from vibeguard.scanners import Scanner


class DetectionMethod(str, Enum):
    """How the detection was made."""
    REGEX = "regex"
    ML_MODEL = "ml_model"
    ENSEMBLE = "ensemble"


@dataclass
class DetectionResult:
    """Result from a single detection method."""
    detected: bool
    confidence: float  # 0.0 - 1.0
    method: DetectionMethod
    category: str
    detail: str
    evidence: str | None = None


class PromptInjectionScanner(Scanner):
    """
    ML-Enhanced Prompt Injection Scanner.
    
    Detection modes:
    - Regex only (fast, ~1ms, good for high-volume)
    - ML only (accurate, ~50-100ms, requires torch)
    - Hybrid (regex first, ML for edge cases, best balance)
    
    Confidence scores:
    - 0.0-0.3: Low confidence (likely benign)
    - 0.3-0.6: Medium confidence (review recommended)
    - 0.6-0.8: High confidence (likely malicious)
    - 0.8-1.0: Very high confidence (almost certain)
    """
    
    name: str = "prompt_injection"
    
    # Pattern format: (regex, category, detail, base_confidence, severity)
    INJECTION_PATTERNS: ClassVar[list[tuple[str, str, str, float, IssueSeverity]]] = [
        # === CRITICAL: Direct instruction overrides ===
        (
            r"(?i)ignore\s+(all\s+)?(previous|above|prior|earlier)\s+(instructions?|prompts?|rules?|guidelines?)",
            "instruction_override",
            "Instruction override attempt",
            0.95,
            IssueSeverity.HIGH,
        ),
        (
            r"(?i)disregard\s+(all\s+)?(previous|above|prior|earlier)\s+(instructions?|prompts?|rules?)",
            "instruction_override", 
            "Instruction override attempt",
            0.95,
            IssueSeverity.HIGH,
        ),
        (
            r"(?i)forget\s+(everything|all|what)\s+(you('ve)?|was)\s+(told|instructed|learned)",
            "instruction_override",
            "Memory wipe attempt",
            0.90,
            IssueSeverity.HIGH,
        ),
        (
            r"(?i)override\s+(all\s+)?(previous\s+)?(instructions?|prompts?|rules?|constraints?)",
            "instruction_override",
            "Explicit override attempt",
            0.95,
            IssueSeverity.HIGH,
        ),
        (
            r"(?i)do\s+not\s+follow\s+(any\s+)?(previous|prior|earlier)\s+(instructions?|rules?)",
            "instruction_override",
            "Instruction rejection attempt",
            0.90,
            IssueSeverity.HIGH,
        ),
        
        # === HIGH: System prompt extraction ===
        (
            r"(?i)(show|reveal|display|print|output|tell)\s+(me\s+)?(your|the)\s+(system\s+)?prompt",
            "prompt_extraction",
            "System prompt extraction attempt",
            0.90,
            IssueSeverity.HIGH,
        ),
        (
            r"(?i)what\s+(are|were|is)\s+your\s+(original\s+|initial\s+|system\s+)?instructions",
            "prompt_extraction",
            "Instruction extraction attempt",
            0.85,
            IssueSeverity.HIGH,
        ),
        (
            r"(?i)output\s+(your\s+)?(entire\s+)?(system\s+)?prompt\s+(verbatim|exactly)",
            "prompt_extraction",
            "Verbatim prompt extraction",
            0.95,
            IssueSeverity.HIGH,
        ),
        (
            r"(?i)repeat\s+(everything|all)\s+(above|before)\s+this",
            "prompt_extraction",
            "Context extraction attempt",
            0.80,
            IssueSeverity.MEDIUM,
        ),
        
        # === CRITICAL: Jailbreaks ===
        (
            r"(?i)\bDAN\b.{0,50}(do\s+anything\s+now|jailbreak|no\s+restrictions)",
            "jailbreak",
            "DAN jailbreak attempt",
            0.98,
            IssueSeverity.CRITICAL,
        ),
        (
            r"(?i)you\s+are\s+(now\s+)?(DAN|evil|unfiltered|uncensored|jailbroken)",
            "jailbreak",
            "Persona hijack attempt",
            0.95,
            IssueSeverity.CRITICAL,
        ),
        (
            r"(?i)developer\s+mode\s+(enabled|activated|on|override)",
            "jailbreak",
            "Developer mode exploit",
            0.90,
            IssueSeverity.CRITICAL,
        ),
        (
            r"(?i)act\s+as\s+(if\s+)?(you\s+)?(have\s+)?no\s+(ethical|moral|safety)\s+(guidelines?|restrictions?|limits?)",
            "jailbreak",
            "Ethics bypass attempt",
            0.92,
            IssueSeverity.CRITICAL,
        ),
        (
            r"(?i)pretend\s+(you('re)?|to\s+be)\s+(an?\s+)?(evil|malicious|unethical|unrestricted)\s+(ai|assistant|bot)",
            "jailbreak",
            "Evil roleplay attempt",
            0.88,
            IssueSeverity.HIGH,
        ),
        (
            r"(?i)bypass\s+(all\s+)?(safety|content|ethical)\s+(filters?|restrictions?|guidelines?)",
            "jailbreak",
            "Safety bypass attempt",
            0.95,
            IssueSeverity.CRITICAL,
        ),
        (
            r"(?i)sudo\s+(mode|command|access|override)",
            "jailbreak",
            "Sudo mode attempt",
            0.85,
            IssueSeverity.HIGH,
        ),
        
        # === HIGH: Indirect injection (RAG/Agent) ===
        (
            r"(?i)\[(SYSTEM|ADMIN|INSTRUCTION|IMPORTANT)\]",
            "indirect_injection",
            "Fake system tag injection",
            0.90,
            IssueSeverity.HIGH,
        ),
        (
            r"(?i)<\|?(system|instruction|admin|prompt|im_start|im_end)\|?>",
            "indirect_injection",
            "Special token injection",
            0.92,
            IssueSeverity.HIGH,
        ),
        (
            r"(?i)###\s*(SYSTEM|INSTRUCTION|ADMIN|IMPORTANT)\s*(PROMPT)?:?",
            "indirect_injection",
            "Markdown header injection",
            0.88,
            IssueSeverity.HIGH,
        ),
        (
            r"(?i)(Human|User|Assistant|System):\s*(Human|User|Assistant|System):",
            "indirect_injection",
            "Conversation format injection",
            0.80,
            IssueSeverity.MEDIUM,
        ),
        (
            r"(?i)```\s*(system|instruction)\s*\n",
            "indirect_injection",
            "Code block injection",
            0.75,
            IssueSeverity.MEDIUM,
        ),
        
        # === MEDIUM: Obfuscation techniques ===
        (
            r"(?i)(base64|b64)[:\s]+[A-Za-z0-9+/=]{30,}",
            "obfuscation",
            "Base64 encoded payload",
            0.70,
            IssueSeverity.MEDIUM,
        ),
        (
            r"(\\u[0-9a-fA-F]{4}){6,}",
            "obfuscation",
            "Unicode escape obfuscation",
            0.75,
            IssueSeverity.MEDIUM,
        ),
        (
            r"[\u200b-\u200f\u2028-\u202f\u2060-\u206f]{4,}",
            "obfuscation",
            "Zero-width character injection",
            0.85,
            IssueSeverity.HIGH,
        ),
        (
            r"(?i)(hex|0x)[:\s]*([0-9a-f]{2}[\s,]*){15,}",
            "obfuscation",
            "Hex encoded payload",
            0.70,
            IssueSeverity.MEDIUM,
        ),
        
        # === MEDIUM: Role manipulation ===
        (
            r"(?i)from\s+now\s+on\s+(you\s+)?(will|are|must|should)",
            "role_manipulation",
            "Persistent behavior change attempt",
            0.70,
            IssueSeverity.MEDIUM,
        ),
        (
            r"(?i)your\s+new\s+(role|identity|purpose|objective)\s+(is|:)",
            "role_manipulation",
            "Role reassignment attempt",
            0.80,
            IssueSeverity.MEDIUM,
        ),
        (
            r"(?i)stop\s+being\s+(a|an)\s+(helpful|safe|ethical|responsible)\s+(assistant|ai)",
            "role_manipulation",
            "Role rejection attempt",
            0.85,
            IssueSeverity.HIGH,
        ),
        
        # === LOW: Suspicious patterns (context-dependent) ===
        (
            r"(?i)(hypothetically|theoretically|in\s+a\s+(story|novel|fiction)|for\s+(educational|research)\s+purposes)",
            "framing",
            "Hypothetical framing (potential bypass)",
            0.40,
            IssueSeverity.LOW,
        ),
        (
            r"(?i)as\s+a\s+(thought\s+)?experiment",
            "framing",
            "Thought experiment framing",
            0.35,
            IssueSeverity.LOW,
        ),
    ]
    
    # Keywords that boost confidence when found near patterns
    AMPLIFYING_KEYWORDS: ClassVar[list[str]] = [
        "injection", "jailbreak", "bypass", "exploit", "hack",
        "override", "ignore", "disregard", "secret", "hidden",
        "unlock", "unrestricted", "unfiltered", "uncensored",
    ]
    
    # Keywords that reduce confidence (legitimate context)
    DAMPENING_KEYWORDS: ClassVar[list[str]] = [
        "security", "research", "testing", "example", "demonstrate",
        "learn", "understand", "prevent", "protect", "detect",
        "paper", "article", "blog", "documentation",
    ]
    
    def __init__(
        self,
        use_ml: bool = False,
        hybrid_mode: bool = True,
        ml_threshold: float = 0.5,
        confidence_threshold: float = 0.6,
        check_obfuscation: bool = True,
        check_indirect: bool = True,
        model_name: str = "protectai/deberta-v3-base-prompt-injection-v2",
    ):
        """
        Initialize the ML-enhanced prompt injection scanner.
        
        Args:
            use_ml: Enable ML-based detection (requires transformers + torch)
            hybrid_mode: Use regex first, ML only for uncertain cases
            ml_threshold: Confidence threshold for ML model (0.0-1.0)
            confidence_threshold: Overall threshold for flagging issues
            check_obfuscation: Check for encoding/obfuscation
            check_indirect: Check for indirect injection markers
            model_name: HuggingFace model for ML detection
        """
        self.use_ml = use_ml
        self.hybrid_mode = hybrid_mode
        self.ml_threshold = ml_threshold
        self.confidence_threshold = confidence_threshold
        self.check_obfuscation = check_obfuscation
        self.check_indirect = check_indirect
        self.model_name = model_name
        
        # Compile regex patterns
        self._compiled_patterns: list[tuple[re.Pattern, str, str, float, IssueSeverity]] = []
        self._compile_patterns()
        
        # Lazy load ML model
        self._ml_model = None
        self._ml_tokenizer = None
        self._ml_available = False
        
        if use_ml:
            self._init_ml_model()
    
    def _compile_patterns(self) -> None:
        """Compile regex patterns for performance."""
        self._compiled_patterns = []
        
        for pattern, category, detail, confidence, severity in self.INJECTION_PATTERNS:
            # Skip obfuscation patterns if disabled
            if category == "obfuscation" and not self.check_obfuscation:
                continue
            # Skip indirect injection patterns if disabled
            if category == "indirect_injection" and not self.check_indirect:
                continue
            
            try:
                compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                self._compiled_patterns.append((compiled, category, detail, confidence, severity))
            except re.error:
                pass  # Skip invalid patterns
    
    def _init_ml_model(self) -> None:
        """Initialize the ML model (lazy loading)."""
        try:
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
            
            self._ml_tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self._ml_model = AutoModelForSequenceClassification.from_pretrained(self.model_name)
            self._ml_model.eval()
            self._ml_available = True
        except ImportError:
            self._ml_available = False
        except Exception:
            self._ml_available = False
    
    def _adjust_confidence(self, text: str, base_confidence: float) -> float:
        """
        Adjust confidence based on context keywords.
        
        Args:
            text: The full text being scanned
            base_confidence: Initial confidence from pattern match
            
        Returns:
            Adjusted confidence score
        """
        text_lower = text.lower()
        
        # Count amplifying keywords
        amp_count = sum(1 for kw in self.AMPLIFYING_KEYWORDS if kw in text_lower)
        
        # Count dampening keywords
        damp_count = sum(1 for kw in self.DAMPENING_KEYWORDS if kw in text_lower)
        
        # Adjust confidence
        adjustment = (amp_count * 0.05) - (damp_count * 0.08)
        adjusted = base_confidence + adjustment
        
        # Clamp to valid range
        return max(0.0, min(1.0, adjusted))
    
    def _regex_scan(self, text: str) -> list[DetectionResult]:
        """
        Scan using regex patterns.
        
        Args:
            text: Text to scan
            
        Returns:
            List of detection results
        """
        results: list[DetectionResult] = []
        
        for compiled, category, detail, base_confidence, severity in self._compiled_patterns:
            matches = list(compiled.finditer(text))
            
            for match in matches:
                # Adjust confidence based on context
                confidence = self._adjust_confidence(text, base_confidence)
                
                results.append(DetectionResult(
                    detected=True,
                    confidence=confidence,
                    method=DetectionMethod.REGEX,
                    category=category,
                    detail=detail,
                    evidence=match.group()[:100],
                ))
        
        return results
    
    def _ml_scan(self, text: str) -> DetectionResult | None:
        """
        Scan using ML model.
        
        Args:
            text: Text to scan
            
        Returns:
            Detection result or None if ML unavailable
        """
        if not self._ml_available or self._ml_model is None:
            return None
        
        try:
            import torch
            
            # Tokenize
            inputs = self._ml_tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=512,
            )
            
            # Inference
            with torch.no_grad():
                outputs = self._ml_model(**inputs)
                probs = torch.softmax(outputs.logits, dim=-1)
                
                # Assuming binary classification: [safe, injection]
                injection_prob = probs[0][1].item()
            
            return DetectionResult(
                detected=injection_prob >= self.ml_threshold,
                confidence=injection_prob,
                method=DetectionMethod.ML_MODEL,
                category="ml_detection",
                detail="ML model detected potential prompt injection",
                evidence=None,
            )
        except Exception:
            return None
    
    def _combine_results(
        self,
        regex_results: list[DetectionResult],
        ml_result: DetectionResult | None,
    ) -> list[DetectionResult]:
        """
        Combine regex and ML results using ensemble logic.
        
        Args:
            regex_results: Results from regex scanning
            ml_result: Result from ML model (if available)
            
        Returns:
            Combined detection results
        """
        combined: list[DetectionResult] = []
        
        # Process regex results
        for result in regex_results:
            if ml_result is not None:
                # Ensemble: average confidence if both agree, boost if both detect
                if ml_result.detected and result.detected:
                    # Both detect - high confidence
                    ensemble_confidence = (result.confidence + ml_result.confidence) / 2 + 0.1
                    ensemble_confidence = min(1.0, ensemble_confidence)
                elif ml_result.detected or result.detected:
                    # One detects - average
                    ensemble_confidence = (result.confidence + ml_result.confidence) / 2
                else:
                    # Neither detects strongly
                    ensemble_confidence = result.confidence * 0.8
                
                combined.append(DetectionResult(
                    detected=result.detected,
                    confidence=ensemble_confidence,
                    method=DetectionMethod.ENSEMBLE,
                    category=result.category,
                    detail=result.detail,
                    evidence=result.evidence,
                ))
            else:
                combined.append(result)
        
        # Add ML-only detection if no regex matches but ML detects
        if ml_result is not None and ml_result.detected and not regex_results:
            combined.append(ml_result)
        
        return combined
    
    def scan(self, text: str, direction: ScanDirection) -> list[Issue]:
        """
        Scan text for prompt injection attempts.
        
        Args:
            text: The text to scan
            direction: Input or output direction
            
        Returns:
            List of detected issues with confidence scores
        """
        if not text or not text.strip():
            return []
        
        issues: list[Issue] = []
        
        # Step 1: Fast regex scan
        regex_results = self._regex_scan(text)
        
        # Step 2: ML scan (if enabled)
        ml_result = None
        if self.use_ml and self._ml_available:
            if self.hybrid_mode:
                # Only use ML if regex is uncertain or no high-confidence matches
                max_regex_confidence = max(
                    (r.confidence for r in regex_results),
                    default=0.0
                )
                if max_regex_confidence < 0.85:
                    ml_result = self._ml_scan(text)
            else:
                # Always use ML
                ml_result = self._ml_scan(text)
        
        # Step 3: Combine results
        if self.use_ml and ml_result is not None:
            combined_results = self._combine_results(regex_results, ml_result)
        else:
            combined_results = regex_results
        
        # Step 4: Convert to Issues
        for result in combined_results:
            if result.confidence >= self.confidence_threshold:
                # Map confidence to severity
                if result.confidence >= 0.9:
                    severity = IssueSeverity.CRITICAL
                elif result.confidence >= 0.75:
                    severity = IssueSeverity.HIGH
                elif result.confidence >= 0.6:
                    severity = IssueSeverity.MEDIUM
                else:
                    severity = IssueSeverity.LOW
                
                # Determine issue type
                if result.category == "jailbreak":
                    issue_type = IssueType.JAILBREAK
                else:
                    issue_type = IssueType.PROMPT_INJECTION
                
                issues.append(Issue(
                    type=issue_type,
                    severity=severity,
                    detail=f"{result.detail} (confidence: {result.confidence:.0%})",
                    scanner=self.name,
                    metadata={
                        "confidence": result.confidence,
                        "method": result.method.value,
                        "category": result.category,
                        "evidence": result.evidence,
                    },
                ))
        
        # Deduplicate by category (keep highest confidence)
        seen_categories: dict[str, Issue] = {}
        for issue in issues:
            category = issue.metadata.get("category", "unknown")
            existing = seen_categories.get(category)
            if existing is None or issue.metadata["confidence"] > existing.metadata["confidence"]:
                seen_categories[category] = issue
        
        return list(seen_categories.values())
    
    def get_confidence(self, text: str) -> float:
        """
        Get overall injection confidence score for text.
        
        Args:
            text: Text to analyze
            
        Returns:
            Confidence score 0.0-1.0 (higher = more likely injection)
        """
        issues = self.scan(text, ScanDirection.INPUT)
        if not issues:
            return 0.0
        return max(i.metadata.get("confidence", 0.0) for i in issues)
    
    def is_safe(self, text: str, threshold: float | None = None) -> bool:
        """
        Quick check if text is likely safe.
        
        Args:
            text: Text to check
            threshold: Confidence threshold (default: self.confidence_threshold)
            
        Returns:
            True if text appears safe
        """
        threshold = threshold or self.confidence_threshold
        return self.get_confidence(text) < threshold
