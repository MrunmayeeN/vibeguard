"""
Toxicity Detection Scanner.

Detects harmful, offensive, or inappropriate content including:
- Hate speech and discrimination
- Harassment and bullying
- Violence and threats
- Sexual content
- Self-harm content
- Profanity and obscenity

Supports multiple detection methods:
1. Keyword/pattern-based (fast, no external dependencies)
2. Local ML model (more accurate, requires torch)
3. External API (most accurate, requires API key)
"""

import re
from enum import Enum
from typing import Any, ClassVar

from vibeguard.models import Issue, IssueSeverity, IssueType, ScanDirection
from vibeguard.scanners import Scanner


class ToxicityCategory(str, Enum):
    """Categories of toxic content."""
    
    HATE_SPEECH = "hate_speech"
    HARASSMENT = "harassment"
    VIOLENCE = "violence"
    SEXUAL = "sexual"
    SELF_HARM = "self_harm"
    PROFANITY = "profanity"
    DISCRIMINATION = "discrimination"
    THREAT = "threat"
    INSULT = "insult"


class ToxicityScanner(Scanner):
    """
    Detects toxic and harmful content.
    
    Uses a combination of pattern matching and optional ML models
    to identify various categories of harmful content.
    
    Usage:
        scanner = ToxicityScanner()
        result = guard.check_input("some potentially harmful text")
        
    With ML model (requires torch):
        scanner = ToxicityScanner(use_ml_model=True)
    """
    
    name: str = "toxicity"
    
    # Hate speech patterns (racial, religious, gender, etc.)
    # Note: These are intentionally broad patterns, not specific slurs
    HATE_PATTERNS: ClassVar[list[tuple[str, str, IssueSeverity]]] = [
        (
            r"(?i)\b(kill|murder|eliminate|exterminate)\s+(all\s+)?(the\s+)?"
            r"(jews?|muslims?|christians?|blacks?|whites?|asians?|mexicans?|immigrants?|gays?|trans)",
            "Genocidal hate speech",
            IssueSeverity.CRITICAL,
        ),
        (
            r"(?i)\b(all\s+)?(jews?|muslims?|blacks?|whites?|women|men|gays?)\s+"
            r"(should|must|need\s+to)\s+(die|be\s+killed|suffer)",
            "Group-targeted violence",
            IssueSeverity.CRITICAL,
        ),
        (
            r"(?i)\b(subhuman|inferior|vermin|cockroach|animal)s?\b.*"
            r"(jews?|muslims?|blacks?|immigrants?|mexicans?)",
            "Dehumanizing language",
            IssueSeverity.HIGH,
        ),
        (
            r"(?i)(white|black|asian)\s+(supremacy|power|pride)\s+(forever|now)",
            "Supremacist ideology",
            IssueSeverity.HIGH,
        ),
    ]
    
    # Harassment patterns
    HARASSMENT_PATTERNS: ClassVar[list[tuple[str, str, IssueSeverity]]] = [
        (
            r"(?i)\bi('ll|'m\s+going\s+to|will)\s+(find|hunt|track)\s+(you|where\s+you)",
            "Stalking threat",
            IssueSeverity.CRITICAL,
        ),
        (
            r"(?i)(kill\s+yourself|kys|go\s+die|hope\s+you\s+die)",
            "Death wish/encouragement",
            IssueSeverity.CRITICAL,
        ),
        (
            r"(?i)(you('re)?\s+)?(worthless|pathetic|disgusting|waste\s+of\s+space)",
            "Personal attack/degradation",
            IssueSeverity.MEDIUM,
        ),
        (
            r"(?i)(i('ll)?\s+)?(ruin|destroy)\s+(your\s+)?(life|career|reputation)",
            "Life destruction threat",
            IssueSeverity.HIGH,
        ),
        (
            r"(?i)(dox|doxx|expose|leak)\s+(your|their)\s+(address|info|personal)",
            "Doxxing threat",
            IssueSeverity.CRITICAL,
        ),
    ]
    
    # Violence patterns
    VIOLENCE_PATTERNS: ClassVar[list[tuple[str, str, IssueSeverity]]] = [
        (
            r"(?i)how\s+to\s+(make|build|create)\s+(a\s+)?(bomb|explosive|weapon)",
            "Weapon creation inquiry",
            IssueSeverity.CRITICAL,
        ),
        (
            r"(?i)(i('ll|'m\s+going\s+to)|gonna)\s+(shoot|stab|kill|attack|hurt)\s+(you|them|people)",
            "Direct violence threat",
            IssueSeverity.CRITICAL,
        ),
        (
            r"(?i)(mass\s+)?(shooting|attack|murder)\s+(plan|idea|target)",
            "Mass violence planning",
            IssueSeverity.CRITICAL,
        ),
        (
            r"(?i)(torture|mutilate|dismember)\s+(you|them|people|someone)",
            "Torture/mutilation threat",
            IssueSeverity.CRITICAL,
        ),
    ]
    
    # Self-harm patterns
    SELF_HARM_PATTERNS: ClassVar[list[tuple[str, str, IssueSeverity]]] = [
        (
            r"(?i)how\s+to\s+(commit\s+)?suicide",
            "Suicide method inquiry",
            IssueSeverity.CRITICAL,
        ),
        (
            r"(?i)(best|easiest|painless)\s+(way|method)\s+to\s+(die|kill\s+myself|end\s+it)",
            "Suicide method seeking",
            IssueSeverity.CRITICAL,
        ),
        (
            r"(?i)(cutting|self.?harm|hurting\s+myself)\s+(tips|advice|how)",
            "Self-harm guidance seeking",
            IssueSeverity.CRITICAL,
        ),
        (
            r"(?i)(i\s+want\s+to|going\s+to)\s+(die|kill\s+myself|end\s+it\s+all)",
            "Suicidal ideation expression",
            IssueSeverity.CRITICAL,
        ),
    ]
    
    # Sexual content patterns (explicit)
    SEXUAL_PATTERNS: ClassVar[list[tuple[str, str, IssueSeverity]]] = [
        (
            r"(?i)(child|minor|underage|kid).{0,20}(sex|porn|nude|naked)",
            "Child sexual abuse material reference",
            IssueSeverity.CRITICAL,
        ),
        (
            r"(?i)(rape|molest|assault)\s+(a\s+)?(child|minor|kid|girl|boy|woman|man)",
            "Sexual assault content",
            IssueSeverity.CRITICAL,
        ),
        # Note: Adult sexual content is not necessarily blocked, just flagged
        (
            r"(?i)(explicit|graphic)\s+(sex|porn|sexual)",
            "Explicit sexual content",
            IssueSeverity.MEDIUM,
        ),
    ]
    
    # Profanity patterns (common profanity - severity depends on context)
    PROFANITY_PATTERNS: ClassVar[list[tuple[str, str, IssueSeverity]]] = [
        (
            r"(?i)\b(fuck|fucking|fucked|fucker)\b",
            "Strong profanity (f-word)",
            IssueSeverity.LOW,
        ),
        (
            r"(?i)\b(shit|shitting|bullshit)\b",
            "Profanity (s-word)",
            IssueSeverity.LOW,
        ),
        (
            r"(?i)\b(bitch|bastard|asshole|ass)\b",
            "Moderate profanity",
            IssueSeverity.LOW,
        ),
    ]
    
    def __init__(
        self,
        check_hate: bool = True,
        check_harassment: bool = True,
        check_violence: bool = True,
        check_self_harm: bool = True,
        check_sexual: bool = True,
        check_profanity: bool = False,  # Off by default
        min_severity: IssueSeverity = IssueSeverity.MEDIUM,
        use_ml_model: bool = False,
        ml_model_name: str = "unitary/toxic-bert",
        api_endpoint: str | None = None,
        api_key: str | None = None,
    ):
        """
        Initialize the toxicity scanner.
        
        Args:
            check_hate: Check for hate speech
            check_harassment: Check for harassment
            check_violence: Check for violence
            check_self_harm: Check for self-harm content
            check_sexual: Check for sexual content
            check_profanity: Check for profanity (off by default)
            min_severity: Minimum severity to report
            use_ml_model: Use ML model for detection (requires torch)
            ml_model_name: HuggingFace model name for toxicity
            api_endpoint: External API endpoint for detection
            api_key: API key for external service
        """
        self.check_hate = check_hate
        self.check_harassment = check_harassment
        self.check_violence = check_violence
        self.check_self_harm = check_self_harm
        self.check_sexual = check_sexual
        self.check_profanity = check_profanity
        self.min_severity = min_severity
        self.use_ml_model = use_ml_model
        self.ml_model_name = ml_model_name
        self.api_endpoint = api_endpoint
        self.api_key = api_key
        
        # Compile patterns
        self._compiled_patterns: list[tuple[re.Pattern, str, IssueSeverity, ToxicityCategory]] = []
        self._compile_patterns()
        
        # Load ML model if requested
        self._ml_model = None
        self._ml_tokenizer = None
        if use_ml_model:
            self._load_ml_model()
    
    def _compile_patterns(self) -> None:
        """Compile regex patterns based on settings."""
        self._compiled_patterns = []
        
        if self.check_hate:
            for pattern, detail, severity in self.HATE_PATTERNS:
                self._compiled_patterns.append((
                    re.compile(pattern),
                    detail,
                    severity,
                    ToxicityCategory.HATE_SPEECH,
                ))
        
        if self.check_harassment:
            for pattern, detail, severity in self.HARASSMENT_PATTERNS:
                self._compiled_patterns.append((
                    re.compile(pattern),
                    detail,
                    severity,
                    ToxicityCategory.HARASSMENT,
                ))
        
        if self.check_violence:
            for pattern, detail, severity in self.VIOLENCE_PATTERNS:
                self._compiled_patterns.append((
                    re.compile(pattern),
                    detail,
                    severity,
                    ToxicityCategory.VIOLENCE,
                ))
        
        if self.check_self_harm:
            for pattern, detail, severity in self.SELF_HARM_PATTERNS:
                self._compiled_patterns.append((
                    re.compile(pattern),
                    detail,
                    severity,
                    ToxicityCategory.SELF_HARM,
                ))
        
        if self.check_sexual:
            for pattern, detail, severity in self.SEXUAL_PATTERNS:
                self._compiled_patterns.append((
                    re.compile(pattern),
                    detail,
                    severity,
                    ToxicityCategory.SEXUAL,
                ))
        
        if self.check_profanity:
            for pattern, detail, severity in self.PROFANITY_PATTERNS:
                self._compiled_patterns.append((
                    re.compile(pattern),
                    detail,
                    severity,
                    ToxicityCategory.PROFANITY,
                ))
    
    def _load_ml_model(self) -> None:
        """Load the ML model for toxicity detection."""
        try:
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
            import torch
            
            self._ml_tokenizer = AutoTokenizer.from_pretrained(self.ml_model_name)
            self._ml_model = AutoModelForSequenceClassification.from_pretrained(
                self.ml_model_name
            )
            self._ml_model.eval()
        except ImportError:
            import logging
            logging.warning(
                "ML model requested but transformers/torch not installed. "
                "Install with: pip install transformers torch"
            )
            self.use_ml_model = False
    
    def scan(self, text: str, direction: ScanDirection) -> list[Issue]:
        """
        Scan text for toxic content.
        
        Args:
            text: The text to scan
            direction: Input or output direction
            
        Returns:
            List of detected toxicity issues
        """
        issues: list[Issue] = []
        severity_order = [
            IssueSeverity.LOW,
            IssueSeverity.MEDIUM,
            IssueSeverity.HIGH,
            IssueSeverity.CRITICAL,
        ]
        min_idx = severity_order.index(self.min_severity)
        
        # Pattern-based detection
        for compiled_pattern, detail, severity, category in self._compiled_patterns:
            # Skip if below minimum severity
            if severity_order.index(severity) < min_idx:
                continue
            
            matches = list(compiled_pattern.finditer(text))
            for match in matches:
                issues.append(Issue(
                    type=IssueType.TOXIC_CONTENT,
                    severity=severity,
                    detail=f"[{category.value}] {detail}",
                    span=(match.start(), match.end()),
                    scanner=self.name,
                    metadata={
                        "category": category.value,
                        "detection_method": "pattern",
                    },
                ))
        
        # ML model detection (if enabled and available)
        if self.use_ml_model and self._ml_model is not None:
            ml_issues = self._scan_with_ml(text)
            issues.extend(ml_issues)
        
        # External API detection (if configured)
        if self.api_endpoint and self.api_key:
            api_issues = self._scan_with_api(text)
            issues.extend(api_issues)
        
        return issues
    
    def _scan_with_ml(self, text: str) -> list[Issue]:
        """Scan using ML model."""
        issues = []
        
        try:
            import torch
            
            inputs = self._ml_tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=512,
            )
            
            with torch.no_grad():
                outputs = self._ml_model(**inputs)
                probabilities = torch.softmax(outputs.logits, dim=-1)
            
            # Model-specific label handling
            # Most toxicity models have a "toxic" class
            toxic_prob = probabilities[0][1].item()  # Assuming binary classification
            
            if toxic_prob > 0.8:
                severity = IssueSeverity.HIGH
            elif toxic_prob > 0.5:
                severity = IssueSeverity.MEDIUM
            else:
                return issues  # Below threshold
            
            issues.append(Issue(
                type=IssueType.TOXIC_CONTENT,
                severity=severity,
                detail=f"ML model detected toxicity (confidence: {toxic_prob:.2%})",
                scanner=self.name,
                metadata={
                    "detection_method": "ml_model",
                    "model": self.ml_model_name,
                    "confidence": toxic_prob,
                },
            ))
            
        except Exception as e:
            import logging
            logging.warning(f"ML toxicity detection failed: {e}")
        
        return issues
    
    def _scan_with_api(self, text: str) -> list[Issue]:
        """Scan using external API."""
        issues = []
        
        try:
            import urllib.request
            import json
            
            data = json.dumps({"text": text}).encode("utf-8")
            req = urllib.request.Request(
                self.api_endpoint,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.api_key}",
                },
                method="POST",
            )
            
            with urllib.request.urlopen(req, timeout=5) as response:
                result = json.loads(response.read().decode("utf-8"))
            
            # Handle API response (format depends on service)
            if result.get("toxic", False) or result.get("flagged", False):
                severity = IssueSeverity.HIGH if result.get("severe", False) else IssueSeverity.MEDIUM
                issues.append(Issue(
                    type=IssueType.TOXIC_CONTENT,
                    severity=severity,
                    detail=f"API detected toxicity: {result.get('reason', 'unspecified')}",
                    scanner=self.name,
                    metadata={
                        "detection_method": "api",
                        "api_response": result,
                    },
                ))
                
        except Exception as e:
            import logging
            logging.warning(f"API toxicity detection failed: {e}")
        
        return issues
    
    def get_categories(self) -> list[ToxicityCategory]:
        """Get the list of enabled toxicity categories."""
        categories = []
        if self.check_hate:
            categories.append(ToxicityCategory.HATE_SPEECH)
        if self.check_harassment:
            categories.append(ToxicityCategory.HARASSMENT)
        if self.check_violence:
            categories.append(ToxicityCategory.VIOLENCE)
        if self.check_self_harm:
            categories.append(ToxicityCategory.SELF_HARM)
        if self.check_sexual:
            categories.append(ToxicityCategory.SEXUAL)
        if self.check_profanity:
            categories.append(ToxicityCategory.PROFANITY)
        return categories
