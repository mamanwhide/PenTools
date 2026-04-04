"""
PenTools Module Engine
─────────────────────
BaseModule:      Abstract base class every attack module inherits.
ModuleRegistry:  Singleton that discovers and indexes all modules.
ParameterSchema: Field type definitions for dynamic form rendering.

Adding a new module:
  1. Create apps/<category>/modules.py
  2. Define class MyModule(BaseModule): ...
  3. The registry auto-discovers it at startup.
"""
from __future__ import annotations
import importlib
import pkgutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


# ─── Field Type Catalogue ────────────────────────────────────────────────

FIELD_TYPES = frozenset([
    "url",           # URL input with validation
    "text",          # Single-line text
    "textarea",      # Multi-line text
    "number",        # Numeric input (int/float)
    "select",        # Single-choice dropdown
    "radio",         # Single-choice radio group
    "checkbox_group",# Multi-choice checkboxes
    "toggle",        # Boolean on/off
    "json_editor",   # JSON textarea with validation
    "file_upload",   # File upload
    "wordlist_select", # Built-in wordlist picker + optional upload
    "auth_block",    # Compound auth widget (type + value fields)
    "range_slider",  # Min–max slider
    "code_editor",   # Syntax-highlighted code area
    "header_list",   # Dynamic key/value list for HTTP headers
])


@dataclass
class FieldSchema:
    """Definition of a single form field."""
    key: str
    label: str
    field_type: str
    required: bool = False
    default: Any = None
    placeholder: str = ""
    help_text: str = ""
    options: list[str | dict] = field(default_factory=list)   # for select/radio/checkbox_group
    min_value: float | None = None
    max_value: float | None = None
    step: float | None = None     # Step for range_slider/number
    sensitive: bool = False       # Mask in logs and DB (passwords, tokens)
    show_if: dict | None = None   # Conditional display: {"field_key": "value"}
    group: str = "basic"          # "basic" or "advanced" — collapsible group
    oast_callback: bool = False   # Renders interactsh/oast URL input hint

    def __post_init__(self):
        assert self.field_type in FIELD_TYPES, (
            f"Unknown field_type '{self.field_type}'. Valid: {FIELD_TYPES}"
        )


# ─── Base Module ─────────────────────────────────────────────────────────

class BaseModule(ABC):
    """
    Every attack module must inherit from this class and define:
      - id:               unique snake_case identifier
      - name:             human-readable display name
      - category:         category slug (matches CATEGORY_CHOICES below)
      - description:      short description for module card
      - risk_level:       "info" | "low" | "medium" | "high" | "critical"
      - tags:             list of string tags for search/filter
      - PARAMETER_SCHEMA: list of FieldSchema defining the dynamic form
      - execute():        the actual scan logic (called by Celery task)
    """

    # ── Override in each module ────────────────────────────────────────
    id: str = ""
    name: str = ""
    category: str = ""
    description: str = ""
    risk_level: str = "medium"
    tags: list[str] = []
    PARAMETER_SCHEMA: list[FieldSchema] = []
    # Time limit override in seconds (None = use Celery global default)
    time_limit: int | None = None
    # Which queue this module's task should be routed to
    celery_queue: str = "web_audit_queue"

    @property
    def category_label(self) -> str:
        """Human-readable category label for display."""
        return CATEGORY_LABEL.get(self.category, self.category.replace("_", " ").title())

    @abstractmethod
    def execute(self, params: dict, job_id: str, stream) -> dict:
        """
        Run the module with validated params.

        Args:
            params:  Deserialized, validated form parameters.
            job_id:  UUID of the ScanJob (for stream + result storage).
            stream:  Callable(level, message) — send real-time log line to WS.

        Returns:
            dict with keys:
              "status":   "success" | "failed" | "partial"
              "findings": list of finding dicts
              "raw":      raw tool output string (truncated if huge)
              "metadata": arbitrary extra info
        """
        ...

    def validate_params(self, params: dict) -> dict:
        """
        Validate and normalize params against PARAMETER_SCHEMA.
        Raises ValueError with details on first validation failure.
        Returns cleaned params dict.
        """
        # Field types that should never be None — normalise to "" when optional and unset.
        _TEXT_TYPES = {"text", "textarea", "url", "json_editor", "code_editor", "password", "hidden"}
        cleaned = {}
        for f in self.PARAMETER_SCHEMA:
            value = params.get(f.key, f.default)
            if f.required and (value is None or value == ""):
                raise ValueError(f"Field '{f.label}' is required.")
            # Prevent downstream AttributeError when modules call .strip() on optional fields
            if value is None and f.field_type in _TEXT_TYPES:
                value = f.default if f.default is not None else ""
            cleaned[f.key] = value
        return cleaned

    def schema_to_dict(self) -> dict:
        """Serialize module + PARAMETER_SCHEMA to JSON-serializable dict for API/template."""
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "risk_level": self.risk_level,
            "tags": self.tags,
            "parameters": [
                {
                    "name": f.key,
                    "label": f.label,
                    "type": f.field_type,
                    "required": f.required,
                    "default": f.default,
                    "placeholder": f.placeholder,
                    "help_text": f.help_text,
                    "options": f.options,
                    "min": f.min_value,
                    "max": f.max_value,
                    "step": f.step,
                    "sensitive": f.sensitive,
                    "show_if": f.show_if,
                    "group": f.group,
                }
                for f in self.PARAMETER_SCHEMA
            ],
        }

    def __repr__(self):
        return f"<Module {self.id}: {self.name}>"


# ─── Category Choices ────────────────────────────────────────────────────

CATEGORY_CHOICES = [
    ("static",         "Static Analysis & Utilities"),
    ("recon",          "Reconnaissance & OSINT"),
    ("injection",      "Injection Attacks"),
    ("xss",            "Cross-Site Scripting (XSS)"),
    ("server_side",    "Server-Side Vulnerabilities"),
    ("access_control", "Access Control & Authorization"),
    ("auth",           "Authentication Attacks"),
    ("client_side",    "Client-Side Attacks"),
    ("api",            "API Security"),
    ("business_logic", "Business Logic & Race Conditions"),
    ("http",           "HTTP-Level Attacks"),
    ("disclosure",     "Information Disclosure"),
    ("cloud",          "Cloud & Infrastructure"),
    ("vuln_scan",      "Vulnerability Scanning"),
]

CATEGORY_LABEL = dict(CATEGORY_CHOICES)


# ─── Module Registry ─────────────────────────────────────────────────────

class ModuleRegistry:
    """
    Singleton registry — discovers all BaseModule subclasses by importing
    every apps/*/modules.py file at startup.

    Usage:
        registry = ModuleRegistry.instance()
        all_modules = registry.all()
        xss_mods = registry.by_category("xss")
        mod = registry.get("dalfox_xss")
    """

    _instance: "ModuleRegistry | None" = None
    # MED-09: _modules must be an instance-level attribute, not class-level.
    # Class-level dicts are shared across all instances and persist across
    # _instance resets (e.g. in tests), causing ghost registrations.
    # Initialised in __init__ so each fresh instance starts with an empty registry.

    def __init__(self):
        self._modules: dict[str, "BaseModule"] = {}  # MED-09: instance-level

    @classmethod
    def instance(cls) -> "ModuleRegistry":
        if cls._instance is None:
            cls._instance = cls()
            cls._instance._discover()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset singleton — use in test tearDown to avoid ghost registrations."""
        cls._instance = None

    def _discover(self):
        """Auto-discover all modules.py files under apps/."""
        import apps
        for _, app_name, _ in pkgutil.iter_modules(apps.__path__):
            try:
                importlib.import_module(f"apps.{app_name}.modules")
            except ModuleNotFoundError:
                pass  # App has no modules.py — fine

        # Register all concrete subclasses of BaseModule
        for cls in BaseModule.__subclasses__():
            self._register(cls)
            # Also pick up subclasses of subclasses (multi-level inheritance)
            for sub in cls.__subclasses__():
                self._register(sub)

    def _register(self, module_cls: type):
        import inspect
        if inspect.isabstract(module_cls):
            return
        try:
            mod = module_cls()
        except TypeError:
            return  # Abstract or un-instantiable intermediate base
        if not mod.id:
            return
        self._modules[mod.id] = mod

    def all(self) -> list[BaseModule]:
        return sorted(self._modules.values(), key=lambda m: (m.category, m.name))

    def get(self, module_id: str) -> BaseModule | None:
        return self._modules.get(module_id)

    def by_category(self, category: str = None):
        """
        If category is given, return list of modules for that category.
        If no argument, return dict of {category: [modules]}.
        """
        if category is not None:
            return [m for m in self.all() if m.category == category]
        # Return dict grouped by category
        from collections import defaultdict
        groups: dict[str, list] = defaultdict(list)
        for m in self.all():
            groups[m.category].append(m)
        return dict(groups)

    def categories(self) -> list[dict]:
        """Return list of {slug, label, count} for sidebar rendering."""
        from collections import defaultdict
        counts = defaultdict(int)
        for m in self._modules.values():
            counts[m.category] += 1
        return [
            {"slug": slug, "label": label, "count": counts[slug]}
            for slug, label in CATEGORY_CHOICES
            if counts[slug] > 0
        ]

    def search(self, query: str) -> list[BaseModule]:
        q = query.lower()
        return [
            m for m in self.all()
            if q in m.name.lower()
            or q in m.description.lower()
            or any(q in t for t in m.tags)
        ]
