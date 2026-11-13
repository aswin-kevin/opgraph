"""Techniques: offensive actions declared as typed Python functions.

    @technique(risk="intrusive", attack="T1046")
    def port_scan(ctx: Ctx, host: Host, ports: str = "top-100") -> TechniqueResult:
        '''Scan TCP ports on a host.'''

From the signature the library derives the JSON schema the LLM sees, which arguments are
scope-checked (those typed Target/Url/Host), and the risk the policy decides on.
"""

from __future__ import annotations

import inspect
import json
import re
import types
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from types import ModuleType
from typing import (
    TYPE_CHECKING,
    Annotated,
    Any,
    Literal,
    Union,
    get_args,
    get_origin,
    get_type_hints,
)

from .facts import Fact, FactStore
from .policy import Risk

if TYPE_CHECKING:
    from .engagement import Ctx


class Target(str):
    """A network target (host, host:port or URL). Scope-checked before the technique runs."""

    kind = "host, host:port or URL"


class Url(Target):
    """An http(s) URL. Scope-checked."""

    kind = "http(s) URL"


class Host(Target):
    """A hostname or IP address without scheme or path. Scope-checked."""

    kind = "hostname or IP"


class Network(Target):
    """A hostname, IP address or CIDR range (10.0.0.0/24). Ranges must lie entirely in scope."""

    kind = "hostname, IP or CIDR range"


class Secret:
    """Marks a parameter that may carry credential handles: ``body: Annotated[str, Secret] = ""``.

    The model only ever sees handles like ``{{cred:1}}``; the engagement swaps in the real secret
    when calling the technique, and only for parameters marked this way (never for targets).
    """


@dataclass
class TechniqueResult:
    observation: str = ""  # shown to the LLM once (sanitized and capped)
    facts: list[Fact] = field(default_factory=list)
    artifacts: list[Fact] = field(default_factory=list)  # created on the target; cleaned via undo


Needs = Callable[[FactStore], Iterable[Fact]]
Suggest = Callable[[Fact], "dict[str, Any] | Iterable[dict[str, Any]] | None"]
Undo = Callable[["Ctx", Fact], object]

_MARK = "__opgraph_technique__"


@dataclass
class Technique:
    name: str
    fn: Callable[..., Any]
    risk: Risk
    attack: str = ""  # MITRE ATT&CK technique id, e.g. "T1046"
    needs: Needs | None = None  # preconditions: returns facts this technique applies to
    undo: Undo | None = None  # cleans up one artifact the technique created
    timeout: int = 120
    tags: frozenset[str] = frozenset()
    doc: str = ""  # full docstring, shown to the model as the tool description
    custom_schema: dict[str, Any] | None = None  # overrides the schema derived from type hints
    suggest: Suggest | None = None  # turns a fact from `needs` into arguments worth trying

    def __post_init__(self) -> None:
        self._hints = get_type_hints(self.fn, include_extras=True)
        params = list(inspect.signature(self.fn).parameters.values())
        self.takes_ctx = bool(params) and params[0].name == "ctx"
        self.params = params[1:] if self.takes_ctx else params
        self._schema: dict[str, Any] | None = None
        self._secret_params = frozenset(p.name for p in self.params if _is_secret(self._hints.get(p.name)))
        bad = self._secret_params & {*self.target_params(), *self.target_list_params()}
        if bad:
            raise TypeError(f"{self.name}: target parameters cannot be Secret: {sorted(bad)}")
        for p in self.params:  # fail closed: a Target we would not scope-check is a definition error
            hint = self._hints.get(p.name)
            is_target = target_type(hint) is not None or _list_target_type(hint) is not None
            if is_target and p.default not in (inspect.Parameter.empty, None):
                raise TypeError(
                    f"{self.name}: target parameter {p.name!r} cannot have a default (defaults are "
                    "never scope-checked); use None"
                )
            if target_type(hint) is None and _list_target_type(hint) is None and _mentions_target(hint):
                raise TypeError(
                    f"{self.name}: parameter {p.name!r} nests a Target where it cannot be scope-checked; "
                    "use Target or list[Target]"
                )

    @property
    def description(self) -> str:
        """First paragraph of the docstring, on one line."""
        return self.doc.split("\n\n")[0].replace("\n", " ")

    def secret_params(self) -> frozenset[str]:
        """Names of parameters marked ``Annotated[..., Secret]``."""
        return self._secret_params

    def schema(self) -> dict[str, Any]:
        """JSON Schema for the LLM-visible parameters (or the schema given to @technique)."""
        if self.custom_schema is not None:
            return self.custom_schema
        if self._schema is None:
            props: dict[str, Any] = {}
            required: list[str] = []
            for p in self.params:
                prop = _json_type(self._hints.get(p.name, str))
                if p.default is not inspect.Parameter.empty:
                    if p.default is not None:
                        prop["default"] = p.default
                else:
                    required.append(p.name)
                props[p.name] = prop
            self._schema = {
                "type": "object",
                "properties": props,
                "required": required,
                "additionalProperties": False,
            }
        return self._schema

    def target_params(self) -> list[str]:
        """Names of parameters typed Target (or Url, Host, Network)."""
        return [p.name for p in self.params if target_type(self._hints.get(p.name)) is not None]

    def target_list_params(self) -> list[str]:
        """Names of parameters typed ``list[Target]`` (every element is scope-checked)."""
        return [p.name for p in self.params if _list_target_type(self._hints.get(p.name)) is not None]

    def accepts_ranges(self, name: str) -> bool:
        """Whether a target parameter is typed Network (or list[Network]) and so may be a CIDR range."""
        hint = self._hints.get(name)
        cls = target_type(hint) or _list_target_type(hint)
        return cls is not None and issubclass(cls, Network)

    def param_type(self, name: str) -> Any:
        return self._hints.get(name, str)

    def is_available(self, facts: FactStore) -> bool:
        return self.needs is None or any(True for _ in self.needs(facts))

    def suggestions(self, facts: FactStore) -> list[dict[str, Any]]:
        """Argument sets worth trying, derived from the facts this technique applies to."""
        if self.suggest is None:
            return []
        out: list[dict[str, Any]] = []
        seen: set[str] = set()
        for fact in self.needs(facts) if self.needs else facts:
            result = self.suggest(fact)
            candidates: list[Any] = [result] if isinstance(result, dict) else list(result or [])
            for args in candidates:
                key = json.dumps(args, sort_keys=True, default=str)
                if isinstance(args, dict) and key not in seen:
                    seen.add(key)
                    out.append(args)
        return out

    def bind(self, args: dict[str, Any]) -> dict[str, Any] | str:
        """Validate and coerce model-provided arguments. Returns the bound args or an error string."""
        names = {p.name for p in self.params}
        unknown = sorted(set(args) - names)
        if unknown:
            return f"unknown parameter(s) {unknown}; expected {sorted(names)}"
        out: dict[str, Any] = {}
        for p in self.params:
            if p.name not in args:
                if p.default is p.empty:
                    return f"missing required parameter {p.name!r}"
                continue
            try:
                out[p.name] = _coerce(self.param_type(p.name), args[p.name])
            except (TypeError, ValueError, OverflowError) as exc:
                return f"{p.name}: {exc}"
        return out


def technique(
    *,
    risk: Risk | str = Risk.SAFE,
    attack: str = "",
    needs: Needs | None = None,
    undo: Undo | None = None,
    name: str | None = None,
    timeout: int = 120,
    tags: Iterable[str] = (),
    schema: dict[str, Any] | None = None,
    suggest: Suggest | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Declare a function as a technique. The function itself is returned unchanged (still callable),
    with the Technique attached; register it on an Engagement to use it.

    `schema` replaces the JSON schema derived from type hints, for parameter shapes the derivation
    does not cover. Type hints still decide which arguments are scope-checked or receive secrets.

    `suggest` maps each fact returned by `needs` (or every fact, without `needs`) to arguments
    worth trying: a dict, several dicts, or None. The engagement
    uses it to list untried work, so coverage gaps are visible and saturation is a stop signal.
    """

    def wrap(fn: Callable[..., Any]) -> Callable[..., Any]:
        doc = inspect.getdoc(fn) or ""
        setattr(
            fn,
            _MARK,
            Technique(
                name=name or fn.__name__,
                fn=fn,
                risk=Risk(risk),
                attack=attack,
                needs=needs,
                undo=undo,
                timeout=timeout,
                tags=frozenset(tags),
                doc=doc,
                custom_schema=schema,
                suggest=suggest,
            ),
        )
        return fn

    return wrap


def collect(*items: Any) -> list[Technique]:
    """Gather techniques from decorated functions, Technique objects, modules or iterables of those."""
    found: list[Technique] = []
    for item in items:
        if isinstance(item, Technique):
            found.append(item)
        elif hasattr(item, _MARK):
            found.append(getattr(item, _MARK))
        elif isinstance(item, ModuleType):
            found.extend(getattr(v, _MARK) for v in vars(item).values() if hasattr(v, _MARK))
        elif isinstance(item, Iterable) and not isinstance(item, str | bytes):
            found.extend(collect(*item))
        else:
            raise TypeError(f"not a technique: {item!r}")
    return found


def _is_secret(annotation: Any) -> bool:
    return get_origin(annotation) is Annotated and Secret in get_args(annotation)[1:]


def _list_target_type(annotation: Any) -> type[Target] | None:
    tp = _strip(annotation)
    if get_origin(tp) is list and get_args(tp):
        return target_type(get_args(tp)[0])
    return None


def _mentions_target(annotation: Any) -> bool:
    if isinstance(annotation, type) and issubclass(annotation, Target):
        return True
    return any(_mentions_target(arg) for arg in get_args(annotation))


def target_type(annotation: Any) -> type[Target] | None:
    """The Target subclass an annotation refers to (unwrapping Optional/Annotated), or None."""
    annotation = _strip(annotation)
    if isinstance(annotation, type) and issubclass(annotation, Target):
        return annotation
    return None


# ---- schema helpers --------------------------------------------------------------------------------

_SIMPLE = {str: "string", int: "integer", float: "number", bool: "boolean"}


def _strip(annotation: Any) -> Any:
    """Unwrap Annotated[...] and Optional[...] to the underlying type."""
    if get_origin(annotation) is Annotated:
        annotation = get_args(annotation)[0]
    if get_origin(annotation) in (Union, types.UnionType):
        args = [a for a in get_args(annotation) if a is not type(None)]
        if len(args) == 1:
            return _strip(args[0])
    return annotation


def _json_type(annotation: Any) -> dict[str, Any]:
    description = ""
    if get_origin(annotation) is Annotated:
        extras = get_args(annotation)[1:]
        description = next((e for e in extras if isinstance(e, str)), "")
        if Secret in extras:
            description = (description + " " if description else "") + "(may contain {{cred:N}} handles)"
    tp = _strip(annotation)
    origin = get_origin(tp)

    if isinstance(tp, type) and issubclass(tp, Target):
        out: dict[str, Any] = {"type": "string"}
        description = description or f"{tp.kind} (scope-checked)"
    elif tp in _SIMPLE:
        out = {"type": _SIMPLE[tp]}
    elif origin is Literal:
        values = list(get_args(tp))
        out = {"type": _SIMPLE.get(type(values[0]), "string"), "enum": values}
    elif origin is list:
        (item,) = get_args(tp) or (str,)
        out = {"type": "array", "items": _json_type(item)}
    elif origin is dict:
        _, value = get_args(tp) or (str, str)
        out = {"type": "object", "additionalProperties": _json_type(value)}
    else:
        raise TypeError(f"unsupported parameter type for a technique: {annotation!r}")
    if description:
        out["description"] = description
    return out


# ---- argument coercion and results ------------------------------------------------------------


def as_result(raw: Any) -> TechniqueResult:
    """Normalise what a technique returned: TechniqueResult, list of facts, text, or None."""
    if isinstance(raw, TechniqueResult):
        return raw
    if raw is None:
        return TechniqueResult()
    if isinstance(raw, str):
        return TechniqueResult(observation=raw)
    if isinstance(raw, list) and all(isinstance(f, Fact) for f in raw):
        return TechniqueResult(facts=raw)
    raise TypeError(f"technique returned {type(raw).__name__}; expected TechniqueResult, list[Fact] or str")


def _coerce(annotation: Any, value: Any) -> Any:
    if value is None:
        return None
    tp = _strip(annotation)
    target_cls = target_type(tp)
    if target_cls is not None:
        return _make_target(target_cls, value)
    if get_origin(tp) is Literal:
        if value not in get_args(tp):
            raise ValueError(f"must be one of {list(get_args(tp))}")
        return value
    if tp is bool:
        if isinstance(value, str) and value.lower() in ("true", "false", "1", "0", "yes", "no"):
            return value.lower() in ("true", "1", "yes")
        if not isinstance(value, bool):
            raise TypeError("expected a boolean")
        return value
    if tp is int:
        if isinstance(value, bool):
            raise TypeError("expected an integer")
        return int(value)
    if tp is float:
        return float(value)
    if tp is str:
        if not isinstance(value, str | int | float):
            raise TypeError("expected a string")
        return str(value)
    if get_origin(tp) is list:
        if not isinstance(value, list):
            raise TypeError("expected a list")
        (item,) = get_args(tp) or (str,)
        return [_coerce(item, v) for v in value]
    if get_origin(tp) is dict:
        if not isinstance(value, dict):
            raise TypeError("expected an object")
        _, item = get_args(tp) or (str, str)
        return {str(k): _coerce(item, v) for k, v in value.items()}
    return value


def _make_target(cls: type, value: Any) -> Any:
    if not isinstance(value, str) or not value.strip():
        raise TypeError("expected a non-empty string target")
    value = value.strip()
    if issubclass(cls, Url) and not re.match(r"(?i)^https?://", value):
        raise ValueError("expected an http:// or https:// URL")
    if issubclass(cls, Host) and ("://" in value or "/" in value):
        raise ValueError("expected a hostname or IP, not a URL or range")
    if issubclass(cls, Network) and "://" in value:
        raise ValueError("expected a hostname, IP or CIDR range, not a URL")
    return cls(value)
