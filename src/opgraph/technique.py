"""Techniques: offensive actions declared as typed Python functions.

    @technique(risk="intrusive", attack="T1046")
    def port_scan(ctx: Ctx, host: Host, ports: str = "top-100") -> TechniqueResult:
        '''Scan TCP ports on a host.'''

From the signature the library derives the JSON schema the LLM sees, which arguments are
scope-checked (those typed Target/Url/Host), and the risk the policy decides on.
"""

from __future__ import annotations

import inspect
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

    def __post_init__(self) -> None:
        self._hints = get_type_hints(self.fn, include_extras=True)
        params = list(inspect.signature(self.fn).parameters.values())
        self.takes_ctx = bool(params) and params[0].name == "ctx"
        self.params = params[1:] if self.takes_ctx else params
        self._schema: dict[str, Any] | None = None
        self._secret_params = frozenset(p.name for p in self.params if _is_secret(self._hints.get(p.name)))
        bad = self._secret_params & set(self.target_params())
        if bad:
            raise TypeError(f"{self.name}: target parameters cannot be Secret: {sorted(bad)}")

    @property
    def description(self) -> str:
        """First paragraph of the docstring, on one line."""
        return self.doc.split("\n\n")[0].replace("\n", " ")

    def secret_params(self) -> frozenset[str]:
        """Names of parameters marked ``Annotated[..., Secret]``."""
        return self._secret_params

    def schema(self) -> dict[str, Any]:
        """JSON Schema for the LLM-visible parameters."""
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
        """Names of parameters typed Target, Url or Host."""
        return [p.name for p in self.params if target_type(self._hints.get(p.name)) is not None]

    def param_type(self, name: str) -> Any:
        return self._hints.get(name, str)

    def is_available(self, facts: FactStore) -> bool:
        return self.needs is None or any(True for _ in self.needs(facts))


def technique(
    *,
    risk: Risk | str = Risk.SAFE,
    attack: str = "",
    needs: Needs | None = None,
    undo: Undo | None = None,
    name: str | None = None,
    timeout: int = 120,
    tags: Iterable[str] = (),
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Declare a function as a technique. The function itself is returned unchanged (still callable),
    with the Technique attached; register it on an Engagement to use it."""

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
