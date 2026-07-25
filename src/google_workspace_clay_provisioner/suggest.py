"""Generate candidate ``.com`` domain names related to a seed domain.

Pure string work — no network. Availability is decided separately by the
Cloudflare Registrar check, which is the only authoritative source.

The generated names are deliberately boring: a small set of prefixes and
suffixes applied to the seed's root label. Random or misspelled lookalikes are
not produced, because a sending domain a recipient cannot recognise as related
to the business hurts both reply rates and domain reputation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

TLD = "com"

# Applied as "<prefix><root>.com" — words that read as a company's own domain.
DEFAULT_PREFIXES: tuple[str, ...] = (
    "get",
    "try",
    "go",
    "hey",
    "join",
    "meet",
    "team",
    "with",
    "use",
    "the",
)

# Applied as "<root><suffix>.com".
DEFAULT_SUFFIXES: tuple[str, ...] = (
    "hq",
    "group",
    "team",
    "mail",
    "inbox",
    "direct",
    "online",
    "digital",
    "co",
    "now",
)

_LABEL_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_STRIP_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://")


@dataclass(frozen=True)
class Candidate:
    """A generated domain plus the rule that produced it, for explainability."""

    domain: str
    pattern: str


def root_label(seed: str) -> str:
    """Reduce a seed such as ``https://www.acme.com/x`` to ``acme``.

    Accepts a bare label, a hostname, or a URL. Raises ``ValueError`` when
    nothing usable is left, so the caller can prompt again rather than
    generating nonsense from an empty string.
    """
    text = seed.strip().lower()
    text = _STRIP_SCHEME.sub("", text)
    text = text.split("/", 1)[0].split("@")[-1].split(":", 1)[0]
    text = text.removeprefix("www.")

    labels = [part for part in text.split(".") if part]
    if not labels:
        raise ValueError(f"no usable domain label in seed: {seed!r}")

    # Drop the public suffix when present. Two-label suffixes such as
    # "com.au" are handled by dropping both when a third label exists.
    if len(labels) >= 3 and labels[-2] in {"com", "co", "net", "org", "gov", "edu"}:
        candidate = labels[-3]
    elif len(labels) >= 2:
        candidate = labels[-2]
    else:
        candidate = labels[0]

    if not is_valid_label(candidate):
        raise ValueError(f"seed root label is not a valid DNS label: {candidate!r}")
    return candidate


def is_valid_label(label: str) -> bool:
    """True when ``label`` is a legal DNS label: 1-63 chars, no edge hyphen."""
    return bool(label) and len(label) <= 63 and _LABEL_PATTERN.match(label) is not None


def generate_candidates(
    seed: str,
    *,
    prefixes: tuple[str, ...] = DEFAULT_PREFIXES,
    suffixes: tuple[str, ...] = DEFAULT_SUFFIXES,
    allow_hyphen: bool = False,
    limit: int = 20,
) -> list[Candidate]:
    """Build up to ``limit`` candidate ``.com`` domains from ``seed``.

    Deterministic: the same seed and options always produce the same list in
    the same order (shortest first, then by rule), so a run is reproducible.
    Hyphenated forms are opt-in — they are widely read as throwaway domains.
    The seed's own ``.com`` is never returned.
    """
    if limit < 1:
        return []

    root = root_label(seed)
    generated: list[Candidate] = []

    for prefix in prefixes:
        generated.append(Candidate(f"{prefix}{root}.{TLD}", f"prefix:{prefix}"))
    for suffix in suffixes:
        generated.append(Candidate(f"{root}{suffix}.{TLD}", f"suffix:{suffix}"))
    if allow_hyphen:
        for suffix in suffixes:
            generated.append(Candidate(f"{root}-{suffix}.{TLD}", f"hyphen-suffix:{suffix}"))

    excluded = f"{root}.{TLD}"
    seen: set[str] = set()
    valid: list[Candidate] = []
    for candidate in generated:
        label = candidate.domain.removesuffix(f".{TLD}")
        if candidate.domain == excluded or candidate.domain in seen:
            continue
        if not is_valid_label(label):
            continue
        seen.add(candidate.domain)
        valid.append(candidate)

    valid.sort(key=lambda item: (len(item.domain), item.domain))
    return valid[:limit]
