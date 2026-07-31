"""
Deterministic JSON canonicalization per RFC 8785 (JCS), matching
Rubric Verify Spec v1.0.0-rc1 section 6.1 and the TypeScript reference
implementation in @rubric-protocol/sdk (canonical.ts).

Dependency-free. Must remain byte-identical to the node implementation;
divergence causes silent commitment verification failure.
"""
import hashlib
import json
import math


class CanonicalInputError(ValueError):
    pass


def canonicalize(value):
    """Canonicalize a JSON-compatible value to its RFC 8785 form (str)."""
    return _serialize(value)


def canonicalize_bytes(value):
    return canonicalize(value).encode("utf-8")


def canonical_sha256_hex(value):
    return hashlib.sha256(canonicalize_bytes(value)).hexdigest()


def _serialize(value):
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _serialize_string(value)
    if isinstance(value, int):
        return _serialize_number(float(value))
    if isinstance(value, float):
        return _serialize_number(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_serialize(v) for v in value) + "]"
    if isinstance(value, dict):
        return _serialize_object(value)
    raise CanonicalInputError("unsupported value type: %s" % type(value).__name__)


def _serialize_object(obj):
    # RFC 8785 3.2.3: keys sorted by UTF-16 code unit order.
    keys = sorted(obj.keys(), key=_utf16_sort_key)
    parts = []
    for k in keys:
        if not isinstance(k, str):
            raise CanonicalInputError("object keys must be strings")
        v = obj[k]
        parts.append(_serialize_string(k) + ":" + _serialize(v))
    return "{" + ",".join(parts) + "}"


def _utf16_sort_key(s):
    # Compare by UTF-16 code units, matching JS String comparison.
    return s.encode("utf-16-be")


def _serialize_number(n):
    if math.isnan(n) or math.isinf(n):
        raise CanonicalInputError("NaN and Infinity are not representable")
    if n == 0:
        return "0"
    # Shortest round-tripping representation, ECMAScript Number::toString form.
    if n == int(n) and abs(n) < 1e21:
        return str(int(n))
    r = repr(n)
    if "e" in r or "E" in r:
        r = _js_exponential(n)
    return r


def _js_exponential(n):
    s = repr(n)
    mant, _, exp = s.partition("e")
    if not exp:
        return s
    exp_i = int(exp)
    mant = mant.rstrip("0").rstrip(".") if "." in mant else mant
    sign = "+" if exp_i >= 0 else "-"
    return "%se%s%d" % (mant, sign, abs(exp_i))


def _serialize_string(s):
    # RFC 8785 3.2.2.2: JSON string escaping, minimal escapes, non-ASCII literal.
    return json.dumps(s, ensure_ascii=False, separators=(",", ":"))
