"""Evaluating the expressions that don't depend on the cloud: variables, locals, literals and what's built from them.

Read from the code alone, `cidr_blocks = [var.allowed]` or `count = var.enabled ? 1 : 0` can't be judged. Terraform
knows their values before it talks to any provider: a variable's value comes from `-var`, `-var-file`,
`*.auto.tfvars`, `terraform.tfvars` or its default; a module's from what its caller passes; a local's from its
expression. This evaluates that subset of HCL:

- literals: strings (with `${ }` templates), numbers, booleans, null, lists, objects;
- `var.x` and `local.x`, with `.attr` and `[index]` after them;
- `cond ? a : b`, `!`, `&&`, `||`, `==`, `!=`, `<`, `<=`, `>`, `>=`, `+`, `-`, `*`, and parentheses;
- the common functions: length, tolist, toset, tostring, tonumber, tobool, lower, upper, concat, contains,
  coalesce, compact, flatten, merge, keys, values, lookup, element, join, split, format (with %s / %d).

Anything else, a resource attribute above all (`aws_vpc.main.id`), is unknown, and an expression that uses it
stays as written: nothing is guessed.
"""

from __future__ import annotations

import re
from collections.abc import Callable

MAX_DEPTH = 40


class Unknown(Exception):
    """The expression depends on something only the cloud knows (or that isn't set)."""


_TOKEN = re.compile(
    r"""\s*(?:
      (?P<num>\d+(?:\.\d+)?)
    | (?P<str>")
    | (?P<op>==|!=|<=|>=|&&|\|\||[?:!<>()\[\],.{}=+*/%-])
    | (?P<name>[A-Za-z_][A-Za-z0-9_-]*)
    )""",
    re.VERBOSE,
)


def _string_end(s: str, i: int) -> int:
    """The index just past the closing quote of the string starting at s[i] == '"' (templates may nest quotes)."""
    j, depth = i + 1, 0
    while j < len(s):
        c = s[j]
        if c == "\\":
            j += 2
            continue
        if s.startswith("${", j) or s.startswith("%{", j):
            depth += 1
            j += 2
            continue
        if c == "}" and depth:
            depth -= 1
        elif c == '"' and not depth:
            return j + 1
        elif c == '"' and depth:  # a string inside a template: skip it whole
            j = _string_end(s, j)
            continue
        j += 1
    raise Unknown("unterminated string")


def _tokens(s: str) -> list[tuple[str, str]]:
    out, i = [], 0
    while i < len(s):
        if s[i:].strip() == "":
            break
        m = _TOKEN.match(s, i)
        if not m:
            raise Unknown(f"can't read {s[i : i + 20]!r}")
        if m.group("str"):
            start = m.start("str")
            end = _string_end(s, start)
            out.append(("str", s[start + 1 : end - 1]))
            i = end
            continue
        kind = next(k for k in ("num", "op", "name") if m.group(k) is not None)
        out.append((kind, m.group(kind)))
        i = m.end()
    return out


def _balanced(s: str, start: int) -> int:
    """For s[start:] beginning after `${`, the index of its closing brace."""
    depth, j = 0, start
    while j < len(s):
        if s[j] == '"':
            j = _string_end(s, j)
            continue
        if s[j] == "{":
            depth += 1
        elif s[j] == "}":
            if depth == 0:
                return j
            depth -= 1
        j += 1
    raise Unknown("unterminated template")


class Evaluator:
    """Evaluates expressions with `resolve(kind, name)` supplying var.x / local.x (raise Unknown when unset)."""

    def __init__(self, resolve: Callable[[str, str], object], read: Callable[[str], str] | None = None):
        self.resolve = resolve
        self.read = read  # file(path) → its text (raise Unknown when it can't be read); None: file() is unknown
        self.depth = 0

    # --- the parser's values

    def value(self, v):
        """A value as the parser gives it ('"text"', '${expr}', numbers, lists, objects) → a Python value."""
        if isinstance(v, str):
            if v.startswith("${") and _balanced(v, 2) == len(v) - 1:
                return self.expr(v[2:-1])
            if len(v) >= 2 and v[0] == v[-1] == '"':
                return self.template(v[1:-1])
            return self.template(v)
        if isinstance(v, list):
            return [self.value(x) for x in v]
        if isinstance(v, dict):
            return {_key(k): self.value(x) for k, x in v.items() if not str(k).startswith("__")}
        return v

    def template(self, s: str) -> str:
        out, i = [], 0
        while True:
            j = s.find("${", i)
            if j == -1:
                out.append(s[i:])
                break
            if j > 0 and s[j - 1] == "$":  # $${ is a literal ${
                out.append(s[i : j + 1])
                i = j + 2
                continue
            out.append(s[i:j])
            end = _balanced(s, j + 2)
            out.append(_tostring(self.expr(s[j + 2 : end])))
            i = end + 1
        if "%{" in s:
            raise Unknown("template directives")
        return "".join(out).replace("\\n", "\n").replace('\\"', '"')

    # --- expressions

    def expr(self, text: str):
        saved = (getattr(self, "toks", None), getattr(self, "pos", 0))  # nested evaluations (a var's value) reenter
        self.depth += 1
        try:
            if self.depth > MAX_DEPTH:
                raise Unknown("too deep")
            self.toks, self.pos = _tokens(text), 0
            v = self._ternary()
            if self.pos != len(self.toks):
                raise Unknown(f"unexpected {self.toks[self.pos][1]!r}")
            return v
        finally:
            self.depth -= 1
            self.toks, self.pos = saved

    def _peek(self, *ops: str) -> bool:
        return self.pos < len(self.toks) and self.toks[self.pos][0] == "op" and self.toks[self.pos][1] in ops

    def _take(self, op: str) -> None:
        if not self._peek(op):
            raise Unknown(f"expected {op}")
        self.pos += 1

    def _ternary(self):
        cond = self._or()
        if self._peek("?"):
            self.pos += 1
            a = self._ternary()
            self._take(":")
            b = self._ternary()
            if not isinstance(cond, bool):
                raise Unknown("a condition that isn't a boolean")
            return a if cond else b
        return cond

    def _or(self):
        v = self._and()
        while self._peek("||"):
            self.pos += 1
            v = _bool(v) | _bool(self._and())
        return v

    def _and(self):
        v = self._cmp()
        while self._peek("&&"):
            self.pos += 1
            v = _bool(v) & _bool(self._cmp())
        return v

    def _cmp(self):
        v = self._sum()
        if self._peek("==", "!=", "<", "<=", ">", ">="):
            op = self.toks[self.pos][1]
            self.pos += 1
            w = self._sum()
            if op == "==":
                return v == w
            if op == "!=":
                return v != w
            if not all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in (v, w)):
                raise Unknown("comparing what isn't a number")
            return {"<": v < w, "<=": v <= w, ">": v > w, ">=": v >= w}[op]
        return v

    def _sum(self):
        v = self._product()
        while self._peek("+", "-"):
            op = self.toks[self.pos][1]
            self.pos += 1
            w = self._product()
            v = _num(v) + _num(w) if op == "+" else _num(v) - _num(w)
        return v

    def _product(self):
        v = self._unary()
        while self._peek("*"):
            self.pos += 1
            v = _num(v) * _num(self._unary())
        return v

    def _unary(self):
        if self._peek("!"):
            self.pos += 1
            return not _bool(self._unary())
        if self._peek("-"):
            self.pos += 1
            return -_num(self._unary())
        return self._postfix(self._primary())

    def _postfix(self, v):
        while True:
            if self._peek("."):
                self.pos += 1
                name = self.toks[self.pos][1]
                self.pos += 1
                if not isinstance(v, dict) or name not in v:
                    raise Unknown(f"no attribute {name}")
                v = v[name]
            elif self._peek("["):
                self.pos += 1
                if self._peek("*"):
                    raise Unknown("splat")
                i = self._ternary()
                self._take("]")
                try:
                    v = v[int(i)] if isinstance(v, list) else v[i]
                except (KeyError, IndexError, TypeError, ValueError):
                    raise Unknown("index") from None
            else:
                return v

    def _primary(self):
        if self.pos >= len(self.toks):
            raise Unknown("end of expression")
        kind, tok = self.toks[self.pos]
        self.pos += 1
        if kind == "num":
            return float(tok) if "." in tok else int(tok)
        if kind == "str":
            return Evaluator(self.resolve, self.read).template(tok) if "${" in tok else tok.replace('\\"', '"')
        if kind == "op" and tok == "(":
            v = self._ternary()
            self._take(")")
            return v
        if kind == "op" and tok == "[":
            items = []
            while not self._peek("]"):
                if self.pos < len(self.toks) and self.toks[self.pos] == ("name", "for"):
                    raise Unknown("for expression")
                items.append(self._ternary())
                if self._peek(","):
                    self.pos += 1
            self._take("]")
            return items
        if kind == "op" and tok == "{":
            obj = {}
            while not self._peek("}"):
                k_kind, k = self.toks[self.pos]
                if k_kind not in ("name", "str"):
                    raise Unknown("object key")
                self.pos += 1
                if not (self._peek("=") or self._peek(":")):
                    raise Unknown("object")
                self.pos += 1
                obj[k] = self._ternary()
                if self._peek(","):
                    self.pos += 1
            self._take("}")
            return obj
        if kind == "name":
            if tok in ("true", "false"):
                return tok == "true"
            if tok == "null":
                return None
            if tok in ("var", "local", "path") and self._peek("."):
                self.pos += 1
                name = self.toks[self.pos][1]
                self.pos += 1
                return self.resolve(tok, name)
            if self._peek("("):
                return self._call(tok)
        raise Unknown(f"{tok} isn't known before apply")

    def _call(self, fn: str):
        self._take("(")
        args = []
        while not self._peek(")"):
            args.append(self._ternary())
            if self._peek(","):
                self.pos += 1
            elif self._peek("..."):
                raise Unknown("expansion")
        self._take(")")
        if fn in ("file", "templatefile") and args and isinstance(args[0], str):
            if self.read is None:
                raise Unknown(f"{fn}()")
            text = self.read(args[0])
            if fn == "templatefile":  # ${name} for the variables given; anything else stays an expression
                given = args[1] if len(args) > 1 and isinstance(args[1], dict) else {}
                text = re.sub(
                    r"\$\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}",
                    lambda m: _tostring(given[m.group(1)]) if m.group(1) in given else m.group(0),
                    text,
                )
            return text
        f = FUNCTIONS.get(fn)
        if f is None:
            raise Unknown(f"function {fn}")
        try:
            return f(*args)
        except Unknown:
            raise
        except Exception:  # noqa: BLE001 - a call Terraform would refuse (coalesce of nothing) is unknown, never fatal
            raise Unknown(f"{fn}()") from None


def _key(k) -> str:
    k = str(k)
    return k[1:-1] if len(k) >= 2 and k[0] == k[-1] == '"' else k


def _bool(v) -> bool:
    if not isinstance(v, bool):
        raise Unknown("not a boolean")
    return v


def _num(v):
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise Unknown("not a number")
    return v


def _tostring(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float, str)):
        return str(v)
    raise Unknown("not a string")


def _flatten(xs):
    out = []
    for x in xs:
        out += _flatten(x) if isinstance(x, list) else [x]
    return out


FUNCTIONS: dict[str, Callable] = {
    "length": len,
    "tolist": list,
    "toset": lambda xs: list(dict.fromkeys(xs)),
    "tostring": _tostring,
    "tonumber": lambda v: float(v) if "." in str(v) else int(v),
    "tobool": lambda v: v if isinstance(v, bool) else {"true": True, "false": False}[v],
    "lower": str.lower,
    "upper": str.upper,
    "concat": lambda *xs: [y for x in xs for y in x],
    "contains": lambda xs, v: v in xs,
    "coalesce": lambda *xs: next(x for x in xs if x not in (None, "")),
    "compact": lambda xs: [x for x in xs if x not in (None, "")],
    "flatten": _flatten,
    "merge": lambda *ds: {k: v for d in ds for k, v in d.items()},
    "keys": lambda d: sorted(d),
    "values": lambda d: [d[k] for k in sorted(d)],
    "lookup": lambda d, k, *default: d[k] if k in d or not default else default[0],
    "element": lambda xs, i: xs[int(i) % len(xs)],
    "join": lambda sep, xs: sep.join(_tostring(x) for x in xs),
    "split": lambda sep, s: s.split(sep),
    "format": lambda f, *a: re.sub(r"%[sd]", "{}", f).format(*a),
}


def to_parser(v):
    """A Python value → the parser's shape (strings quoted), so the rest reads it as if it had been written so."""
    if isinstance(v, str):
        return f'"{v}"'
    if isinstance(v, list):
        return [to_parser(x) for x in v]
    if isinstance(v, dict):
        return {k: to_parser(x) for k, x in v.items()}
    return v


_CONCAT = re.compile(r"^concat\s*\((.*)\)$", re.DOTALL)


def split_top(text: str, sep: str = ",") -> list[str]:
    """Split an expression on `sep` where it's not inside brackets, braces, parentheses or a string."""
    out, depth, start, i = [], 0, 0, 0
    while i < len(text):
        c = text[i]
        if c == '"':
            i = _string_end(text, i)
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == sep and depth == 0:
            out.append(text[start:i])
            start = i + 1
        i += 1
    tail = text[start:]
    return out + ([tail] if tail.strip() else [])


def partial(expr: str, whole: Callable[[str], object]) -> list:
    """When a list expression as a whole is unknown, what of it is known, in the parser's shape: the items of a list
    literal or a concat() that evaluate, and the others kept as `${…}`. `whole(text)` evaluates one piece (raising
    Unknown); raises Unknown when the expression isn't a list or concat()."""
    e = expr.strip()
    m = _CONCAT.match(e)
    if m:
        out: list = []
        for arg in split_top(m.group(1)):
            try:
                v = whole(arg)
            except Unknown:
                try:
                    out += partial(arg, whole)
                except Unknown:
                    out.append("${" + arg.strip() + "}")
                continue
            out += to_parser(v) if isinstance(v, list) else [to_parser(v)]
        return out
    if e.startswith("[") and e.endswith("]"):
        out = []
        for item in split_top(e[1:-1]):
            try:
                out.append(to_parser(whole(item)))
            except Unknown:
                t = item.strip()
                out.append(t if t.startswith('"') else "${" + t + "}")  # a template stays the string it is
        return out
    raise Unknown("not a list")
