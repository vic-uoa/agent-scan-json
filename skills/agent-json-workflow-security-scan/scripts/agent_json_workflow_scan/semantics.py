"""Local, non-executing semantic checks. No imports of scanned code or network I/O.

These summaries are conservative call-site evidence, not whole-program proofs.
Unknown dispatch remains a coverage gap; a schema or function name is no sanitizer.
"""
from __future__ import annotations

import ast
from collections import deque
from dataclasses import dataclass, field
import re
from typing import Any, Iterable


def field_matches(value: str, words: Iterable[str]) -> bool:
    expanded = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    components = re.findall(r"[a-z0-9]+|[\u4e00-\u9fff]+", expanded.lower())
    components.extend(re.sub(r"[^a-z0-9]", "", part.lower()) for part in re.split(r"[./\[\]]", value))
    compact = {normalized for word in words if (normalized := re.sub(r"[^a-z0-9]", "", word.lower()))}
    # Explicit platform spellings; do not match 'host' in 'ghost' or 'cmd' in 'cmdlet'.
    aliases = {"callbackurl": "url", "imageurl": "url", "baseurl": "url",
               "redirecturi": "uri", "hostname": "host"}
    return any(part in compact or aliases.get(part) in compact for part in components) or any(
        word in value for word in words if re.search(r"[\u4e00-\u9fff]", word)
    ) or re.sub(r"[^a-z0-9]", "", value.lower()) in compact


_PROVIDER_SECRET = re.compile(
    r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|"
    r"\bgithub_pat_[A-Za-z0-9_]{22,}\b|\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}|"
    r"-----BEGIN(?: RSA| EC| OPENSSH| ENCRYPTED)? PRIVATE KEY-----"
)
_ASSIGNMENT_SECRET = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|passwd|authorization)"
    r"[\"']?\s*[:=]\s*[\"']?(?:bearer\s+)?(?P<secret>[A-Za-z0-9_~./+=-]{8,})"
    r"|\bbearer\s+(?P<bearer>[A-Za-z0-9_~./+=-]{12,})"
)
_PLACEHOLDER = re.compile(
    r"(?i)(?:example|placeholder|dummy|changeme|redacted|your[_-]?(?:api[_-]?)?(?:key|token|secret)|"
    r"<[^>]+>|\*{3,}|x{3,}|\$\{[^}]+\}|\{\{.*\}\})"
)
_SECRET_KEYS = {"apikey", "accesstoken", "clientsecret", "password", "passwd", "authorization", "secret", "token"}


def contains_secret(value: str, key: str = "") -> bool:
    # Exempt only the candidate itself, never its surrounding line/document.
    if _PROVIDER_SECRET.search(value):
        return True
    candidates = [match.group("secret") or match.group("bearer") for match in _ASSIGNMENT_SECRET.finditer(value)]
    if re.sub(r"[^a-z0-9]", "", re.split(r"[./]", key.lower())[-1]) in _SECRET_KEYS:
        candidates.append(re.sub(r"(?i)^bearer\s+", "", value.strip()))
    return any(len(candidate) >= 8 and not _PLACEHOLDER.fullmatch(candidate)
               and bool(re.fullmatch(r"[A-Za-z0-9_~./+=-]+", candidate)) for candidate in candidates)


@dataclass
class CodeCall:
    name: str
    kind: str
    line: int
    dynamic: bool
    input_names: list[str] = field(default_factory=list)


@dataclass
class CodeAnalysis:
    calls: list[CodeCall] = field(default_factory=list)
    gaps: set[str] = field(default_factory=set)

    @property
    def capabilities(self) -> set[str]:
        result = {call.kind for call in self.calls}
        if result:
            result.add("DANGEROUS_CODE_PRIMITIVE")
        result.update(self.gaps)
        return result


_PROCESS = {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_call", "subprocess.check_output"}
_SHELL = {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"}
_EXEC = {"eval", "exec", "builtins.eval", "builtins.exec"}
_DESERIALIZE = {"pickle.loads", "pickle.load", "dill.loads", "dill.load", "marshal.loads", "yaml.unsafe_load"}
_NETWORK_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "request", "stream"}
_INTERPRETERS = {"python", "python3", "bash", "sh", "node", "powershell", "pwsh", "cmd"}
_SAFE_MODULES = {"json", "math", "re", "html", "datetime", "decimal", "statistics", "collections", "typing"}
_DATA_BUILTINS = {"str", "int", "float", "bool", "dict", "list", "tuple", "set", "len", "range", "enumerate", "zip",
                  "print", "sorted", "sum", "min", "max", "abs", "round", "isinstance", "issubclass", "type", "all", "any",
                  "map", "filter", "reversed", "bytes", "bytearray", "ord", "chr", "repr", "format", "iter", "next",
                  "ValueError", "TypeError", "RuntimeError", "Exception"}


def analyze_python(code: str) -> CodeAnalysis:
    result = CodeAnalysis()
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError):
        result.gaps.add("CODE_PARSE_ERROR")
        return result
    if sum(1 for _ in ast.walk(tree)) > 30000:
        result.gaps.add("CODE_ANALYSIS_LIMIT")
        return result

    def scan(scope: ast.AST, inherited: dict[str, str]) -> None:
        aliases = dict(inherited)
        parameter_names = {item.arg for item in ast.walk(scope.args) if isinstance(item, ast.arg)} if hasattr(scope, "args") else set()
        # Scope-local union: reassignment never silently selects a harmless alias.
        assignments: dict[str, list[ast.AST]] = {}
        items: list[ast.AST] = []
        children: list[ast.AST] = []
        pending = deque(ast.iter_child_nodes(scope))
        while pending:
            item = pending.popleft()
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                children.append(item)
                continue
            items.append(item)
            pending.extend(ast.iter_child_nodes(item))
        for item in items:
            if isinstance(item, ast.Import):
                for alias in item.names:
                    aliases[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]
            elif isinstance(item, ast.ImportFrom):
                for alias in item.names:
                    if alias.name == "*":
                        result.gaps.add("CODE_UNRESOLVED_CALL")
                    aliases[alias.asname or alias.name] = f"{item.module}.{alias.name}"
            elif isinstance(item, (ast.Assign, ast.AnnAssign, ast.NamedExpr, ast.AugAssign)):
                targets = item.targets if isinstance(item, ast.Assign) else [item.target]
                for target in targets:
                    if isinstance(target, ast.Name) and item.value is not None:
                        assignments.setdefault(target.id, []).append(item.value)

        resolution_steps = 0

        def names(expr: ast.AST, seen: frozenset[str] = frozenset()) -> set[str]:
            nonlocal resolution_steps
            resolution_steps += 1
            if len(seen) > 64 or resolution_steps > 100000:
                result.gaps.add("CODE_ANALYSIS_LIMIT")
                return set()
            if isinstance(expr, ast.Name):
                if expr.id in seen:
                    return set()
                values = assignments.get(expr.id, [])
                return {aliases.get(expr.id, expr.id)} | set().union(*(names(v, seen | {expr.id}) for v in values))
            if isinstance(expr, ast.Attribute):
                return {f"{base}.{expr.attr}" for base in names(expr.value, seen)}
            if isinstance(expr, ast.Call):
                constructors = names(expr.func, seen)
                if constructors & {"requests.Session", "httpx.Client", "httpx.AsyncClient", "aiohttp.ClientSession", "pathlib.Path"}:
                    return constructors
            return set()

        def fixed(expr: ast.AST, seen: frozenset[str] = frozenset()) -> bool:
            nonlocal resolution_steps
            resolution_steps += 1
            if len(seen) > 64 or resolution_steps > 100000:
                result.gaps.add("CODE_ANALYSIS_LIMIT")
                return False
            if isinstance(expr, ast.Constant):
                return True
            if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
                return all(fixed(e, seen) for e in expr.elts)
            # Without reaching-definition analysis, a later/conditional literal
            # assignment cannot prove a name constant at this earlier sink.
            if isinstance(expr, ast.BinOp):
                return fixed(expr.left, seen) and fixed(expr.right, seen)
            return False

        def fixed_authority(expr: ast.AST) -> bool:
            prefix = ""
            if isinstance(expr, ast.JoinedStr) and expr.values and isinstance(expr.values[0], ast.Constant):
                prefix = str(expr.values[0].value)
            elif isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add) and isinstance(expr.left, ast.Constant):
                prefix = str(expr.left.value)
            return bool(re.match(r"^https?://[^/?#\s]+[/?#]", prefix, re.I))

        def arg(call: ast.Call, index: int, *keys: str) -> list[ast.AST]:
            return call.args[index:index + 1] + [k.value for k in call.keywords if k.arg in keys]

        imported_roots = {value.split(".")[0] for value in aliases.values()}
        for item in items:
            if not isinstance(item, ast.Call):
                continue
            resolved = names(item.func)
            matched = False
            for name in sorted(resolved):
                values = arg(item, 0, "source", "object", "s", "data", "stream")
                kind = ""
                if name in _EXEC | _SHELL | _DESERIALIZE:
                    kind = "CODE_DYNAMIC_EXEC" if name in _EXEC | _SHELL else "CODE_DESERIALIZE"
                    if name in _SHELL:
                        values = arg(item, 0, "command", "cmd")
                elif name == "yaml.load":
                    loaders = arg(item, 1, "Loader")
                    if loaders and all(names(loader) <= {"yaml.SafeLoader", "yaml.CSafeLoader"} and names(loader) for loader in loaders):
                        continue
                    kind = "CODE_DESERIALIZE"
                elif name in _PROCESS:
                    kind = "CODE_PROCESS"
                    values = arg(item, 0, "args")
                    shell = next((k.value for k in item.keywords if k.arg == "shell"), ast.Constant(False))
                    if isinstance(shell, ast.Constant) and shell.value is False and len(values) == 1 and isinstance(values[0], (ast.List, ast.Tuple)):
                        argv = values[0].elts
                        if argv and isinstance(argv[0], ast.Constant) and isinstance(argv[0].value, str):
                            exe = argv[0].value.replace("\\", "/").split("/")[-1].lower().removesuffix(".exe")
                            values = argv[1:] if exe in _INTERPRETERS else []
                elif name.startswith(("requests.", "httpx.", "aiohttp.")) and name.rsplit(".", 1)[-1] in _NETWORK_METHODS:
                    kind = "CODE_NETWORK"
                    values = arg(item, 1 if name.endswith((".request", ".stream")) else 0, "url")
                elif name in {"urllib.request.urlopen", "urllib.request.urlretrieve"}:
                    kind = "CODE_NETWORK"
                    values = arg(item, 0, "url", "fullurl")
                elif name in {"http.client.HTTPConnection", "http.client.HTTPSConnection", "socket.create_connection", "socket.socket.connect", "socket.socket.connect_ex"}:
                    kind = "CODE_NETWORK"
                    values = arg(item, 0, "host", "address")
                elif name in {"open", "io.open"} or name.startswith("pathlib.Path.") and name.rsplit(".", 1)[-1] in {"open", "read_text", "read_bytes", "write_text", "write_bytes", "unlink"}:
                    kind = "CODE_FILE_IO"
                    values = arg(item, 0, "file")
                    if name.startswith("pathlib.Path."):
                        # Instance path resolution is deliberately conservative.
                        values = [item.func.value] if isinstance(item.func, ast.Attribute) else values
                elif name in {"os.remove", "os.unlink", "shutil.rmtree"}:
                    kind = "CODE_FILE_IO"
                    values = arg(item, 0, "path")
                elif name.endswith((".execute", ".executemany", ".executescript")):
                    kind = "CODE_SQL"
                    values = arg(item, 0, "sql", "query", "operation")
                elif name in {"getattr", "__import__", "importlib.import_module"}:
                    result.gaps.add("CODE_UNRESOLVED_CALL")
                elif name.startswith("socket."):
                    result.gaps.add("CODE_UNRESOLVED_CALL")
                elif "." in name and name.split(".")[0] in imported_roots:
                    safe = name.split(".")[0] in _SAFE_MODULES or name.startswith("urllib.parse.") or name in {
                        "yaml.safe_load", "requests.Session", "httpx.Client", "httpx.AsyncClient", "aiohttp.ClientSession", "pathlib.Path"
                    }
                    if not safe:
                        result.gaps.add("CODE_UNRESOLVED_CALL")
                if kind:
                    matched = True
                    dynamic = any(not fixed(v) and not (kind == "CODE_NETWORK" and fixed_authority(v)) for v in values) or any(k.arg is None for k in item.keywords)
                    result.calls.append(CodeCall(name, kind, item.lineno, dynamic, sorted({
                        n.id for v in values for n in ast.walk(v) if isinstance(n, ast.Name)
                    })))
            local_functions = {child.name for child in children if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))}
            if not matched and (not resolved or isinstance(item.func, ast.Name) and (
                item.func.id in parameter_names or item.func.id not in _DATA_BUILTINS | local_functions | set(aliases)
            )):
                result.gaps.add("CODE_UNRESOLVED_CALL")
        for child in children:
            scan(child, aliases)

    try:
        scan(tree, {})
    except RecursionError:
        result.gaps.add("CODE_ANALYSIS_LIMIT")
    return result
