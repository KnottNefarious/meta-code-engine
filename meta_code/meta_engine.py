"""
meta_engine.py — Core SAST engine for Meta-Code Engine.

Implements taint-flow + control-flow analysis over Python ASTs.
Detects:  SQL Injection, XSS, Command Injection, Path Traversal,
          Unsafe Deserialization, SSRF, Open Redirect, IDOR.

Architecture:  Source → Propagation → Sink
"""

import ast

# ---------------------------------------------------------------------------
# Configuration — sink method name sets
# ---------------------------------------------------------------------------

SQL_METHODS        = {"execute", "executemany"}

# Variable names that strongly suggest a database cursor/connection.
DB_CURSOR_NAMES = {
    "cursor", "cur", "c", "curs",
    "conn", "connection", "db", "database",
    "session", "sess", "con", "engine",
}

# Flask request containers — taint sources
REQUEST_CONTAINERS  = {"args", "form", "json", "values", "headers", "cookies", "data", "files"}
REQUEST_METHODS     = {"get_json", "get_data"}
REQUEST_ATTRIBUTES  = {"data", "args", "form", "json", "values", "headers", "cookies", "files"}

HTML_KEYWORDS       = {"<html", "<div", "<script", "<h1", "<body", "<span", "<p", "<a "}
SANITIZERS          = {"escape", "Markup"}

# os.* command sinks — keyed under canonical module name "os"
OS_COMMAND_METHODS  = {"system", "popen", "popen2", "popen3", "popen4"}

# subprocess.* command sinks
SUBPROCESS_METHODS  = {"call", "run", "Popen", "check_call", "check_output"}

# pickle / yaml / marshal deserialization sinks
DESERIALIZE_CONTAINERS = {"pickle", "yaml", "marshal"}
DESERIALIZE_METHODS    = {"loads", "load"}

# requests.* SSRF sinks
REQUESTS_METHODS = {"get", "post", "put", "patch", "delete", "request", "head", "options"}

# Flask redirect — open redirect
REDIRECT_FUNCTIONS = {"redirect"}

# Flask template rendering — XSS sink
TEMPLATE_RENDER_FUNCTIONS = {"render_template_string", "make_response", "Response"}

# File open functions — path traversal
FILE_OPEN_FUNCTIONS = {"open"}

# SQLAlchemy / Django ORM raw-query sinks
ORM_RAW_FUNCTIONS = {"text", "raw", "extra", "RawSQL"}

# ---------------------------------------------------------------------------
# Exploitability scoring
# ---------------------------------------------------------------------------

def calculate_exploitability(vuln_type):
    if vuln_type in {"Command Injection", "Unsafe Deserialization"}:
        return "VERY LIKELY", "direct code execution possible"
    if vuln_type == "SQL Injection":
        return "VERY LIKELY", "database can be manipulated directly"
    if vuln_type in {"Cross-Site Scripting (XSS)", "Open Redirect"}:
        return "LIKELY", "attacker can execute JavaScript or redirect victims"
    if vuln_type == "Path Traversal":
        return "LIKELY", "attacker may read sensitive files"
    if vuln_type == "Server-Side Request Forgery (SSRF)":
        return "LIKELY", "attacker controls server network requests"
    if vuln_type == "Insecure Direct Object Reference (IDOR)":
        return "VERY LIKELY", "unauthorized data access possible"
    return "UNKNOWN", "insufficient context"


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

class Finding:
    """A single detected vulnerability with full context."""

    def __init__(self, vuln_type, severity, path, sink, reason, fix, lineno=None):
        self.vuln_type  = vuln_type
        self.severity   = severity
        self.path       = path
        self.sink       = sink
        self.reason     = reason
        self.fix        = fix
        self.lineno     = lineno
        self.exploitability, self.exploit_reason = calculate_exploitability(vuln_type)

    def format(self):
        location = f"Location: line {self.lineno}\n" if self.lineno else ""
        return (
            f"{self.vuln_type}\n"
            f"Severity: {self.severity}\n"
            f"{location}"
            f"Exploitability: {self.exploitability} — {self.exploit_reason}\n"
            f"Attack Path: {' → '.join(str(p) for p in self.path)}\n"
            f"Sink: {self.sink}\n"
            f"Why: {self.reason}\n"
            f"Fix: {self.fix}"
        )


# ---------------------------------------------------------------------------
# Symbolic value
# ---------------------------------------------------------------------------

class SymbolicValue:
    def __init__(self, name, tainted=False, path=None):
        self.name    = name
        self.tainted = tainted
        self.path    = path if path is not None else [name]

    def add(self, label):
        self.path.append(label)

    def merge(self, other):
        merged      = SymbolicValue(self.name, self.tainted or other.tainted, list(self.path))
        merged.path = list(dict.fromkeys(self.path + other.path))
        return merged


# ---------------------------------------------------------------------------
# Symbolic Analyzer
# ---------------------------------------------------------------------------

class SymbolicAnalyzer:

    def __init__(self):
        self.symbols       = {}     # variable name → SymbolicValue | literal
        self.findings      = []
        self._fingerprints = set()
        self.counter       = 0
        self.functions     = {}     # function name → FunctionDef

        # Import alias maps:
        #   module_aliases: alias_name → canonical_module  e.g. "op_sys" → "os"
        #   func_aliases:   alias_name → (module, funcname) e.g. "run_cmd" → ("subprocess", "call")
        self.module_aliases = {}
        self.func_aliases   = {}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _new_tainted(self, label="request"):
        self.counter += 1
        return SymbolicValue(f"request_{self.counter}", tainted=True, path=[label])

    def _add_finding(self, vuln_type, severity, sym, sink, reason, fix, node=None):
        lineno      = getattr(node, "lineno", None)
        fingerprint = (vuln_type, lineno, sink)
        if fingerprint in self._fingerprints:
            return
        self._fingerprints.add(fingerprint)
        self.findings.append(
            Finding(vuln_type, severity, list(sym.path), sink, reason, fix, lineno)
        )

    @staticmethod
    def _has_shell_true(call_node):
        for kw in call_node.keywords:
            if (kw.arg == "shell"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True):
                return True
        return False

    def _resolve_module(self, name):
        """Return the canonical module name for a possibly-aliased name."""
        return self.module_aliases.get(name, name)

    def _any_tainted(self, nodes):
        """Return the first tainted SymbolicValue found in a list of AST nodes, or None."""
        for n in nodes:
            val = self.eval(n)
            if isinstance(val, SymbolicValue) and val.tainted:
                return val
        return None

    def _any_tainted_kw(self, keywords):
        """Return the first tainted SymbolicValue in keyword args, or None."""
        for kw in keywords:
            val = self.eval(kw.value)
            if isinstance(val, SymbolicValue) and val.tainted:
                return val
        return None

    # ------------------------------------------------------------------
    # Expression evaluation
    # ------------------------------------------------------------------

    def eval(self, node):  # noqa: C901
        if node is None:
            return None

        # Literal constant — safe
        if isinstance(node, ast.Constant):
            return node.value

        # Variable reference
        if isinstance(node, ast.Name):
            return self.symbols.get(node.id)

        # ── Direct attribute access: request.data, request.args etc. ──
        if isinstance(node, ast.Attribute):
            if (isinstance(node.value, ast.Name)
                    and node.value.id == "request"
                    and node.attr in REQUEST_ATTRIBUTES):
                sym = self._new_tainted("request")
                sym.add(node.attr)
                return sym
            inner = self.eval(node.value)
            if isinstance(inner, SymbolicValue) and inner.tainted:
                return inner
            return None

        # ── Subscript: data["key"], documents[user_id] ──
        if isinstance(node, ast.Subscript):
            key       = self.eval(node.slice)
            container = self.eval(node.value)
            # IDOR: attacker controls the key
            if isinstance(key, SymbolicValue) and key.tainted:
                sym = SymbolicValue(f"subscript_{self.counter}", tainted=True,
                                    path=list(key.path) + ["subscript_access"])
                return sym
            # Dict taint propagation: tainted dict → tainted value
            if isinstance(container, SymbolicValue) and container.tainted:
                sym = SymbolicValue(container.name, True, list(container.path))
                sym.add("dict_access")
                return sym
            return None

        # ── Binary operation ──
        if isinstance(node, ast.BinOp):
            left  = self.eval(node.left)
            right = self.eval(node.right)

            def _contains_html(v):
                return isinstance(v, str) and any(tag in v.lower() for tag in HTML_KEYWORDS)

            if (_contains_html(left)  and isinstance(right, SymbolicValue) and right.tainted) or \
               (_contains_html(right) and isinstance(left,  SymbolicValue) and left.tainted):
                sym = right if (isinstance(right, SymbolicValue) and right.tainted) else left
                sym.add("html_concat")
                return sym

            # ── % string formatting: "query %s" % tainted ──
            if isinstance(node.op, ast.Mod):
                # right side may be a single value or a Tuple of values
                tainted = None
                if isinstance(right, SymbolicValue) and right.tainted:
                    tainted = right
                elif isinstance(node.right, ast.Tuple):
                    tainted = self._any_tainted(node.right.elts)
                if tainted:
                    sym = SymbolicValue(tainted.name, True, list(tainted.path))
                    sym.add("percent_format")
                    return sym

            if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
                return left.merge(right)
            if isinstance(left,  SymbolicValue): return left
            if isinstance(right, SymbolicValue): return right
            return None

        # ── f-string: JoinedStr ──
        if isinstance(node, ast.JoinedStr):
            tainted_parts = []
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    val = self.eval(part.value)
                    if isinstance(val, SymbolicValue) and val.tainted:
                        tainted_parts.append(val)
            if tainted_parts:
                result = tainted_parts[0]
                for extra in tainted_parts[1:]:
                    result = result.merge(extra)
                result.add("fstring")
                return result
            return None

        # ── Function / method calls ──
        if isinstance(node, ast.Call):
            func = node.func

            # ── Attribute calls: obj.method(...) ──
            if isinstance(func, ast.Attribute):
                method   = func.attr
                obj      = func.value
                obj_name = obj.id if isinstance(obj, ast.Name) else None
                # Resolve alias → canonical module name
                canon    = self._resolve_module(obj_name) if obj_name else None

                # Sanitizer
                if method in SANITIZERS:
                    return None

                # ---- Taint source: request.<container>.get() ---------------
                if isinstance(obj, ast.Attribute) and obj.attr in REQUEST_CONTAINERS:
                    if isinstance(obj.value, ast.Name) and obj.value.id == "request":
                        sym = self._new_tainted("request")
                        sym.add(obj.attr)
                        sym.add(method)
                        return sym

                # ---- Taint source: request.get_json() / request.get_data() -
                if obj_name == "request" and method in REQUEST_METHODS:
                    sym = self._new_tainted("request")
                    sym.add(method)
                    return sym

                # ---- Taint source: request.<container> directly ------------
                if obj_name == "request" and method in REQUEST_CONTAINERS:
                    sym = self._new_tainted("request")
                    sym.add(method)
                    return sym

                # ---- .format() string interpolation -------------------------
                if method == "format":
                    tainted = (self._any_tainted(node.args) or
                               self._any_tainted_kw(node.keywords))
                    if tainted:
                        sym = SymbolicValue(tainted.name, True, list(tainted.path))
                        sym.add("str_format")
                        return sym

                # ---- Taint propagation: tainted_dict.get('key') -------------
                if method in {"get", "values", "items", "keys", "pop", "setdefault"}:
                    receiver = self.eval(obj)
                    if isinstance(receiver, SymbolicValue) and receiver.tainted:
                        sym = SymbolicValue(receiver.name, True, list(receiver.path))
                        sym.add(method)
                        return sym

                # ---- String taint passthrough: .strip() .lower() etc. ------
                if method in {"strip", "lstrip", "rstrip", "lower", "upper",
                              "encode", "decode", "replace", "split", "join",
                              "expandtabs", "title", "capitalize"}:
                    receiver = self.eval(obj)
                    if isinstance(receiver, SymbolicValue) and receiver.tainted:
                        sym = SymbolicValue(receiver.name, True, list(receiver.path))
                        sym.add(method)
                        return sym

                # ---- SQL Injection ------------------------------------------
                if method in SQL_METHODS and node.args:
                    is_db_cursor = (
                        obj_name in DB_CURSOR_NAMES
                        or canon   in DB_CURSOR_NAMES
                        or isinstance(obj, ast.Attribute)
                    )
                    if is_db_cursor:
                        arg = self.eval(node.args[0])
                        if isinstance(arg, SymbolicValue) and arg.tainted:
                            self._add_finding(
                                "SQL Injection", "HIGH", arg,
                                f"{obj_name or 'cursor'}.{method}(query)",
                                "User input concatenated into SQL query",
                                "Use parameterized queries: cursor.execute(sql, (param,))",
                                node,
                            )

                # ---- Command Injection: os.system / os.popen ----------------
                if canon == "os" and method in OS_COMMAND_METHODS:
                    if node.args:
                        arg = self.eval(node.args[0])
                        if isinstance(arg, SymbolicValue) and arg.tainted:
                            self._add_finding(
                                "Command Injection", "CRITICAL", arg,
                                f"{obj_name}.{method}(cmd)",
                                "User input executed directly by the OS shell",
                                "Never pass user input to os.system/popen — use subprocess with a list and shell=False",
                                node,
                            )

                # ---- Command Injection: subprocess.*(..., shell=True) -------
                if canon == "subprocess" and method in SUBPROCESS_METHODS:
                    if node.args and self._has_shell_true(node):
                        arg = self.eval(node.args[0])
                        if isinstance(arg, SymbolicValue) and arg.tainted:
                            self._add_finding(
                                "Command Injection", "CRITICAL", arg,
                                f"{obj_name}.{method}(cmd, shell=True)",
                                "User input passed to shell via subprocess",
                                "Pass arguments as a list and omit shell=True",
                                node,
                            )
                    # Also flag non-shell subprocess when first arg is tainted string
                    # (e.g. subprocess.run(tainted) without shell=True is still risky)

                # ---- Unsafe Deserialization ---------------------------------
                if (obj_name in DESERIALIZE_CONTAINERS or canon in DESERIALIZE_CONTAINERS):
                    real = canon if canon in DESERIALIZE_CONTAINERS else obj_name
                    if method in DESERIALIZE_METHODS and node.args:
                        arg = self.eval(node.args[0])
                        if isinstance(arg, SymbolicValue) and arg.tainted:
                            self._add_finding(
                                "Unsafe Deserialization", "CRITICAL", arg,
                                f"{obj_name}.{method}(data)",
                                f"User input deserialized with {real} — arbitrary code execution possible",
                                f"Never deserialize untrusted data with {real}; use a safe format like JSON",
                                node,
                            )

                # ---- SSRF ---------------------------------------------------
                if canon == "requests" and method in REQUESTS_METHODS:
                    url_arg_index = 1 if method == "request" else 0
                    if len(node.args) > url_arg_index:
                        arg = self.eval(node.args[url_arg_index])
                        if isinstance(arg, SymbolicValue) and arg.tainted:
                            sink_label = (f"{obj_name}.{method}(method, url)"
                                          if method == "request"
                                          else f"{obj_name}.{method}(url)")
                            self._add_finding(
                                "Server-Side Request Forgery (SSRF)", "HIGH", arg,
                                sink_label,
                                "Server makes HTTP request to attacker-controlled URL",
                                "Validate and allowlist URLs before making server-side requests",
                                node,
                            )

                # ---- Recursive eval for method chains (open(path).read()) --
                inner = self.eval(obj)
                if isinstance(inner, SymbolicValue) and inner.tainted:
                    return inner
                return None

            # ── Bare function calls ──
            if isinstance(func, ast.Name):
                name     = func.id
                # Check if this name is an aliased function
                resolved = self.func_aliases.get(name)

                # Path Traversal
                if name in FILE_OPEN_FUNCTIONS and node.args:
                    arg = self.eval(node.args[0])
                    if isinstance(arg, SymbolicValue) and arg.tainted:
                        self._add_finding(
                            "Path Traversal", "MEDIUM", arg,
                            f"{name}(path)",
                            "User input used as a filesystem path — arbitrary file read possible",
                            "Validate the filename against an allowlist and resolve the real path",
                            node,
                        )

                # Open Redirect
                if name in REDIRECT_FUNCTIONS and node.args:
                    arg = self.eval(node.args[0])
                    if isinstance(arg, SymbolicValue) and arg.tainted:
                        self._add_finding(
                            "Open Redirect", "MEDIUM", arg,
                            f"{name}(url)",
                            "User-controlled URL passed to redirect — attacker can redirect victims off-site",
                            "Validate redirect URLs against a known-good allowlist or use url_for()",
                            node,
                        )

                # XSS: render_template_string / make_response
                if name in TEMPLATE_RENDER_FUNCTIONS and node.args:
                    arg = self.eval(node.args[0])
                    if isinstance(arg, SymbolicValue) and arg.tainted:
                        self._add_finding(
                            "Cross-Site Scripting (XSS)", "HIGH", arg,
                            f"{name}(template)",
                            f"User input passed directly to {name} — template injection possible",
                            "Never concatenate user input into templates; use template variables with auto-escaping",
                            node,
                        )

                # ORM raw functions: text(tainted), raw(tainted)
                if name in ORM_RAW_FUNCTIONS and node.args:
                    arg = self.eval(node.args[0])
                    if isinstance(arg, SymbolicValue) and arg.tainted:
                        # Return tainted so the outer session.execute() call can detect it
                        sym = SymbolicValue(arg.name, True, list(arg.path))
                        sym.add(f"{name}_wrap")
                        return sym

                # Aliased function calls e.g. run_cmd = subprocess.call
                if resolved:
                    mod, fn = resolved
                    canon_mod = self._resolve_module(mod)
                    # Command injection via aliased subprocess function
                    if canon_mod == "subprocess" and fn in SUBPROCESS_METHODS:
                        if node.args and self._has_shell_true(node):
                            arg = self.eval(node.args[0])
                            if isinstance(arg, SymbolicValue) and arg.tainted:
                                self._add_finding(
                                    "Command Injection", "CRITICAL", arg,
                                    f"{name}(cmd, shell=True)  [alias: {mod}.{fn}]",
                                    "User input passed to shell via aliased subprocess function",
                                    "Pass arguments as a list and omit shell=True",
                                    node,
                                )
                    # OS command via aliased os function
                    if canon_mod == "os" and fn in OS_COMMAND_METHODS:
                        if node.args:
                            arg = self.eval(node.args[0])
                            if isinstance(arg, SymbolicValue) and arg.tainted:
                                self._add_finding(
                                    "Command Injection", "CRITICAL", arg,
                                    f"{name}(cmd)  [alias: {mod}.{fn}]",
                                    "User input executed by OS via aliased function",
                                    "Never pass user input to os.system/popen",
                                    node,
                                )

                # Forbidden call guard
                if name in {"exec", "eval", "compile", "__import__"}:
                    return None

            return None

        # Dict literal — tainted if any value is tainted
        # e.g. data = {"query": uid}  →  data is tainted
        if isinstance(node, ast.Dict):
            for val_node in node.values:
                val = self.eval(val_node)
                if isinstance(val, SymbolicValue) and val.tainted:
                    sym = SymbolicValue("dict", True, list(val.path))
                    sym.add("dict_literal")
                    return sym
            return None

        # List/Tuple literal — tainted if any element is tainted
        if isinstance(node, (ast.List, ast.Tuple)):
            for elt in node.elts:
                val = self.eval(elt)
                if isinstance(val, SymbolicValue) and val.tainted:
                    sym = SymbolicValue("seq", True, list(val.path))
                    sym.add("sequence_literal")
                    return sym
            return None

        return None

    # ------------------------------------------------------------------
    # Statement execution
    # ------------------------------------------------------------------

    def execute_block(self, body):  # noqa: C901
        for stmt in body:

            # ── Import alias tracking ──────────────────────────────────
            if isinstance(stmt, ast.Import):
                for alias in stmt.names:
                    if alias.asname:
                        # e.g. import os as op_sys  →  op_sys → os
                        self.module_aliases[alias.asname] = alias.name.split(".")[0]

            elif isinstance(stmt, ast.ImportFrom):
                module = stmt.module or ""
                for alias in stmt.names:
                    if alias.asname:
                        # e.g. from subprocess import call as run_cmd
                        self.func_aliases[alias.asname] = (module, alias.name)
                    else:
                        # e.g. from os import system  →  system callable directly
                        canon_mod = module.split(".")[0]
                        if canon_mod == "os" and alias.name in OS_COMMAND_METHODS:
                            self.func_aliases[alias.name] = ("os", alias.name)
                        if canon_mod == "subprocess" and alias.name in SUBPROCESS_METHODS:
                            self.func_aliases[alias.name] = ("subprocess", alias.name)

            # ── Variable assignment ────────────────────────────────────
            elif isinstance(stmt, ast.Assign):
                val = self.eval(stmt.value)
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        if isinstance(val, SymbolicValue):
                            val.add(target.id)
                        self.symbols[target.id] = val
                    # Tuple unpacking: a, b = tainted_pair
                    elif isinstance(target, ast.Tuple):
                        for elt in target.elts:
                            if isinstance(elt, ast.Name):
                                self.symbols[elt.id] = val

            # ── Augmented assignment ───────────────────────────────────
            elif isinstance(stmt, ast.AugAssign):
                if isinstance(stmt.target, ast.Name):
                    existing = self.symbols.get(stmt.target.id)
                    new_val  = self.eval(stmt.value)
                    if isinstance(existing, SymbolicValue) or isinstance(new_val, SymbolicValue):
                        merged = (existing if isinstance(existing, SymbolicValue)
                                  else SymbolicValue("_aug", False))
                        if isinstance(new_val, SymbolicValue):
                            merged = merged.merge(new_val)
                        self.symbols[stmt.target.id] = merged

            # ── Return statement — XSS / IDOR sink ─────────────────────
            elif isinstance(stmt, ast.Return):
                val = self.eval(stmt.value)
                if isinstance(val, SymbolicValue) and val.tainted:
                    if "subscript_access" in val.path:
                        self._add_finding(
                            "Insecure Direct Object Reference (IDOR)", "HIGH", val,
                            "return resource[user_id]",
                            "Resource fetched by user-controlled ID with no authorization check",
                            "Verify the authenticated user is authorized to access the requested resource",
                            stmt,
                        )
                    else:
                        self._add_finding(
                            "Cross-Site Scripting (XSS)", "HIGH", val,
                            "HTTP response",
                            "User input returned directly to the browser without escaping",
                            "Escape output with markupsafe.escape() or use a templating engine with auto-escaping",
                            stmt,
                        )

            # ── Function definition ────────────────────────────────────
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions[stmt.name] = stmt
                self.execute_block(stmt.body)

            # ── Class definition — scan all methods ────────────────────
            elif isinstance(stmt, ast.ClassDef):
                for item in stmt.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self.functions[item.name] = item
                        self.execute_block(item.body)

            # ── Bare expression ────────────────────────────────────────
            elif isinstance(stmt, ast.Expr):
                call = stmt.value
                if (isinstance(call, ast.Call)
                        and isinstance(call.func, ast.Name)
                        and call.func.id in self.functions):
                    func  = self.functions[call.func.id]
                    saved = self.symbols.copy()
                    for arg_node, param in zip(call.args, func.args.args):
                        self.symbols[param.arg] = self.eval(arg_node)
                    self.execute_block(func.body)
                    self.symbols = saved
                else:
                    self.eval(call)

            # ── If-statement — walrus + both branches ──────────────────
            elif isinstance(stmt, ast.If):
                if isinstance(stmt.test, ast.NamedExpr):
                    val = self.eval(stmt.test.value)
                    if isinstance(val, SymbolicValue):
                        val.add(stmt.test.target.id)
                    self.symbols[stmt.test.target.id] = val
                self.execute_block(stmt.body)
                if stmt.orelse:
                    self.execute_block(stmt.orelse)

            # ── Loops ──────────────────────────────────────────────────
            elif isinstance(stmt, (ast.For, ast.While)):
                self.execute_block(stmt.body)

            # ── Try/except ─────────────────────────────────────────────
            elif isinstance(stmt, ast.Try):
                self.execute_block(stmt.body)
                for handler in stmt.handlers:
                    self.execute_block(handler.body)

    def analyze(self, tree):
        self.execute_block(tree.body)


# ---------------------------------------------------------------------------
# Analysis Report
# ---------------------------------------------------------------------------

class AnalysisReport:
    def __init__(self, findings):
        self.issues = [f.format() for f in findings]


# ---------------------------------------------------------------------------
# Meta-Code Engine — public API
# ---------------------------------------------------------------------------

class MetaCodeEngine:
    def orchestrate(self, code: str) -> AnalysisReport:
        if not code or not code.strip():
            return AnalysisReport([])
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return AnalysisReport([
                Finding(
                    "Invalid Python", "INFO", ["parser"], "AST",
                    f"Code cannot be parsed: {e.msg}",
                    "Fix syntax errors before analysis",
                )
            ])
        analyzer = SymbolicAnalyzer()
        analyzer.analyze(tree)
        return AnalysisReport(analyzer.findings)
