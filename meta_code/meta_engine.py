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
# .execute() is only flagged as SQL Injection when the receiver matches one of these,
# preventing false positives on objects like HarmonicExecutor, SQLAlchemy Engine, etc.
DB_CURSOR_NAMES = {
    "cursor", "cur", "c", "curs",
    "conn", "connection", "db", "database",
    "session", "sess", "con",
}
REQUEST_CONTAINERS = {"args", "form", "json", "values", "headers", "cookies", "data"}
HTML_KEYWORDS      = {"<html", "<div", "<script", "<h1", "<body", "<span"}
SANITIZERS         = {"escape"}                               # markupsafe.escape

# os.* command sinks
OS_COMMAND_METHODS = {"system", "popen", "popen2", "popen3", "popen4"}

# subprocess.* command sinks (only dangerous when shell=True or first arg tainted)
SUBPROCESS_METHODS = {"call", "run", "Popen", "check_call", "check_output"}

# pickle / yaml / marshal deserialization sinks
DESERIALIZE_CONTAINERS = {"pickle", "yaml", "marshal"}
DESERIALIZE_METHODS    = {"loads", "load"}

# requests.* SSRF sinks
REQUESTS_METHODS = {"get", "post", "put", "patch", "delete", "request", "head", "options"}

# Flask redirect — open redirect
REDIRECT_FUNCTIONS = {"redirect"}


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
# Symbolic value — tracks taint through the program
# ---------------------------------------------------------------------------

class SymbolicValue:
    """
    Represents a value in the symbolic execution engine.
    tainted=True means the value flows from attacker-controlled input.
    path records how the value was derived (for attack-path reconstruction).
    """

    def __init__(self, name, tainted=False, path=None):
        self.name    = name
        self.tainted = tainted
        self.path    = path if path is not None else [name]

    def add(self, label):
        """Extend the derivation path with a new label."""
        self.path.append(label)

    def merge(self, other):
        """Merge two symbolic values — result is tainted if either is."""
        merged      = SymbolicValue(self.name, self.tainted or other.tainted, list(self.path))
        merged.path = list(dict.fromkeys(self.path + other.path))  # dedup, preserve order
        return merged


# ---------------------------------------------------------------------------
# Symbolic Analyzer — the taint engine
# ---------------------------------------------------------------------------

class SymbolicAnalyzer:

    def __init__(self):
        self.symbols      = {}           # variable name → SymbolicValue | literal
        self.findings     = []
        self._fingerprints = set()       # (vuln_type, lineno, sink) for dedup
        self.counter      = 0
        self.functions    = {}           # function name → ast.FunctionDef

    # ------------------------------------------------------------------
    # Taint source factory
    # ------------------------------------------------------------------

    def _new_tainted(self, label="request"):
        self.counter += 1
        return SymbolicValue(f"request_{self.counter}", tainted=True, path=[label])

    # ------------------------------------------------------------------
    # Finding with deduplication
    # ------------------------------------------------------------------

    def _add_finding(self, vuln_type, severity, sym, sink, reason, fix, node=None):
        lineno      = getattr(node, "lineno", None)
        fingerprint = (vuln_type, lineno, sink)
        if fingerprint in self._fingerprints:
            return
        self._fingerprints.add(fingerprint)
        self.findings.append(
            Finding(vuln_type, severity, list(sym.path), sink, reason, fix, lineno)
        )

    # ------------------------------------------------------------------
    # Helper — does a call have shell=True as a keyword argument?
    # ------------------------------------------------------------------

    @staticmethod
    def _has_shell_true(call_node):
        for kw in call_node.keywords:
            if (kw.arg == "shell"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True):
                return True
        return False

    # ------------------------------------------------------------------
    # Expression evaluation — returns SymbolicValue | literal | None
    # ------------------------------------------------------------------

    def eval(self, node):  # noqa: C901  (complexity is inherent to the pattern matching)
        if node is None:
            return None

        # Literal constant — safe
        if isinstance(node, ast.Constant):
            return node.value

        # Variable reference
        if isinstance(node, ast.Name):
            return self.symbols.get(node.id)

        # Subscript  e.g.  documents[user_id]
        if isinstance(node, ast.Subscript):
            key = self.eval(node.slice)
            if isinstance(key, SymbolicValue) and key.tainted:
                # Return a tainted value so callers can detect IDOR on return
                sym = SymbolicValue(f"subscript_{self.counter}", tainted=True,
                                    path=list(key.path) + ["subscript_access"])
                return sym
            return None

        # Function / method calls
        if isinstance(node, ast.Call):
            func = node.func

            # ----------------------------------------------------------------
            # Calls with attribute access:  obj.method(...)
            # ----------------------------------------------------------------
            if isinstance(func, ast.Attribute):
                method = func.attr
                obj    = func.value

                # Sanitizer — wipes taint
                if method in SANITIZERS:
                    return None

                # ---- Taint source: request.<container>.get() ---------------
                if isinstance(obj, ast.Attribute) and obj.attr in REQUEST_CONTAINERS:
                    if isinstance(obj.value, ast.Name) and obj.value.id == "request":
                        sym = self._new_tainted("request")
                        sym.add(obj.attr)
                        sym.add(method)
                        return sym

                # Also handle request.<container> directly (no .get)
                if isinstance(obj, ast.Name) and obj.id == "request":
                    if method in REQUEST_CONTAINERS:
                        sym = self._new_tainted("request")
                        sym.add(method)
                        return sym

                # ---- SQL Injection: cursor.execute(tainted) -----------------
                # Only flag when the calling object looks like a DB cursor/connection,
                # not arbitrary objects with an .execute() method (e.g. HarmonicExecutor).
                if method in SQL_METHODS and node.args:
                    obj_name = obj.id if isinstance(obj, ast.Name) else None
                    is_db_cursor = (
                        obj_name in DB_CURSOR_NAMES
                        or isinstance(obj, ast.Attribute)  # e.g. db.cursor().execute()
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
                if (isinstance(obj, ast.Name) and obj.id == "os"
                        and method in OS_COMMAND_METHODS):
                    if node.args:
                        arg = self.eval(node.args[0])
                        if isinstance(arg, SymbolicValue) and arg.tainted:
                            self._add_finding(
                                "Command Injection", "CRITICAL", arg,
                                f"os.{method}(cmd)",
                                "User input executed directly by the OS shell",
                                "Never pass user input to os.system/popen — use subprocess with a list and shell=False",
                                node,
                            )

                # ---- Command Injection: subprocess.*( ..., shell=True) ------
                if (isinstance(obj, ast.Name) and obj.id == "subprocess"
                        and method in SUBPROCESS_METHODS):
                    if node.args and self._has_shell_true(node):
                        arg = self.eval(node.args[0])
                        if isinstance(arg, SymbolicValue) and arg.tainted:
                            self._add_finding(
                                "Command Injection", "CRITICAL", arg,
                                f"subprocess.{method}(cmd, shell=True)",
                                "User input passed to shell via subprocess",
                                "Pass arguments as a list and omit shell=True",
                                node,
                            )

                # ---- Unsafe Deserialization: pickle/yaml/marshal.loads ------
                if (isinstance(obj, ast.Name)
                        and obj.id in DESERIALIZE_CONTAINERS
                        and method in DESERIALIZE_METHODS):
                    if node.args:
                        arg = self.eval(node.args[0])
                        if isinstance(arg, SymbolicValue) and arg.tainted:
                            self._add_finding(
                                "Unsafe Deserialization", "CRITICAL", arg,
                                f"{obj.id}.{method}(data)",
                                f"User input deserialized with {obj.id} — arbitrary code execution possible",
                                f"Never deserialize untrusted data with {obj.id}; use a safe format like JSON",
                                node,
                            )

                # ---- SSRF: requests.<method>(tainted_url) ------------------
                if (isinstance(obj, ast.Name) and obj.id == "requests"
                        and method in REQUESTS_METHODS):
                    # requests.request('GET', url) — URL is 2nd arg
                    # requests.get/post/put/... — URL is 1st arg
                    url_arg_index = 1 if method == "request" else 0
                    if len(node.args) > url_arg_index:
                        arg = self.eval(node.args[url_arg_index])
                        if isinstance(arg, SymbolicValue) and arg.tainted:
                            sink_label = (f"requests.{method}(method, url)"
                                          if method == "request"
                                          else f"requests.{method}(url)")
                            self._add_finding(
                                "Server-Side Request Forgery (SSRF)", "HIGH", arg,
                                sink_label,
                                "Server makes HTTP request to attacker-controlled URL",
                                "Validate and allowlist URLs before making server-side requests",
                                node,
                            )

            # ----------------------------------------------------------------
            # Bare function calls:  open(...), redirect(...), etc.
            # ----------------------------------------------------------------
            if isinstance(func, ast.Name):
                name = func.id

                # Path Traversal: open(tainted_path)
                if name == "open" and node.args:
                    arg = self.eval(node.args[0])
                    if isinstance(arg, SymbolicValue) and arg.tainted:
                        self._add_finding(
                            "Path Traversal", "MEDIUM", arg,
                            "open(path)",
                            "User input used as a filesystem path — arbitrary file read possible",
                            "Validate the filename against an allowlist and resolve the real path",
                            node,
                        )

                # Open Redirect: redirect(tainted_url)
                if name in REDIRECT_FUNCTIONS and node.args:
                    arg = self.eval(node.args[0])
                    if isinstance(arg, SymbolicValue) and arg.tainted:
                        self._add_finding(
                            "Open Redirect", "MEDIUM", arg,
                            "redirect(url)",
                            "User-controlled URL passed to redirect — attacker can redirect victims off-site",
                            "Validate redirect URLs against a known-good allowlist or use url_for()",
                            node,
                        )

                # Forbidden call guard (exec/eval/compile/__import__)
                if name in {"exec", "eval", "compile", "__import__"}:
                    return None  # don't propagate taint through these

            return None

        # Binary operation — propagate taint; detect XSS on HTML + tainted concat
        if isinstance(node, ast.BinOp):
            left  = self.eval(node.left)
            right = self.eval(node.right)

            def _contains_html(v):
                return isinstance(v, str) and any(tag in v.lower() for tag in HTML_KEYWORDS)

            if (_contains_html(left) and isinstance(right, SymbolicValue) and right.tainted) or \
               (_contains_html(right) and isinstance(left, SymbolicValue) and left.tainted):
                sym = right if (isinstance(right, SymbolicValue) and right.tainted) else left
                sym.add("html_concat")
                return sym

            if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
                return left.merge(right)
            return left if isinstance(left, SymbolicValue) else right

        return None

    # ------------------------------------------------------------------
    # Statement execution
    # ------------------------------------------------------------------

    def execute_block(self, body):  # noqa: C901
        for stmt in body:

            # Variable assignment — propagate taint
            if isinstance(stmt, ast.Assign):
                val = self.eval(stmt.value)
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        if isinstance(val, SymbolicValue):
                            val.add(target.id)
                        self.symbols[target.id] = val

            # Augmented assignment  x += tainted
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

            # Return statement — XSS sink + IDOR sink
            elif isinstance(stmt, ast.Return):
                val = self.eval(stmt.value)
                if isinstance(val, SymbolicValue) and val.tainted:
                    # IDOR: tainted subscript access returned
                    if "subscript_access" in val.path:
                        self._add_finding(
                            "Insecure Direct Object Reference (IDOR)", "HIGH", val,
                            "return resource[user_id]",
                            "Resource fetched by user-controlled ID with no authorization check",
                            "Verify the authenticated user is authorized to access the requested resource",
                            stmt,
                        )
                    else:
                        # XSS: tainted value returned as HTTP response
                        self._add_finding(
                            "Cross-Site Scripting (XSS)", "HIGH", val,
                            "HTTP response",
                            "User input returned directly to the browser without escaping",
                            "Escape output with markupsafe.escape() or use a templating engine with auto-escaping",
                            stmt,
                        )

            # Function definition — register for inter-procedural tracking
            elif isinstance(stmt, ast.FunctionDef):
                self.functions[stmt.name] = stmt
                # Also recurse to register nested functions
                self.execute_block(stmt.body)

            # Bare expression — includes function calls like os.system(cmd)
            elif isinstance(stmt, ast.Expr):
                call = stmt.value
                # Inline call that is a tracked user-defined function
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
                    # Evaluate to trigger any sink detections inside eval()
                    self.eval(call)

            # If-statement — analyze both branches
            elif isinstance(stmt, ast.If):
                self.execute_block(stmt.body)
                if stmt.orelse:
                    self.execute_block(stmt.orelse)

            # For / While loops
            elif isinstance(stmt, (ast.For, ast.While)):
                self.execute_block(stmt.body)

            # Try/except
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
    """The result returned by MetaCodeEngine.orchestrate()."""

    def __init__(self, findings):
        self.issues = [f.format() for f in findings]


# ---------------------------------------------------------------------------
# Meta-Code Engine — public API
# ---------------------------------------------------------------------------

class MetaCodeEngine:
    """
    Orchestrates a full SAST pass over Python source code.

    Usage:
        engine = MetaCodeEngine()
        report = engine.orchestrate(code_string)
        for issue in report.issues:
            print(issue)
    """

    def orchestrate(self, code: str) -> AnalysisReport:
        if not code or not code.strip():
            return AnalysisReport([])

        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return AnalysisReport([
                Finding(
                    "Invalid Python", "INFO",
                    ["parser"],
                    "AST",
                    f"Code cannot be parsed: {e.msg}",
                    "Fix syntax errors before analysis",
                )
            ])

        analyzer = SymbolicAnalyzer()
        analyzer.analyze(tree)
        return AnalysisReport(analyzer.findings)
