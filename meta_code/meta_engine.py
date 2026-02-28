import ast

SQL_METHODS = {"execute", "executemany"}
SUBPROCESS_METHODS = {"Popen", "run", "call"}
DESERIALIZE_METHODS = {"loads", "load"}
NETWORK_METHODS = {"get", "post", "put", "delete", "head", "options", "request"}
DB_FETCH_NAMES = {"find", "load", "fetch", "get_user", "get_by_id", "query_user"}
REQUEST_CONTAINERS = {"args", "form", "json", "values", "headers", "cookies", "data"}

HTML_KEYWORDS = {"<html", "<div", "<script", "<h1", "<body", "<span"}

# -------- Sanitizers --------
SANITIZER_FUNCTIONS = {
    "escape",
    "html.escape",
    "bleach.clean",
    "clean",
    "flask.escape"
}

# ---------------- Exploitability scoring ----------------
def calculate_exploitability(vuln_type, path, sink):
    if vuln_type in {"Command Injection", "Unsafe Deserialization"}:
        return "VERY LIKELY", "direct code execution possible"
    if vuln_type == "SQL Injection":
        return "VERY LIKELY", "database can be manipulated directly"
    if vuln_type == "Server-Side Request Forgery (SSRF)":
        return "LIKELY", "attacker controls server network requests"
    if vuln_type == "Path Traversal":
        return "LIKELY", "attacker may read sensitive files"
    if vuln_type == "Cross-Site Scripting (XSS)":
        return "LIKELY", "attacker can execute JavaScript in victim browser"
    if vuln_type == "Insecure Direct Object Reference (IDOR)":
        return "LIKELY", "unauthorized data access possible"
    if vuln_type == "Open Redirect":
        return "LOW", "requires user interaction to exploit"
    if vuln_type == "Missing Authorization":
        return "VERY LIKELY", "privileged action can be triggered by attacker"
    return "UNKNOWN", "insufficient context"


class Finding:
    def __init__(self, vuln_type, severity, path, sink, reason, fix):
        self.vuln_type = vuln_type
        self.severity = severity
        self.path = path
        self.sink = sink
        self.reason = reason
        self.fix = fix
        self.exploitability, self.exploit_reason = calculate_exploitability(vuln_type, path, sink)

    def format(self):
        path_str = " → ".join(f"{label}(line {line})" if line else label for label, line in self.path)
        return (
            f"{self.vuln_type}\n"
            f"Severity: {self.severity}\n"
            f"Exploitability: {self.exploitability}\n"
            f"Reason: {self.exploit_reason}\n"
            f"Attack Path: {path_str}\n"
            f"Sink: {self.sink}\n"
            f"Why: {self.reason}\n"
            f"Fix: {self.fix}"
        )


class SymbolicValue:
    def __init__(self, name, tainted=False, path=None):
        self.name = name
        self.tainted = tainted
        self.path = path or [(name, None)]

    def add_step(self, label, node):
        line = getattr(node, "lineno", None)
        self.path.append((label, line))

    def merge(self, other):
        merged = SymbolicValue(self.name, self.tainted or other.tainted, list(self.path))
        merged.path = list(dict.fromkeys(self.path + other.path))
        return merged


class SymbolicAnalyzer:
    def __init__(self):
        self.symbols = {}
        self.findings = []
        self._fingerprints = set()
        self.counter = 0
        self.authorized_ids = set()

    def new_symbol(self, source="request", node=None):
        self.counter += 1
        sym = SymbolicValue(f"{source}_{self.counter}", True, [(source, getattr(node, "lineno", None))])
        return sym

    # -------- function name resolver --------
    def get_call_name(self, node):
        if isinstance(node.func, ast.Name):
            return node.func.id

        if isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return None

    def add_finding(self, vuln_type, severity, sym, sink, reason, fix):
        last = sym.path[-1] if sym.path else ("unknown", None)
        fingerprint = (vuln_type, last, sink)

        if fingerprint in self._fingerprints:
            return
        self._fingerprints.add(fingerprint)

        self.findings.append(Finding(vuln_type, severity, sym.path, sink, reason, fix))

    # ---------------- Core evaluation ----------------
    def eval_node(self, node):

        if node is None:
            return None

        if isinstance(node, ast.Constant):
            return node.value

        if isinstance(node, ast.Name):
            return self.symbols.get(node.id)

        # -------- request sources --------
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "request":
                if node.attr in REQUEST_CONTAINERS:
                    return self.new_symbol("request", node)

        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Attribute):
                    if isinstance(node.func.value.value, ast.Name) and node.func.value.value.id == "request":
                        sym = self.new_symbol("request", node)
                        sym.add_step("get", node)
                        return sym

        # -------- function propagation & sanitizers --------
        if isinstance(node, ast.Call):
            func_name = self.get_call_name(node)

            arg_symbols = []
            for arg in node.args:
                val = self.eval_node(arg)
                if isinstance(val, SymbolicValue):
                    arg_symbols.append(val)

            if not arg_symbols:
                return None

            # sanitizer cleans taint
            if func_name in SANITIZER_FUNCTIONS:
                return None

            merged = arg_symbols[0]
            for other in arg_symbols[1:]:
                merged = merged.merge(other)

            merged.add_step(func_name or "call", node)
            return merged

        # -------- XSS detection --------
        if isinstance(node, ast.BinOp):

            left = self.eval_node(node.left)
            right = self.eval_node(node.right)

            def contains_html(v):
                return isinstance(v, str) and any(tag in v.lower() for tag in HTML_KEYWORDS)

            if (contains_html(left) and isinstance(right, SymbolicValue)) or (
                contains_html(right) and isinstance(left, SymbolicValue)
            ):
                sym = right if isinstance(right, SymbolicValue) else left
                sym.add_step("return", node)
                self.add_finding(
                    "Cross-Site Scripting (XSS)",
                    "HIGH",
                    sym,
                    "HTTP response",
                    "User input returned directly to browser",
                    "Escape output or use templating auto-escaping"
                )

            if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
                return left.merge(right)
            if isinstance(left, SymbolicValue):
                return left
            if isinstance(right, SymbolicValue):
                return right

        # -------- RETURN sink --------
        if isinstance(node, ast.Return):
            val = self.eval_node(node.value)
            if isinstance(val, SymbolicValue):
                val.add_step("return", node)
                self.add_finding(
                    "Cross-Site Scripting (XSS)",
                    "HIGH",
                    val,
                    "HTTP response",
                    "User input returned directly to browser",
                    "Escape output or use templating auto-escaping"
                )

        # -------- Path traversal --------
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
            if node.args:
                arg = self.eval_node(node.args[0])
                if isinstance(arg, SymbolicValue):
                    arg.add_step("open", node)
                    self.add_finding("Path Traversal", "MEDIUM", arg, "open(path)",
                                     "User input used as filesystem path",
                                     "Validate filename or use secure_filename()")

        # -------- SQL injection --------
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in SQL_METHODS and node.args:
                query = self.eval_node(node.args[0])
                if isinstance(query, SymbolicValue):
                    query.add_step("execute", node)
                    self.add_finding("SQL Injection", "HIGH", query, "cursor.execute(query)",
                                     "User input concatenated into SQL query",
                                     "Use parameterized queries")

        # -------- SSRF --------
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            obj = node.func.value
            if isinstance(obj, ast.Name) and obj.id == "requests":
                if node.args:
                    url = self.eval_node(node.args[0])
                    if isinstance(url, SymbolicValue):
                        url.add_step("request", node)
                        self.add_finding("Server-Side Request Forgery (SSRF)", "HIGH", url, "HTTP request",
                                         "User-controlled URL used in server request",
                                         "Validate allowed hosts")

        return None

    # -------- traversal --------
    def execute_block(self, body):
        for stmt in body:

            if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name):
                val = self.eval_node(stmt.value)
                if isinstance(val, SymbolicValue):
                    val.add_step(stmt.targets[0].id, stmt)
                self.symbols[stmt.targets[0].id] = val

            elif isinstance(stmt, ast.Expr):
                self.eval_node(stmt.value)

            elif isinstance(stmt, ast.Return):
                self.eval_node(stmt)

            elif isinstance(stmt, ast.If):
                self.eval_node(stmt.test)
                self.execute_block(stmt.body)
                self.execute_block(stmt.orelse)

    def analyze(self, tree):
        self.execute_block(tree.body)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                saved = self.symbols.copy()
                self.execute_block(node.body)
                self.symbols = saved


class AnalysisReport:
    def __init__(self, findings):
        self.issues = [f.format() for f in findings]


class MetaCodeEngine:
    def orchestrate(self, code):
        tree = ast.parse(code)
        analyzer = SymbolicAnalyzer()
        analyzer.analyze(tree)
        return AnalysisReport(analyzer.findings)
