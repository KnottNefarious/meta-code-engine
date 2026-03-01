import ast

# ---------- configuration ----------
SQL_METHODS = {"execute", "executemany"}
REQUEST_CONTAINERS = {"args", "form", "json", "values", "headers", "cookies", "data"}
HTML_KEYWORDS = {"<html", "<div", "<script", "<h1", "<body", "<span"}
SANITIZERS = {"escape"}  # markupsafe.escape


# ---------- exploitability scoring ----------
def calculate_exploitability(vuln_type):
    if vuln_type in {"Command Injection", "Unsafe Deserialization"}:
        return "VERY LIKELY", "direct code execution possible"
    if vuln_type == "SQL Injection":
        return "VERY LIKELY", "database can be manipulated directly"
    if vuln_type == "Cross-Site Scripting (XSS)":
        return "LIKELY", "attacker can execute JavaScript in victim browser"
    if vuln_type == "Path Traversal":
        return "LIKELY", "attacker may read sensitive files"
    if vuln_type == "Server-Side Request Forgery (SSRF)":
        return "LIKELY", "attacker controls server network requests"
    if vuln_type == "Insecure Direct Object Reference (IDOR)":
        return "VERY LIKELY", "unauthorized data access possible"
    return "UNKNOWN", "insufficient context"


# ---------- finding ----------
class Finding:
    def __init__(self, vuln_type, severity, path, sink, reason, fix, lineno=None):
        self.vuln_type = vuln_type
        self.severity = severity
        self.path = path
        self.sink = sink
        self.reason = reason
        self.fix = fix
        self.lineno = lineno
        self.exploitability, self.exploit_reason = calculate_exploitability(vuln_type)

    def format(self):
        location = f"Location: line {self.lineno}\n" if self.lineno else ""
        return (
            f"{self.vuln_type}\n"
            f"Severity: {self.severity}\n"
            f"{location}"
            f"Attack Path: {' → '.join(self.path)}\n"
            f"Sink: {self.sink}\n"
            f"Why: {self.reason}\n"
            f"Fix: {self.fix}"
        )


# ---------- symbolic value ----------
class SymbolicValue:
    def __init__(self, name, tainted=False, path=None):
        self.name = name
        self.tainted = tainted
        self.path = path or [name]

    def add(self, label):
        self.path.append(label)

    def merge(self, other):
        merged = SymbolicValue(self.name, self.tainted or other.tainted, list(self.path))
        merged.path = list(dict.fromkeys(self.path + other.path))
        return merged


# ---------- analyzer ----------
class SymbolicAnalyzer:
    def __init__(self):
        self.symbols = {}
        self.findings = []
        self._fingerprints = set()
        self.counter = 0
        self.functions = {}

    # ---- taint source ----
    def new_symbol(self):
        self.counter += 1
        return SymbolicValue(f"request_{self.counter}", True, ["request"])

    # ---- finding (DEDUP FIX) ----
    def add_finding(self, vuln_type, severity, sym, sink, reason, fix, node=None):
        lineno = getattr(node, "lineno", None)
        fingerprint = (vuln_type, lineno, sink)

        if fingerprint in self._fingerprints:
            return

        self._fingerprints.add(fingerprint)
        self.findings.append(
            Finding(vuln_type, severity, sym.path, sink, reason, fix, lineno)
        )

    # ---- node evaluation ----
    def eval(self, node):
        if node is None:
            return None

        if isinstance(node, ast.Constant):
            return node.value

        if isinstance(node, ast.Name):
            return self.symbols.get(node.id)

        # request.args.get()
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):

                # sanitizer detection
                if node.func.attr in SANITIZERS:
                    return None

                # request.args.get
                if isinstance(node.func.value, ast.Attribute):
                    if isinstance(node.func.value.value, ast.Name) and node.func.value.value.id == "request":
                        sym = self.new_symbol()
                        sym.add("get")
                        return sym

                # SQL injection
                if node.func.attr in SQL_METHODS and node.args:
                    query = self.eval(node.args[0])
                    if isinstance(query, SymbolicValue):
                        self.add_finding(
                            "SQL Injection",
                            "HIGH",
                            query,
                            "cursor.execute(query)",
                            "User input concatenated into SQL query",
                            "Use parameterized queries",
                            node
                        )

        # XSS via string concat
        if isinstance(node, ast.BinOp):
            left = self.eval(node.left)
            right = self.eval(node.right)

            def contains_html(v):
                return isinstance(v, str) and any(tag in v.lower() for tag in HTML_KEYWORDS)

            if (contains_html(left) and isinstance(right, SymbolicValue)) or (
                contains_html(right) and isinstance(left, SymbolicValue)
            ):
                sym = right if isinstance(right, SymbolicValue) else left
                sym.add("propagation")
                return sym

            if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
                return left.merge(right)
            return left or right

        # open(path) -> path traversal
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
            arg = self.eval(node.args[0])
            if isinstance(arg, SymbolicValue):
                self.add_finding(
                    "Path Traversal",
                    "MEDIUM",
                    arg,
                    "open(path)",
                    "User input used as filesystem path",
                    "Validate filename",
                    node
                )

        return None

    # ---- execution ----
    def execute_block(self, body):
        for stmt in body:

            # assignment
            if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name):
                val = self.eval(stmt.value)
                if isinstance(val, SymbolicValue):
                    val.add(stmt.targets[0].id)
                self.symbols[stmt.targets[0].id] = val

            # return -> XSS sink
            elif isinstance(stmt, ast.Return):
                val = self.eval(stmt.value)
                if isinstance(val, SymbolicValue):
                    self.add_finding(
                        "Cross-Site Scripting (XSS)",
                        "HIGH",
                        val,
                        "HTTP response",
                        "User input returned directly to browser",
                        "Escape output or use templating auto-escaping",
                        stmt
                    )

            # function defs (inter-procedural tracking)
            elif isinstance(stmt, ast.FunctionDef):
                self.functions[stmt.name] = stmt

            # function calls
            elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                call = stmt.value
                if isinstance(call.func, ast.Name) and call.func.id in self.functions:
                    func = self.functions[call.func.id]
                    saved = self.symbols.copy()

                    for arg, param in zip(call.args, func.args.args):
                        val = self.eval(arg)
                        self.symbols[param.arg] = val

                    self.execute_block(func.body)
                    self.symbols = saved

    def analyze(self, tree):
        self.execute_block(tree.body)


# ---------- report ----------
class AnalysisReport:
    def __init__(self, findings):
        self.issues = [f.format() for f in findings]


# ---------- engine ----------
class MetaCodeEngine:
    def orchestrate(self, code):
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return AnalysisReport([
                Finding(
                    "Invalid Python",
                    "INFO",
                    [("parser", None)],
                    "AST",
                    f"Code cannot be parsed: {e.msg}",
                    "Fix syntax before analysis"
                )
            ])

        analyzer = SymbolicAnalyzer()
        analyzer.analyze(tree)

        return AnalysisReport(analyzer.findings)