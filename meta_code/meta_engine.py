import ast

SANITIZERS = {"escape"}

SQL_METHODS = {"execute", "executemany"}
DB_FETCH_NAMES = {"find", "load", "fetch", "get_user", "get_by_id", "query_user"}
REQUEST_CONTAINERS = {"args", "form", "json", "values", "headers", "cookies", "data"}

HTML_KEYWORDS = {"<html", "<div", "<script", "<h1", "<body", "<span"}


# ---------------- Finding ----------------
class Finding:
    def __init__(self, vuln_type, severity, line, path, sink, reason, fix):
        self.vuln_type = vuln_type
        self.severity = severity
        self.line = line
        self.path = path
        self.sink = sink
        self.reason = reason
        self.fix = fix

    def format(self):
        path_str = " → ".join(f"{label}(line {ln})" if ln else label for label, ln in self.path)

        return (
            f"{self.vuln_type}\n"
            f"Severity: {self.severity}\n"
            f"Location: line {self.line}\n"
            f"Attack Path: {path_str}\n"
            f"Sink: {self.sink}\n"
            f"Why: {self.reason}\n"
            f"Fix: {self.fix}"
        )


# ---------------- Symbolic Value ----------------
class SymbolicValue:
    def __init__(self, tainted=False, path=None):
        self.tainted = tainted
        self.path = path or []

    def step(self, label, node):
        line = getattr(node, "lineno", None)
        self.path.append((label, line))

    def merge(self, other):
        return SymbolicValue(
            self.tainted or other.tainted,
            list(dict.fromkeys(self.path + other.path))
        )


# ---------------- Analyzer ----------------
class SymbolicAnalyzer:
    def __init__(self):
        self.symbols = {}
        self.findings = []
        self.fingerprints = set()
        self.functions = {}

    def add_finding(self, vuln_type, severity, sym, node, sink, reason, fix):
        line = getattr(node, "lineno", 0)

        fingerprint = (vuln_type, line, sink)
        if fingerprint in self.fingerprints:
            return
        self.fingerprints.add(fingerprint)

        self.findings.append(
            Finding(vuln_type, severity, line, sym.path, sink, reason, fix)
        )

    # ---------- Sources ----------
    def request_source(self, node):
        sym = SymbolicValue(True, [])
        sym.step("request", node)
        return sym

    # ---------- Evaluation ----------
    def eval(self, node):

        if node is None:
            return None

        # constant
        if isinstance(node, ast.Constant):
            return node.value

        # variable
        if isinstance(node, ast.Name):
            return self.symbols.get(node.id)

        # request.args / request.form
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "request":
                if node.attr in REQUEST_CONTAINERS:
                    return self.request_source(node)

        # request.args.get("q")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Attribute):
                if isinstance(node.func.value.value, ast.Name) and node.func.value.value.id == "request":
                    sym = self.request_source(node)
                    sym.step("get", node)
                    return sym

        # sanitizer
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in SANITIZERS:
                return SymbolicValue(False, [])

        # function calls (inter-procedural)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            fname = node.func.id

            # IDOR
            if fname in DB_FETCH_NAMES and node.args:
                arg = self.eval(node.args[0])
                if isinstance(arg, SymbolicValue) and arg.tainted:
                    self.add_finding(
                        "Insecure Direct Object Reference (IDOR)",
                        "HIGH",
                        arg,
                        node,
                        f"{fname}(id)",
                        "User-controlled identifier used to access protected object",
                        "Verify the object belongs to the current authenticated user"
                    )

            if fname in self.functions:
                arg_values = [self.eval(a) for a in node.args]

                saved = self.symbols.copy()
                params = self.functions[fname][0].args.args

                for param, val in zip(params, arg_values):
                    if isinstance(val, SymbolicValue):
                        val.step(fname, node)
                    self.symbols[param.arg] = val

                self.execute(self.functions[fname][1])
                ret = self.symbols.get("__return__")

                self.symbols = saved
                return ret

        # concatenation XSS
        if isinstance(node, ast.BinOp):
            left = self.eval(node.left)
            right = self.eval(node.right)

            if isinstance(left, SymbolicValue) and isinstance(right, str):
                if any(tag in right.lower() for tag in HTML_KEYWORDS):
                    left.step("propagation", node)
                    return left

            if isinstance(right, SymbolicValue) and isinstance(left, str):
                if any(tag in left.lower() for tag in HTML_KEYWORDS):
                    right.step("propagation", node)
                    return right

            if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
                return left.merge(right)
            return left or right

        return None

    # ---------- Execute block ----------
    def execute(self, body):
        for stmt in body:

            if isinstance(stmt, ast.Assign):
                if isinstance(stmt.targets[0], ast.Name):
                    val = self.eval(stmt.value)
                    if isinstance(val, SymbolicValue):
                        val.step(stmt.targets[0].id, stmt)
                    self.symbols[stmt.targets[0].id] = val

            elif isinstance(stmt, ast.Return):
                val = self.eval(stmt.value)
                if isinstance(val, SymbolicValue) and val.tainted:
                    val.step("return", stmt)
                    self.add_finding(
                        "Cross-Site Scripting (XSS)",
                        "HIGH",
                        val,
                        stmt,
                        "HTTP response",
                        "User input returned directly to browser",
                        "Escape output or use templating auto-escaping"
                    )
                self.symbols["__return__"] = val

            elif isinstance(stmt, ast.Expr):
                self.eval(stmt.value)

            elif isinstance(stmt, ast.If):
                self.execute(stmt.body)
                self.execute(stmt.orelse)

    # ---------- Analyze ----------
    def analyze(self, tree):

        # collect functions
        for node in tree.body:
            if isinstance(node, ast.FunctionDef):
                self.functions[node.name] = (node, node.body)

        # run module
        self.execute(tree.body)


# ---------------- Report ----------------
class AnalysisReport:
    def __init__(self, findings):
        self.issues = [f.format() for f in findings]


# ---------------- Engine ----------------
class MetaCodeEngine:
    def orchestrate(self, code):
        tree = ast.parse(code)
        analyzer = SymbolicAnalyzer()
        analyzer.analyze(tree)
        return AnalysisReport(analyzer.findings)
