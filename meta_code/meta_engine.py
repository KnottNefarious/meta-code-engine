import ast

SQL_METHODS = {"execute", "executemany"}
SUBPROCESS_METHODS = {"Popen", "run", "call"}
DESERIALIZE_METHODS = {"loads", "load"}
NETWORK_METHODS = {"get", "post", "put", "delete", "head", "options", "request"}
DB_FETCH_NAMES = {"find", "load", "fetch", "get_user", "get_by_id", "query_user"}
REQUEST_CONTAINERS = {"args", "form", "json", "values", "headers", "cookies", "data"}

HTML_KEYWORDS = {"<html", "<div", "<script", "<h1", "<body", "<span"}


# ---------------- EXPLOITABILITY SCORING ----------------
def calculate_exploitability(vuln_type, path, sink):
    length = len(path)

    # Direct user control
    direct = length <= 3

    critical_sinks = {
        "subprocess(shell=True)",
        "cursor.execute(query)",
        "pickle/yaml loads()",
        "open(path)"
    }

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

    return "UNKNOWN", "insufficient context"


class Finding:
    def __init__(self, vuln_type, severity, path, sink, reason, fix):
        self.vuln_type = vuln_type
        self.severity = severity
        self.path = path
        self.sink = sink
        self.reason = reason
        self.fix = fix

        self.exploitability, self.exploit_reason = calculate_exploitability(
            vuln_type, path, sink
        )

    def format(self):
        return (
            f"{self.vuln_type}\n"
            f"Severity: {self.severity}\n"
            f"Exploitability: {self.exploitability}\n"
            f"Reason: {self.exploit_reason}\n"
            f"Attack Path: {' → '.join(self.path)}\n"
            f"Sink: {self.sink}\n"
            f"Why: {self.reason}\n"
            f"Fix: {self.fix}"
        )


class SymbolicValue:
    def __init__(self, name, tainted=False, path=None):
        self.name = name
        self.tainted = tainted
        self.path = path or [name]

    def merge(self, other):
        merged = SymbolicValue(self.name, self.tainted or other.tainted, list(self.path))
        merged.path = list(dict.fromkeys(self.path + other.path))
        return merged


class SymbolicAnalyzer:
    def __init__(self):
        self.symbols = {}
        self.findings = []
        self.counter = 0
        self.functions = {}

    def new_symbol(self, source="request"):
        self.counter += 1
        return SymbolicValue(f"{source}_{self.counter}", True, [source])

    def is_request(self, node):
        return (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "request"
            and node.attr in REQUEST_CONTAINERS
        )

    def add_finding(self, vuln_type, severity, sym, sink, reason, fix):
        self.findings.append(Finding(vuln_type, severity, sym.path, sink, reason, fix))

    def is_html_string(self, value):
        return isinstance(value, str) and any(tag in value.lower() for tag in HTML_KEYWORDS)

    # ---------------- CORE ANALYSIS ----------------

    def eval_node(self, node):

        if node is None:
            return None

        if isinstance(node, ast.Constant):
            return node.value

        if isinstance(node, ast.Name):
            return self.symbols.get(node.id)

        # request sources
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and self.is_request(node.func.value):
                sym = self.new_symbol("request")
                sym.path.append("get")
                return sym

        # XSS
        if isinstance(node, ast.BinOp):
            left = self.eval_node(node.left)
            right = self.eval_node(node.right)

            if isinstance(left, str) and isinstance(right, SymbolicValue) and self.is_html_string(left):
                self.add_finding(
                    "Cross-Site Scripting (XSS)",
                    "HIGH",
                    right,
                    "HTML response",
                    "User input embedded into HTML response",
                    "Escape output or use templating auto-escaping",
                )

            if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
                return left.merge(right)
            if isinstance(left, SymbolicValue):
                return left
            if isinstance(right, SymbolicValue):
                return right

        # PATH TRAVERSAL
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
            arg = self.eval_node(node.args[0])
            if isinstance(arg, SymbolicValue):
                self.add_finding(
                    "Path Traversal",
                    "MEDIUM",
                    arg,
                    "open(path)",
                    "User input used as filesystem path",
                    "Validate filename or use secure_filename()",
                )

        # SQL
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in SQL_METHODS:
                query = self.eval_node(node.args[0])
                if isinstance(query, SymbolicValue):
                    self.add_finding(
                        "SQL Injection",
                        "HIGH",
                        query,
                        "cursor.execute(query)",
                        "User input concatenated into SQL query",
                        "Use parameterized queries",
                    )

        # COMMAND
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in SUBPROCESS_METHODS:
                cmd = self.eval_node(node.args[0])
                shell_true = any(kw.arg == "shell" and getattr(kw.value, "value", False) for kw in node.keywords)
                if isinstance(cmd, SymbolicValue) and shell_true:
                    self.add_finding(
                        "Command Injection",
                        "CRITICAL",
                        cmd,
                        "subprocess(shell=True)",
                        "User input executed by OS shell",
                        "Avoid shell=True and pass arguments as a list",
                    )

        # DESERIALIZATION
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in DESERIALIZE_METHODS:
                val = self.eval_node(node.args[0])
                if isinstance(val, SymbolicValue):
                    self.add_finding(
                        "Unsafe Deserialization",
                        "CRITICAL",
                        val,
                        "pickle/yaml loads()",
                        "Untrusted data deserialized into objects",
                        "Never deserialize untrusted input",
                    )

        # SSRF
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            obj = node.func.value
            if isinstance(obj, ast.Name) and obj.id in {"requests", "httpx", "urllib"}:
                url = self.eval_node(node.args[0])
                if isinstance(url, SymbolicValue):
                    self.add_finding(
                        "Server-Side Request Forgery (SSRF)",
                        "HIGH",
                        url,
                        "HTTP request",
                        "User-controlled URL used in server request",
                        "Validate allowed hosts",
                    )

        # OPEN REDIRECT
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "redirect":
            target = self.eval_node(node.args[0])
            if isinstance(target, SymbolicValue):
                self.add_finding(
                    "Open Redirect",
                    "MEDIUM",
                    target,
                    "redirect()",
                    "User-controlled URL used in redirect",
                    "Restrict to internal paths",
                )

        # IDOR
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            obj = node.func.value
            if isinstance(obj, ast.Name) and obj.id in {"requests", "httpx", "urllib"}:
                return None
            if node.func.attr in DB_FETCH_NAMES:
                ident = self.eval_node(node.args[0])
                if isinstance(ident, SymbolicValue):
                    self.add_finding(
                        "Insecure Direct Object Reference (IDOR)",
                        "HIGH",
                        ident,
                        f"{node.func.attr}(id)",
                        "User-controlled identifier used to access protected object",
                        "Verify authorization",
                    )

        return None

    def execute_block(self, body):
        for stmt in body:
            if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name):
                val = self.eval_node(stmt.value)
                if isinstance(val, SymbolicValue):
                    val.path.append(stmt.targets[0].id)
                self.symbols[stmt.targets[0].id] = val
            elif isinstance(stmt, ast.Expr):
                self.eval_node(stmt.value)

    def analyze(self, tree):
        for node in tree.body:
            if isinstance(node, ast.FunctionDef):
                self.functions[node.name] = node

        self.execute_block(tree.body)


class AnalysisReport:
    def __init__(self, findings):
        self.issues = [f.format() for f in findings]


class MetaCodeEngine:
    def orchestrate(self, code):
        tree = ast.parse(code)
        analyzer = SymbolicAnalyzer()
        analyzer.analyze(tree)
        return AnalysisReport(analyzer.findings)
