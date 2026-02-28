import ast

SQL_METHODS = {"execute", "executemany"}
SUBPROCESS_METHODS = {"Popen", "run", "call"}
DESERIALIZE_METHODS = {"loads", "load"}
NETWORK_METHODS = {"get", "post", "put", "delete", "head", "options", "request"}
DB_FETCH_NAMES = {"find", "load", "fetch", "get_user", "get_by_id", "query_user"}
REQUEST_CONTAINERS = {"args", "form", "json", "values", "headers", "cookies", "data"}

HTML_KEYWORDS = {"<html", "<div", "<script", "<h1", "<body", "<span"}


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
        self.authorized_ids = set()

    def new_symbol(self, source="request"):
        self.counter += 1
        return SymbolicValue(f"{source}_{self.counter}", True, [source])

    def add_finding(self, vuln_type, severity, sym, sink, reason, fix):
        self.findings.append(Finding(vuln_type, severity, sym.path, sink, reason, fix))

    # ---------------- Core evaluation ----------------
    def eval_node(self, node):

        if node is None:
            return None

        if isinstance(node, ast.Constant):
            return node.value

        if isinstance(node, ast.Name):
            return self.symbols.get(node.id)

        # -------- Flask taint sources (FULL FIX) --------
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):

            container = node.func.value

            if isinstance(container, ast.Attribute):
                if isinstance(container.value, ast.Name) and container.value.id == "request":
                    if container.attr in REQUEST_CONTAINERS:
                        sym = self.new_symbol("request")
                        sym.path.append(container.attr)
                        sym.path.append(node.func.attr)
                        return sym

        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "request":
                if node.attr in REQUEST_CONTAINERS:
                    sym = self.new_symbol("request")
                    sym.path.append(node.attr)
                    return sym

        # -------- Authorization tracking --------
        if isinstance(node, ast.Compare):
            left = node.left
            right = node.comparators[0] if node.comparators else None

            def is_current_user_attr(n):
                return isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "current_user"

            if isinstance(left, ast.Name) and is_current_user_attr(right):
                self.authorized_ids.add(left.id)

            if isinstance(right, ast.Name) and is_current_user_attr(left):
                self.authorized_ids.add(right.id)

        # -------- XSS detection --------
        def contains_tainted(expr):
            if expr is None:
                return None

            val = self.eval_node(expr)
            if isinstance(val, SymbolicValue):
                return val

            if isinstance(expr, ast.BinOp):
                return contains_tainted(expr.left) or contains_tainted(expr.right)

            if isinstance(expr, ast.JoinedStr):
                for v in expr.values:
                    found = contains_tainted(v)
                    if found:
                        return found

            if isinstance(expr, ast.FormattedValue):
                return contains_tainted(expr.value)

            return None

        def contains_html(expr):
            if expr is None:
                return False

            if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
                return any(tag in expr.value.lower() for tag in HTML_KEYWORDS)

            if isinstance(expr, ast.BinOp):
                return contains_html(expr.left) or contains_html(expr.right)

            if isinstance(expr, ast.JoinedStr):
                for v in expr.values:
                    if contains_html(v):
                        return True

            return False

        if isinstance(node, ast.BinOp):
            tainted = contains_tainted(node)
            html = contains_html(node)

            if tainted and html:
                self.add_finding(
                    "Cross-Site Scripting (XSS)",
                    "HIGH",
                    tainted,
                    "HTTP response",
                    "User input returned directly to browser",
                    "Escape output or use templating auto-escaping"
                )

        # -------- Path traversal --------
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
            if node.args:
                arg = self.eval_node(node.args[0])
                if isinstance(arg, SymbolicValue):
                    self.add_finding("Path Traversal", "MEDIUM", arg, "open(path)",
                                     "User input used as filesystem path",
                                     "Validate filename or use secure_filename()")

        # -------- SQL injection --------
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in SQL_METHODS and node.args:
                query = self.eval_node(node.args[0])
                if isinstance(query, SymbolicValue):
                    self.add_finding("SQL Injection", "HIGH", query, "cursor.execute(query)",
                                     "User input concatenated into SQL query",
                                     "Use parameterized queries")

        # -------- Command injection --------
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in SUBPROCESS_METHODS:
                if node.args:
                    cmd = self.eval_node(node.args[0])
                    shell_true = any(kw.arg == "shell" and getattr(kw.value, "value", False) for kw in node.keywords)
                    if isinstance(cmd, SymbolicValue) and shell_true:
                        self.add_finding("Command Injection", "CRITICAL", cmd, "subprocess(shell=True)",
                                         "User input executed by OS shell",
                                         "Avoid shell=True and pass arguments as a list")

        # -------- Unsafe deserialization --------
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in DESERIALIZE_METHODS and node.args:
                val = self.eval_node(node.args[0])
                if isinstance(val, SymbolicValue):
                    self.add_finding("Unsafe Deserialization", "CRITICAL", val, "pickle/yaml loads()",
                                     "Untrusted data deserialized into objects",
                                     "Never deserialize untrusted input")

        # -------- SSRF --------
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            obj = node.func.value
            if isinstance(obj, ast.Name) and obj.id == "requests":
                if node.args:
                    url = self.eval_node(node.args[0])
                    if isinstance(url, SymbolicValue):
                        self.add_finding("Server-Side Request Forgery (SSRF)", "HIGH", url, "HTTP request",
                                         "User-controlled URL used in server request",
                                         "Validate allowed hosts")

        # -------- Open redirect --------
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "redirect":
            if node.args:
                target = self.eval_node(node.args[0])
                if isinstance(target, SymbolicValue):
                    self.add_finding("Open Redirect", "MEDIUM", target, "redirect()",
                                     "User-controlled URL used in redirect",
                                     "Restrict to internal paths")

        # -------- IDOR --------
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in DB_FETCH_NAMES and node.args:
                arg_node = node.args[0]
                ident = self.eval_node(arg_node)
                if isinstance(ident, SymbolicValue):
                    if isinstance(arg_node, ast.Name) and arg_node.id in self.authorized_ids:
                        return None

                    self.add_finding("Insecure Direct Object Reference (IDOR)", "HIGH", ident,
                                     f"{node.func.attr}(id)",
                                     "User-controlled identifier used to access protected object",
                                     "Verify authorization")

        # -------- Missing Authorization --------
        if isinstance(node, ast.Call):

            func_name = ""
            if isinstance(node.func, ast.Attribute):
                func_name = node.func.attr.lower()
            elif isinstance(node.func, ast.Name):
                func_name = node.func.id.lower()

            privileged_keywords = [
                "delete", "remove", "transfer",
                "grant", "revoke", "promote",
                "demote", "set_role", "make_admin",
                "change_password", "reset_password",
                "ban", "unban"
            ]

            if any(word in func_name for word in privileged_keywords):
                if node.args:
                    sym = self.eval_node(node.args[0])
                    if isinstance(sym, SymbolicValue):
                        self.add_finding(
                            "Missing Authorization",
                            "CRITICAL",
                            sym,
                            f"{func_name}(...)",
                            "Privileged action performed using user-controlled data without verifying permissions",
                            "Verify the current user is authorized before performing this action"
                        )

        return None

    # -------- Execution traversal --------
    def execute_block(self, body):
        for stmt in body:
            if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name):
                val = self.eval_node(stmt.value)
                if isinstance(val, SymbolicValue):
                    val.path.append(stmt.targets[0].id)
                self.symbols[stmt.targets[0].id] = val
            elif isinstance(stmt, ast.Expr):
                self.eval_node(stmt.value)
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

            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, ast.FunctionDef):
                        saved = self.symbols.copy()
                        self.execute_block(item.body)
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
