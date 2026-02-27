import ast

DANGEROUS_CALLS = {"eval", "exec"}
DANGEROUS_METHODS = {"system", "popen", "Popen"}
SQL_SINKS = {"execute", "executemany"}

FIX_SUGGESTIONS = {
    "system": "Avoid os.system with user input. Use subprocess.run([...], shell=False) and pass arguments as a list.",
    "popen": "Avoid executing shell commands with user input. Use subprocess.run with validated arguments.",
    "Popen": "Avoid executing shell commands with user input. Use subprocess.run with shell=False.",
    "eval": "Never execute user input with eval(). Parse or validate the data instead (e.g., JSON parsing).",
    "exec": "Do not execute dynamic code from user input. Redesign logic to interpret commands safely.",
    "sql": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE name=?', (name,))"
}


class SymbolicValue:
    def __init__(self, name, tainted=False, path=None):
        self.name = name
        self.tainted = tainted
        self.attributes = {}
        self.path = path or [name]

    def copy(self):
        new = SymbolicValue(self.name, self.tainted, list(self.path))
        new.attributes = dict(self.attributes)
        return new

    def add_step(self, step):
        self.path.append(step)


class SymbolicAnalyzer:
    def __init__(self):
        self.symbols = {}
        self.functions = {}
        self.classes = {}
        self.issues = []
        self.symbolic_counter = 0

    def new_symbol(self):
        self.symbolic_counter += 1
        return SymbolicValue(f"input_{self.symbolic_counter}", tainted=True)

    def clone(self):
        new = SymbolicAnalyzer()
        new.symbols = {k: (v.copy() if isinstance(v, SymbolicValue) else v)
                       for k, v in self.symbols.items()}
        new.functions = self.functions
        new.classes = self.classes
        new.symbolic_counter = self.symbolic_counter
        return new

    def run(self, tree):
        for stmt in tree.body:
            self.execute(stmt)

    # ---------------- statements ----------------
    def execute(self, node):

        if isinstance(node, ast.ClassDef):
            self.classes[node.name] = node
            return

        if isinstance(node, ast.FunctionDef):
            self.functions[node.name] = node
            return

        if isinstance(node, ast.Assign):

            if isinstance(node.targets[0], ast.Attribute):
                obj = self.evaluate(node.targets[0].value)
                value = self.evaluate(node.value)

                if isinstance(obj, SymbolicValue) and isinstance(value, SymbolicValue):
                    value.add_step(node.targets[0].attr)
                    obj.attributes[node.targets[0].attr] = value
                return

            if isinstance(node.targets[0], ast.Name):
                value = self.evaluate(node.value)
                if isinstance(value, SymbolicValue):
                    value.add_step(node.targets[0].id)
                self.symbols[node.targets[0].id] = value
            return

        if isinstance(node, ast.Expr):
            self.evaluate(node.value)
            return

    # ---------------- expressions ----------------
    def evaluate(self, node):

        if isinstance(node, ast.Constant):
            return node.value

        if isinstance(node, ast.Name):
            return self.symbols.get(node.id, None)

        if isinstance(node, ast.Attribute):
            obj = self.evaluate(node.value)
            if isinstance(obj, SymbolicValue):
                val = obj.attributes.get(node.attr, None)
                if isinstance(val, SymbolicValue):
                    val.add_step(node.attr)
                return val
            return None

        if isinstance(node, ast.Call):

            # SOURCE
            if isinstance(node.func, ast.Name) and node.func.id == "input":
                return self.new_symbol()

            # CLASS CONSTRUCTOR
            if isinstance(node.func, ast.Name) and node.func.id in self.classes:
                class_def = self.classes[node.func.id]
                obj = SymbolicValue(node.func.id)

                for stmt in class_def.body:
                    if isinstance(stmt, ast.FunctionDef) and stmt.name == "__init__":
                        saved = self.symbols
                        local = self.symbols.copy()
                        local["self"] = obj
                        self.symbols = local

                        for init_stmt in stmt.body:
                            self.execute(init_stmt)

                        self.symbols = saved
                return obj

            # USER FUNCTION
            if isinstance(node.func, ast.Name) and node.func.id in self.functions:
                func = self.functions[node.func.id]

                saved = self.symbols
                local = self.symbols.copy()

                for param, arg in zip(func.args.args, node.args):
                    val = self.evaluate(arg)
                    if isinstance(val, SymbolicValue):
                        val.add_step(f"param:{param.arg}")
                    local[param.arg] = val

                self.symbols = local
                for stmt in func.body:
                    self.execute(stmt)
                self.symbols = saved
                return None

            # ATTRIBUTE CALL (SINK)
            if isinstance(node.func, ast.Attribute):
                method = node.func.attr
                for arg in node.args:
                    val = self.evaluate(arg)

                    if isinstance(val, SymbolicValue) and val.tainted:

                        if method in DANGEROUS_METHODS:
                            trace = " → ".join(val.path + [method])
                            fix = FIX_SUGGESTIONS.get(method, "Validate user input before use.")
                            self.issues.append(f"Command execution path: {trace}\nSuggested fix: {fix}")

                        if method in SQL_SINKS:
                            trace = " → ".join(val.path + [method])
                            fix = FIX_SUGGESTIONS["sql"]
                            self.issues.append(f"SQL injection path: {trace}\nSuggested fix: {fix}")
                return None

            # DIRECT DANGEROUS
            if isinstance(node.func, ast.Name):
                for arg in node.args:
                    val = self.evaluate(arg)
                    if isinstance(val, SymbolicValue) and val.tainted and node.func.id in DANGEROUS_CALLS:
                        trace = " → ".join(val.path + [node.func.id])
                        fix = FIX_SUGGESTIONS[node.func.id]
                        self.issues.append(f"Code execution path: {trace}\nSuggested fix: {fix}")
                return None

        if isinstance(node, ast.BinOp):
            left = self.evaluate(node.left)
            right = self.evaluate(node.right)
            if isinstance(left, SymbolicValue):
                return left
            if isinstance(right, SymbolicValue):
                return right

        return None


class AnalysisReport:
    def __init__(self, issues):
        self.issues = issues
        self.complexity_metrics = {}
        self.structural_analysis = {}
        self.resolution_predictions = [
            {"issue": i, "suggestion": "Follow the suggested fix.", "convergence": False}
            for i in issues
        ]


class MetaCodeEngine:
    def orchestrate(self, code):
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return AnalysisReport([f"Syntax error: {e}"])

        analyzer = SymbolicAnalyzer()
        analyzer.run(tree)
        return AnalysisReport(analyzer.issues)
