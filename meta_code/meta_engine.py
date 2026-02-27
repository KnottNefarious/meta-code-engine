import ast

DANGEROUS_CALLS = {"eval", "exec"}
DANGEROUS_METHODS = {"system", "popen", "Popen"}
SQL_SINKS = {"execute", "executemany"}


class SymbolicValue:
    def __init__(self, name, tainted=False):
        self.name = name
        self.tainted = tainted
        self.attributes = {}

    def copy(self):
        new = SymbolicValue(self.name, self.tainted)
        new.attributes = dict(self.attributes)
        return new

    def __repr__(self):
        return f"Symbolic({self.name}, tainted={self.tainted})"


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
                if isinstance(obj, SymbolicValue):
                    obj.attributes[node.targets[0].attr] = value
                return

            if isinstance(node.targets[0], ast.Name):
                self.symbols[node.targets[0].id] = self.evaluate(node.value)
            return

        if isinstance(node, ast.If):

            # allowlist validation
            if isinstance(node.test, ast.Compare):
                left = node.test.left
                op = node.test.ops[0]
                right = node.test.comparators[0]

                if (
                    isinstance(left, ast.Name)
                    and isinstance(op, ast.In)
                    and isinstance(right, (ast.List, ast.Tuple))
                ):
                    true_branch = self.clone()
                    false_branch = self.clone()

                    sym = true_branch.symbols.get(left.id)
                    if isinstance(sym, SymbolicValue):
                        sym.tainted = False

                    for s in node.body:
                        true_branch.execute(s)

                    for s in node.orelse:
                        false_branch.execute(s)

                    self.issues.extend(true_branch.issues)
                    self.issues.extend(false_branch.issues)
                    return

            true_branch = self.clone()
            false_branch = self.clone()

            for s in node.body:
                true_branch.execute(s)
            for s in node.orelse:
                false_branch.execute(s)

            self.issues.extend(true_branch.issues)
            self.issues.extend(false_branch.issues)
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
                return obj.attributes.get(node.attr, None)
            return None

        # ---------- CALLS ----------
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
                    local[param.arg] = self.evaluate(arg)

                self.symbols = local
                for stmt in func.body:
                    self.execute(stmt)
                self.symbols = saved
                return None

            # ---------- ATTRIBUTE CALL (MOST IMPORTANT FIX) ----------
            if isinstance(node.func, ast.Attribute):
                method = node.func.attr

                for arg in node.args:
                    val = self.evaluate(arg)

                    if method in SQL_SINKS and isinstance(val, SymbolicValue) and val.tainted:
                        self.issues.append("SQL injection risk: tainted data in database query")

                    if method in DANGEROUS_METHODS and isinstance(val, SymbolicValue) and val.tainted:
                        self.issues.append(f"Tainted data reaches '{method}' → command execution risk")
                return None

            # DIRECT DANGEROUS
            if isinstance(node.func, ast.Name):
                for arg in node.args:
                    val = self.evaluate(arg)
                    if node.func.id in DANGEROUS_CALLS and isinstance(val, SymbolicValue) and val.tainted:
                        self.issues.append(f"Tainted data reaches '{node.func.id}' → code execution risk")
                return None

        # taint propagation
        if isinstance(node, ast.BinOp):
            left = self.evaluate(node.left)
            right = self.evaluate(node.right)
            if isinstance(left, SymbolicValue) or isinstance(right, SymbolicValue):
                return SymbolicValue("expr", tainted=True)

        return None


class AnalysisReport:
    def __init__(self, issues):
        self.issues = issues
        self.complexity_metrics = {}
        self.structural_analysis = {}
        self.resolution_predictions = [
            {"issue": i, "suggestion": "Review code", "convergence": False}
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
