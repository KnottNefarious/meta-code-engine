import ast

DANGEROUS_CALLS = {"eval", "exec", "os.system"}
SQL_SINKS = {"execute", "executemany"}


class SymbolicValue:
    def __init__(self, name, tainted=False):
        self.name = name
        self.tainted = tainted
        self.attributes = {}

    def __repr__(self):
        return f"Symbolic({self.name}, tainted={self.tainted})"


class SymbolicAnalyzer:
    def __init__(self):
        self.symbols = {}
        self.functions = {}
        self.classes = {}   # NEW: store class definitions
        self.issues = []
        self.symbolic_counter = 0

    def new_symbol(self):
        self.symbolic_counter += 1
        return SymbolicValue(f"input_{self.symbolic_counter}", tainted=True)

    def clone(self):
        new = SymbolicAnalyzer()
        new.symbols = {k: v for k, v in self.symbols.items()}
        new.functions = self.functions
        new.classes = self.classes
        new.symbolic_counter = self.symbolic_counter
        return new

    def run(self, tree):
        for stmt in tree.body:
            self.execute(stmt)

    # ---------------- statements ----------------
    def execute(self, node):

        # register classes
        if isinstance(node, ast.ClassDef):
            self.classes[node.name] = node
            return

        # register functions
        if isinstance(node, ast.FunctionDef):
            self.functions[node.name] = node
            return

        # assignment
        if isinstance(node, ast.Assign):

            # attribute assignment
            if isinstance(node.targets[0], ast.Attribute):
                obj = self.evaluate(node.targets[0].value)
                value = self.evaluate(node.value)

                if isinstance(obj, SymbolicValue):
                    obj.attributes[node.targets[0].attr] = value
                return

            # variable assignment
            if isinstance(node.targets[0], ast.Name):
                self.symbols[node.targets[0].id] = self.evaluate(node.value)
            return

        # expression
        if isinstance(node, ast.Expr):
            self.evaluate(node.value)
            return

    # ---------------- expressions ----------------
    def evaluate(self, node):

        if isinstance(node, ast.Constant):
            return node.value

        # variable
        if isinstance(node, ast.Name):
            return self.symbols.get(node.id, None)

        # attribute access
        if isinstance(node, ast.Attribute):
            obj = self.evaluate(node.value)
            if isinstance(obj, SymbolicValue):
                return obj.attributes.get(node.attr, None)
            return None

        # ---------- function / class calls ----------
        if isinstance(node, ast.Call):

            # input source
            if isinstance(node.func, ast.Name) and node.func.id == "input":
                return self.new_symbol()

            # ---------- CLASS INSTANTIATION ----------
            if isinstance(node.func, ast.Name) and node.func.id in self.classes:
                class_def = self.classes[node.func.id]

                obj = SymbolicValue(node.func.id)

                # execute __init__
                for stmt in class_def.body:
                    if isinstance(stmt, ast.FunctionDef) and stmt.name == "__init__":

                        saved_symbols = self.symbols
                        local_symbols = self.symbols.copy()
                        local_symbols["self"] = obj
                        self.symbols = local_symbols

                        for init_stmt in stmt.body:
                            self.execute(init_stmt)

                        self.symbols = saved_symbols

                return obj

            # ---------- SQL sink ----------
            if isinstance(node.func, ast.Attribute):
                method = node.func.attr
                for arg in node.args:
                    val = self.evaluate(arg)

                    if method in SQL_SINKS and isinstance(val, SymbolicValue) and val.tainted:
                        self.issues.append("SQL injection risk: tainted data in database query")

                    if method in DANGEROUS_CALLS and isinstance(val, SymbolicValue) and val.tainted:
                        self.issues.append(f"Tainted data reaches '{method}' → code execution risk")
                return None

            # direct dangerous calls
            if isinstance(node.func, ast.Name):
                for arg in node.args:
                    val = self.evaluate(arg)
                    if node.func.id in DANGEROUS_CALLS and isinstance(val, SymbolicValue) and val.tainted:
                        self.issues.append(
                            f"Tainted data reaches '{node.func.id}' → code execution risk"
                        )
                return None

        # binary operations propagate taint
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
