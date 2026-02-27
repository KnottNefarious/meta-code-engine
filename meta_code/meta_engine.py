import ast

MAX_LOOP_ITERATIONS = 10


class SymbolicAnalyzer:
    def __init__(self):
        self.symbols = {
            "print": "builtin",
            "len": "builtin",
            "range": "builtin",
            "int": "builtin",
            "str": "builtin",
            "float": "builtin"
        }

        self.functions = {}
        self.issues = []

    def clone(self):
        new = SymbolicAnalyzer()
        new.symbols = self.symbols.copy()
        new.functions = self.functions
        return new

    def run(self, tree):
        for stmt in tree.body:
            self.execute(stmt)

    # ---------- statement execution ----------
    def execute(self, node):

        # function definition
        if isinstance(node, ast.FunctionDef):
            self.functions[node.name] = node
            return

        # assignment
        if isinstance(node, ast.Assign):
            if isinstance(node.targets[0], ast.Name):
                value = self.evaluate(node.value)
                self.symbols[node.targets[0].id] = value
            return

        # expression
        if isinstance(node, ast.Expr):
            self.evaluate(node.value)
            return

        # ----------- PATH SPLITTING IF -----------
        if isinstance(node, ast.If):

            condition = self.evaluate(node.test)

            # known true
            if condition is True:
                for stmt in node.body:
                    self.execute(stmt)
                return

            # known false
            if condition is False:
                for stmt in node.orelse:
                    self.execute(stmt)
                return

            # UNKNOWN → SPLIT REALITY
            true_branch = self.clone()
            false_branch = self.clone()

            for stmt in node.body:
                true_branch.execute(stmt)

            for stmt in node.orelse:
                false_branch.execute(stmt)

            # merge issues
            self.issues.extend(true_branch.issues)
            self.issues.extend(false_branch.issues)

            return

        # ----------- WHILE LOOP -----------
        if isinstance(node, ast.While):
            iteration = 0

            while iteration < MAX_LOOP_ITERATIONS:

                cond = self.evaluate(node.test)

                if cond is False:
                    return

                previous = self.symbols.copy()

                for stmt in node.body:
                    self.execute(stmt)

                if previous == self.symbols:
                    self.issues.append("Possible infinite loop (state unchanged)")
                    return

                iteration += 1

            self.issues.append("Loop exceeded reasoning depth")
            return

    # ---------- expression evaluation ----------
    def evaluate(self, node):

        if isinstance(node, ast.Constant):
            return node.value

        if isinstance(node, ast.Name):
            if node.id not in self.symbols:
                self.issues.append(f"Variable '{node.id}' used before assignment")
                return None
            return self.symbols[node.id]

        if isinstance(node, ast.BinOp):
            l = self.evaluate(node.left)
            r = self.evaluate(node.right)
            if l is not None and r is not None:
                try:
                    if isinstance(node.op, ast.Add):
                        return l + r
                    if isinstance(node.op, ast.Sub):
                        return l - r
                    if isinstance(node.op, ast.Mult):
                        return l * r
                    if isinstance(node.op, ast.Div):
                        return l / r
                except Exception:
                    self.issues.append("Invalid arithmetic types")
                    return None

        if isinstance(node, ast.Compare):
            l = self.evaluate(node.left)
            r = self.evaluate(node.comparators[0])
            if l is not None and r is not None:
                op = node.ops[0]
                if isinstance(op, ast.Eq):
                    return l == r
                if isinstance(op, ast.NotEq):
                    return l != r
                if isinstance(op, ast.Gt):
                    return l > r
                if isinstance(op, ast.Lt):
                    return l < r
                if isinstance(op, ast.GtE):
                    return l >= r
                if isinstance(op, ast.LtE):
                    return l <= r

        if isinstance(node, ast.Call):
            for arg in node.args:
                self.evaluate(arg)
            return None

        return None


class AnalysisReport:
    def __init__(self, issues):
        self.issues = issues
        self.complexity_metrics = {}
        self.structural_analysis = {}
        self.resolution_predictions = [{"issue": i, "suggestion": "Review code", "convergence": False} for i in issues]


class MetaCodeEngine:
    def orchestrate(self, code):
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return AnalysisReport([f"Syntax error: {e}"])

        analyzer = SymbolicAnalyzer()
        analyzer.run(tree)
        return AnalysisReport(analyzer.issues)
