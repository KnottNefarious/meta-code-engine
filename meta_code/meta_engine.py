import ast

MAX_LOOP_ITERATIONS = 8


# ---------- Symbolic Value ----------
class SymbolicValue:
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return f"Symbolic({self.name})"


# ---------- Analyzer ----------
class SymbolicAnalyzer:
    def __init__(self):
        self.symbols = {}
        self.functions = {}
        self.issues = []
        self.symbolic_counter = 0

    def new_symbol(self):
        self.symbolic_counter += 1
        return SymbolicValue(f"input_{self.symbolic_counter}")

    def clone(self):
        new = SymbolicAnalyzer()
        new.symbols = self.symbols.copy()
        new.functions = self.functions
        new.symbolic_counter = self.symbolic_counter
        return new

    def run(self, tree):
        for stmt in tree.body:
            self.execute(stmt)

    # ---------------- statements ----------------
    def execute(self, node):

        if isinstance(node, ast.FunctionDef):
            self.functions[node.name] = node
            return

        if isinstance(node, ast.Assign):
            if isinstance(node.targets[0], ast.Name):
                value = self.evaluate(node.value)
                self.symbols[node.targets[0].id] = value
            return

        if isinstance(node, ast.Expr):
            self.evaluate(node.value)
            return

        # IF with path splitting
        if isinstance(node, ast.If):
            cond = self.evaluate(node.test)

            if cond is True:
                for s in node.body:
                    self.execute(s)
                return

            if cond is False:
                for s in node.orelse:
                    self.execute(s)
                return

            # symbolic branch split
            true_branch = self.clone()
            false_branch = self.clone()

            for s in node.body:
                true_branch.execute(s)

            for s in node.orelse:
                false_branch.execute(s)

            self.issues.extend(true_branch.issues)
            self.issues.extend(false_branch.issues)
            return

        # WHILE bounded symbolic
        if isinstance(node, ast.While):
            for _ in range(MAX_LOOP_ITERATIONS):
                cond = self.evaluate(node.test)
                if cond is False:
                    return

                previous = self.symbols.copy()

                for s in node.body:
                    self.execute(s)

                if previous == self.symbols:
                    self.issues.append("Possible infinite loop")
                    return

            self.issues.append("Loop reasoning limit reached")
            return

    # ---------------- expressions ----------------
    def evaluate(self, node):

        # constants
        if isinstance(node, ast.Constant):
            return node.value

        # variable
        if isinstance(node, ast.Name):
            if node.id not in self.symbols:
                self.issues.append(f"Variable '{node.id}' used before assignment")
                return None
            return self.symbols[node.id]

        # binary operations
        if isinstance(node, ast.BinOp):
            left = self.evaluate(node.left)
            right = self.evaluate(node.right)

            # division by zero detection
            if isinstance(node.op, ast.Div):
                if right == 0:
                    self.issues.append("Guaranteed division by zero")
                if isinstance(right, SymbolicValue):
                    self.issues.append("Possible division by zero")

            if isinstance(left, SymbolicValue) or isinstance(right, SymbolicValue):
                return SymbolicValue("expr")

            try:
                if isinstance(node.op, ast.Add):
                    return left + right
                if isinstance(node.op, ast.Sub):
                    return left - right
                if isinstance(node.op, ast.Mult):
                    return left * right
                if isinstance(node.op, ast.Div):
                    return left / right
            except Exception:
                self.issues.append("Invalid arithmetic types")
                return None

        # comparisons
        if isinstance(node, ast.Compare):
            left = self.evaluate(node.left)
            right = self.evaluate(node.comparators[0])

            if isinstance(left, SymbolicValue) or isinstance(right, SymbolicValue):
                return None

            op = node.ops[0]
            if isinstance(op, ast.Eq):
                return left == right
            if isinstance(op, ast.NotEq):
                return left != right
            if isinstance(op, ast.Gt):
                return left > right
            if isinstance(op, ast.Lt):
                return left < right
            if isinstance(op, ast.GtE):
                return left >= right
            if isinstance(op, ast.LtE):
                return left <= right

        # function calls
        if isinstance(node, ast.Call):

            # input() becomes symbolic variable
            if isinstance(node.func, ast.Name) and node.func.id == "input":
                return self.new_symbol()

            # int(symbolic)
            if isinstance(node.func, ast.Name) and node.func.id == "int":
                val = self.evaluate(node.args[0])
                if isinstance(val, SymbolicValue):
                    return SymbolicValue("int_input")
                return int(val)

            # print
            if isinstance(node.func, ast.Name) and node.func.id == "print":
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
