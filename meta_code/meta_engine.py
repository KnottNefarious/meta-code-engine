import ast

MAX_LOOP_ITERATIONS = 8


class SymbolicValue:
    def __init__(self, name):
        self.name = name
        self.non_zero = False

    def __repr__(self):
        return f"Symbolic({self.name})"


class SymbolicAnalyzer:
    def __init__(self):
        self.symbols = {}
        self.issues = []
        self.symbolic_counter = 0

    def new_symbol(self):
        self.symbolic_counter += 1
        return SymbolicValue(f"input_{self.symbolic_counter}")

    def clone(self):
        new = SymbolicAnalyzer()
        new.symbols = {k: v for k, v in self.symbols.items()}
        new.symbolic_counter = self.symbolic_counter
        return new

    def run(self, tree):
        for stmt in tree.body:
            self.execute(stmt)

    # ---------------- statements ----------------
    def execute(self, node):

        # assignment
        if isinstance(node, ast.Assign):
            if isinstance(node.targets[0], ast.Name):
                self.symbols[node.targets[0].id] = self.evaluate(node.value)
            return

        # expression
        if isinstance(node, ast.Expr):
            self.evaluate(node.value)
            return

        # -------- IF with constraint tracking --------
        if isinstance(node, ast.If):

            # detect x != 0
            if isinstance(node.test, ast.Compare):
                left = node.test.left
                right = node.test.comparators[0]

                if (
                    isinstance(left, ast.Name)
                    and isinstance(right, ast.Constant)
                    and right.value == 0
                    and isinstance(node.test.ops[0], ast.NotEq)
                ):
                    true_branch = self.clone()
                    false_branch = self.clone()

                    sym = true_branch.symbols.get(left.id)
                    if isinstance(sym, SymbolicValue):
                        sym.non_zero = True

                    for s in node.body:
                        true_branch.execute(s)
                    for s in node.orelse:
                        false_branch.execute(s)

                    self.issues.extend(true_branch.issues)
                    self.issues.extend(false_branch.issues)
                    return

            # generic split
            true_branch = self.clone()
            false_branch = self.clone()

            for s in node.body:
                true_branch.execute(s)
            for s in node.orelse:
                false_branch.execute(s)

            self.issues.extend(true_branch.issues)
            self.issues.extend(false_branch.issues)
            return

    # ---------------- expressions ----------------
    def evaluate(self, node):

        if isinstance(node, ast.Constant):
            return node.value

        if isinstance(node, ast.Name):
            if node.id not in self.symbols:
                self.issues.append(f"Variable '{node.id}' used before assignment")
                return None
            return self.symbols[node.id]

        # input() -> symbolic
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "input":
                return self.new_symbol()

            if isinstance(node.func, ast.Name) and node.func.id == "int":
                val = self.evaluate(node.args[0])
                if isinstance(val, SymbolicValue):
                    return val
                return int(val)

            if isinstance(node.func, ast.Name) and node.func.id == "print":
                for arg in node.args:
                    self.evaluate(arg)
                return None

        # -------- symbolic arithmetic --------
        if isinstance(node, ast.BinOp):
            left = self.evaluate(node.left)
            right = self.evaluate(node.right)

            # division safety reasoning
            if isinstance(node.op, ast.Div):
                if right == 0:
                    self.issues.append("Guaranteed division by zero")

                if isinstance(right, SymbolicValue) and not right.non_zero:
                    self.issues.append("Possible division by zero")

            # IMPORTANT FIX:
            # If either side is symbolic → return symbolic result (DO NOT COMPUTE)
            if isinstance(left, SymbolicValue) or isinstance(right, SymbolicValue):
                return SymbolicValue("expr")

            # only compute real numbers
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if isinstance(node.op, ast.Div):
                return left / right

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
