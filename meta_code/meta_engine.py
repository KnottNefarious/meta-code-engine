import ast

MAX_LOOP_ITERATIONS = 8
DANGEROUS_CALLS = {"eval", "exec", "os.system"}


class SymbolicValue:
    def __init__(self, name, tainted=False):
        self.name = name
        self.non_zero = False
        self.tainted = tainted

    def __repr__(self):
        return f"Symbolic({self.name}, tainted={self.tainted})"


class SymbolicAnalyzer:
    def __init__(self):
        self.symbols = {}
        self.functions = {}
        self.issues = []
        self.symbolic_counter = 0

    def new_symbol(self):
        self.symbolic_counter += 1
        return SymbolicValue(f"input_{self.symbolic_counter}", tainted=True)

    def clone(self):
        new = SymbolicAnalyzer()
        new.symbols = {k: v for k, v in self.symbols.items()}
        new.functions = self.functions
        new.symbolic_counter = self.symbolic_counter
        return new

    def run(self, tree):
        for stmt in tree.body:
            self.execute(stmt)

    # ---------------- statements ----------------
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

        # if privilege check
        if isinstance(node, ast.If):
            if isinstance(node.test, ast.Compare):
                left = node.test.left
                right = node.test.comparators[0]
                op = node.test.ops[0]

                if (
                    isinstance(left, ast.Name)
                    and isinstance(right, ast.Constant)
                    and isinstance(right.value, str)
                    and isinstance(op, ast.Eq)
                ):
                    sym = self.symbols.get(left.id)
                    if isinstance(sym, SymbolicValue) and sym.tainted:
                        self.issues.append(
                            f"Tainted input can equal '{right.value}' → authentication bypass possible"
                        )

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

        # ---------- function calls ----------
        if isinstance(node, ast.Call):

            # SOURCE
            if isinstance(node.func, ast.Name) and node.func.id == "input":
                return self.new_symbol()

            # propagate through int()
            if isinstance(node.func, ast.Name) and node.func.id == "int":
                val = self.evaluate(node.args[0])
                return val

            # ---------- user defined function ----------
            if isinstance(node.func, ast.Name) and node.func.id in self.functions:

                func = self.functions[node.func.id]

                # create local scope
                local_symbols = self.symbols.copy()

                # map arguments to parameters
                for param, arg in zip(func.args.args, node.args):
                    arg_value = self.evaluate(arg)
                    local_symbols[param.arg] = arg_value

                # run function body with local scope
                saved_symbols = self.symbols
                self.symbols = local_symbols

                for stmt in func.body:
                    self.execute(stmt)

                self.symbols = saved_symbols
                return None

            # ---------- sink detection ----------
            if isinstance(node.func, ast.Name):
                func_name = node.func.id

                if func_name in DANGEROUS_CALLS:
                    for arg in node.args:
                        val = self.evaluate(arg)
                        if isinstance(val, SymbolicValue) and val.tainted:
                            self.issues.append(
                                f"Tainted input reaches dangerous function '{func_name}' → code execution path found"
                            )
                return None

            # print
            if isinstance(node.func, ast.Name) and node.func.id == "print":
                for arg in node.args:
                    self.evaluate(arg)
                return None

        # arithmetic
        if isinstance(node, ast.BinOp):
            left = self.evaluate(node.left)
            right = self.evaluate(node.right)

            if isinstance(node.op, ast.Div):
                if right == 0:
                    self.issues.append("Guaranteed division by zero")
                if isinstance(right, SymbolicValue) and not right.non_zero:
                    self.issues.append("Possible division by zero")

            if isinstance(left, SymbolicValue) or isinstance(right, SymbolicValue):
                return SymbolicValue("expr", tainted=True)

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
