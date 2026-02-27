import ast
import zlib

MAX_LOOP_ITERATIONS = 12


class SymbolicAnalyzer:
    def __init__(self):
        self.symbols = {
            "print": "builtin",
            "len": "builtin",
            "range": "builtin",
            "int": "builtin",
            "str": "builtin",
            "float": "builtin",
            "list": "builtin",
            "dict": "builtin",
            "set": "builtin",
            "bool": "builtin",
            "abs": "builtin",
            "min": "builtin",
            "max": "builtin",
            "sum": "builtin"
        }

        self.functions = {}
        self.issues = []

    def run(self, tree):
        for stmt in tree.body:
            self.execute(stmt)

    # ---------------- statements ----------------
    def execute(self, node):

        # function definitions
        if isinstance(node, ast.FunctionDef):
            self.functions[node.name] = node
            return

        # assignment
        if isinstance(node, ast.Assign):
            if isinstance(node.targets[0], ast.Name):
                name = node.targets[0].id
                value = self.evaluate(node.value)
                self.symbols[name] = value
            return

        # expression
        if isinstance(node, ast.Expr):
            self.evaluate(node.value)
            return

        # if
        if isinstance(node, ast.If):
            condition = self.evaluate(node.test)

            if condition is True:
                self.issues.append("If condition is always TRUE")
                for stmt in node.body:
                    self.execute(stmt)

            elif condition is False:
                self.issues.append("If condition is always FALSE")
                for stmt in node.orelse:
                    self.execute(stmt)

            else:
                saved = self.symbols.copy()
                for stmt in node.body:
                    self.execute(stmt)
                self.symbols = saved
                for stmt in node.orelse:
                    self.execute(stmt)
            return

        # ----------- FIXED WHILE LOOP -----------
        if isinstance(node, ast.While):

            iteration = 0
            last_condition = None

            while iteration < MAX_LOOP_ITERATIONS:

                condition = self.evaluate(node.test)

                # loop exits
                if condition is False:
                    return

                # true forever detection
                if condition is True and last_condition is True and iteration > 3:
                    self.issues.append("Possible infinite loop: condition never becomes FALSE")
                    return

                last_condition = condition

                # execute body
                previous_state = self.symbols.copy()
                for stmt in node.body:
                    self.execute(stmt)

                # detect no change
                if previous_state == self.symbols:
                    self.issues.append("Possible infinite loop: loop body does not modify state")
                    return

                iteration += 1

            self.issues.append("Loop exceeded symbolic reasoning depth (possible unbounded loop)")
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

        if isinstance(node, ast.BinOp):
            left = self.evaluate(node.left)
            right = self.evaluate(node.right)
            if left is not None and right is not None:
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
                    self.issues.append("Invalid arithmetic operation between incompatible types")
                    return None

        if isinstance(node, ast.Compare):
            left = self.evaluate(node.left)
            right = self.evaluate(node.comparators[0])
            if left is not None and right is not None:
                op = node.ops[0]
                if isinstance(op, ast.Gt):
                    return left > right
                if isinstance(op, ast.Lt):
                    return left < right
                if isinstance(op, ast.Eq):
                    return left == right
                if isinstance(op, ast.NotEq):
                    return left != right
                if isinstance(op, ast.GtE):
                    return left >= right
                if isinstance(op, ast.LtE):
                    return left <= right

        if isinstance(node, ast.Call):

            # builtin
            if isinstance(node.func, ast.Name) and node.func.id in self.symbols:
                for arg in node.args:
                    self.evaluate(arg)
                return None

            # user function
            if isinstance(node.func, ast.Name) and node.func.id in self.functions:
                func = self.functions[node.func.id]

                local = self.symbols.copy()
                for param, arg in zip(func.args.args, node.args):
                    local[param.arg] = self.evaluate(arg)

                saved = self.symbols
                self.symbols = local

                ret = None
                for stmt in func.body:
                    if isinstance(stmt, ast.Return):
                        ret = self.evaluate(stmt.value)
                        break
                    else:
                        self.execute(stmt)

                self.symbols = saved
                return ret

        return None


class AnalysisReport:
    def __init__(self, issues, complexity_metrics, structural_analysis, resolution_predictions):
        self.issues = issues
        self.complexity_metrics = complexity_metrics
        self.structural_analysis = structural_analysis
        self.resolution_predictions = resolution_predictions


class MetaCodeEngine:
    def orchestrate(self, code):
        issues = []
        resolution_predictions = []

        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            issues.append(f"Syntax error: {e}")
            return AnalysisReport(issues, {}, {}, [])

        analyzer = SymbolicAnalyzer()
        analyzer.run(tree)
        issues.extend(analyzer.issues)

        complexity_metrics = {"lines": len(code.splitlines())}
        structural_analysis = {}

        if not issues:
            resolution_predictions.append({
                "issue": "No major problems detected",
                "suggestion": "Code structure appears valid.",
                "convergence": True
            })
        else:
            for issue in issues:
                resolution_predictions.append({
                    "issue": issue,
                    "suggestion": "Review this section of the code.",
                    "convergence": False
                })

        return AnalysisReport(issues, complexity_metrics, structural_analysis, resolution_predictions)
