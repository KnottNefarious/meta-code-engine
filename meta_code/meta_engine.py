import ast

# Dangerous execution sinks
DANGEROUS_CALLS = {"eval", "exec"}
DANGEROUS_METHODS = {"system", "popen", "Popen", "run", "call"}


# ---------------- SYMBOLIC VALUE ----------------
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

    def merge(self, other):
        merged = SymbolicValue(self.name, self.tainted or other.tainted, list(self.path))
        merged.path = list(dict.fromkeys(self.path + other.path))
        return merged

    def add_step(self, step):
        self.path.append(step)


# ---------------- SYMBOLIC ANALYZER ----------------
class SymbolicAnalyzer:
    def __init__(self):
        self.symbols = {}
        self.functions = {}
        self.issues = []
        self.symbolic_counter = 0
        self.return_value = None

    def new_symbol(self, source="input"):
        self.symbolic_counter += 1
        return SymbolicValue(f"{source}_{self.symbolic_counter}", tainted=True, path=[source])

    # ---------------- RUN PROGRAM ----------------
    def run(self, tree):
        # collect definitions
        for stmt in tree.body:
            self.execute(stmt)

        # simulate web entrypoints
        for func in self.functions.values():
            saved_symbols = self.symbols
            self.symbols = self.symbols.copy()

            for arg in func.args.args:
                self.symbols[arg.arg] = self.new_symbol("param")

            self.execute_block(func.body)
            self.symbols = saved_symbols

    # ---------------- BLOCK ----------------
    def execute_block(self, statements):
        for stmt in statements:
            if self.execute(stmt) == "return":
                break

    # ---------------- STATEMENTS ----------------
    def execute(self, node):

        if isinstance(node, ast.FunctionDef):
            self.functions[node.name] = node
            return

        if isinstance(node, ast.Return):
            self.return_value = self.evaluate(node.value)
            return "return"

        if isinstance(node, ast.Assign):
            if isinstance(node.targets[0], ast.Name):
                value = self.evaluate(node.value)
                if isinstance(value, SymbolicValue):
                    value.add_step(node.targets[0].id)
                self.symbols[node.targets[0].id] = value
            return

        if isinstance(node, ast.Expr):
            self.evaluate(node.value)
            return

    # ---------------- EXPRESSIONS ----------------
    def evaluate(self, node):

        if node is None:
            return None

        # constants
        if isinstance(node, ast.Constant):
            return node.value

        # variables
        if isinstance(node, ast.Name):
            return self.symbols.get(node.id, None)

        # Flask request sources
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "request":
                return self.new_symbol("request")
            return None

        # function calls
        if isinstance(node, ast.Call):

            # input()
            if isinstance(node.func, ast.Name) and node.func.id == "input":
                return self.new_symbol("input")

            # request.args.get(...)
            if isinstance(node.func, ast.Attribute):

                if isinstance(node.func.value, ast.Attribute):
                    if isinstance(node.func.value.value, ast.Name) and node.func.value.value.id == "request":
                        sym = self.new_symbol("request")
                        sym.add_step(node.func.attr)
                        return sym

                obj = self.evaluate(node.func.value)
                if isinstance(obj, SymbolicValue) and obj.tainted:
                    val = obj.copy()
                    val.add_step(node.func.attr)
                    return val

            # user-defined function call
            if isinstance(node.func, ast.Name) and node.func.id in self.functions:
                func = self.functions[node.func.id]

                saved_symbols = self.symbols
                saved_return = self.return_value

                local_symbols = self.symbols.copy()

                for param, arg in zip(func.args.args, node.args):
                    val = self.evaluate(arg)
                    if isinstance(val, SymbolicValue):
                        val.add_step(f"param:{param.arg}")
                    local_symbols[param.arg] = val

                self.symbols = local_symbols
                self.return_value = None

                self.execute_block(func.body)

                ret = self.return_value

                self.symbols = saved_symbols
                self.return_value = saved_return

                return ret

            # dangerous method calls
            if isinstance(node.func, ast.Attribute):
                method = node.func.attr

                for arg in node.args:
                    val = self.evaluate(arg)

                    if isinstance(val, SymbolicValue) and val.tainted and method in DANGEROUS_METHODS:
                        trace = " → ".join(val.path + [method])
                        self.issues.append(
                            f"Command execution path: {trace}\n"
                            f"Suggested fix: Avoid building shell commands from user input. "
                            f"Use subprocess.run([...], shell=False) with argument lists."
                        )

                return None

            # eval/exec
            if isinstance(node.func, ast.Name) and node.func.id in DANGEROUS_CALLS:
                for arg in node.args:
                    val = self.evaluate(arg)
                    if isinstance(val, SymbolicValue) and val.tainted:
                        trace = " → ".join(val.path + [node.func.id])
                        self.issues.append(
                            f"Code execution path: {trace}\n"
                            f"Suggested fix: Never execute user-controlled code."
                        )
                return None

        # ----------- NEW: STRING CONCATENATION TAINT MERGE -----------
        if isinstance(node, ast.BinOp):
            left = self.evaluate(node.left)
            right = self.evaluate(node.right)

            if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
                return left.merge(right)
            if isinstance(left, SymbolicValue):
                return left
            if isinstance(right, SymbolicValue):
                return right

        return None


# ---------------- REPORT ----------------
class AnalysisReport:
    def __init__(self, issues):
        self.issues = issues
        self.complexity_metrics = {}
        self.structural_analysis = {}
        self.resolution_predictions = []


# ---------------- ENGINE ----------------
class MetaCodeEngine:
    def orchestrate(self, code):
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return AnalysisReport([f"Syntax error: {e}"])

        analyzer = SymbolicAnalyzer()
        analyzer.run(tree)
        return AnalysisReport(analyzer.issues)
