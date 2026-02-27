import ast

# Dangerous execution sinks
DANGEROUS_CALLS = {"eval", "exec"}
DANGEROUS_METHODS = {"system", "popen", "Popen"}


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

    def add_step(self, step):
        self.path.append(step)


# ---------------- SYMBOLIC ANALYZER ----------------
class SymbolicAnalyzer:
    def __init__(self):
        self.symbols = {}
        self.functions = {}
        self.issues = []
        self.symbolic_counter = 0

    # create attacker-controlled symbolic value
    def new_symbol(self, source="input"):
        self.symbolic_counter += 1
        return SymbolicValue(f"{source}_{self.symbolic_counter}", tainted=True, path=[source])

    # ---------------- RUN PROGRAM ----------------
    def run(self, tree):
        # First pass: collect globals & functions
        for stmt in tree.body:
            self.execute(stmt)

        # Second pass: simulate calling all functions
        # (represents web framework calling route handlers)
        for func in self.functions.values():
            saved_symbols = self.symbols
            self.symbols = self.symbols.copy()

            # parameters are unknown user-controlled values
            for arg in func.args.args:
                self.symbols[arg.arg] = self.new_symbol("param")

            for stmt in func.body:
                self.execute(stmt)

            self.symbols = saved_symbols

    # ---------------- STATEMENTS ----------------
    def execute(self, node):

        # collect function definitions
        if isinstance(node, ast.FunctionDef):
            self.functions[node.name] = node
            return

        # assignment
        if isinstance(node, ast.Assign):
            if isinstance(node.targets[0], ast.Name):
                value = self.evaluate(node.value)
                if isinstance(value, SymbolicValue):
                    value.add_step(node.targets[0].id)
                self.symbols[node.targets[0].id] = value
            return

        # expression
        if isinstance(node, ast.Expr):
            self.evaluate(node.value)
            return

    # ---------------- EXPRESSIONS ----------------
    def evaluate(self, node):

        # constants
        if isinstance(node, ast.Constant):
            return node.value

        # variable lookup
        if isinstance(node, ast.Name):
            return self.symbols.get(node.id, None)

        # ---------- ATTRIBUTE ACCESS ----------
        if isinstance(node, ast.Attribute):

            # Flask request.* is attacker input
            if isinstance(node.value, ast.Name) and node.value.id == "request":
                return self.new_symbol("request")

            return None

        # ---------- CALLS ----------
        if isinstance(node, ast.Call):

            # input()
            if isinstance(node.func, ast.Name) and node.func.id == "input":
                return self.new_symbol("input")

            # request.args.get(...)
            if isinstance(node.func, ast.Attribute):

                # direct request access
                if isinstance(node.func.value, ast.Attribute):
                    if isinstance(node.func.value.value, ast.Name) and node.func.value.value.id == "request":
                        sym = self.new_symbol("request")
                        sym.add_step(node.func.attr)
                        return sym

                # propagate .get() from tainted object
                obj = self.evaluate(node.func.value)
                if isinstance(obj, SymbolicValue) and obj.tainted:
                    val = obj.copy()
                    val.add_step(node.func.attr)
                    return val

            # ---------- dangerous methods (os.system) ----------
            if isinstance(node.func, ast.Attribute):
                method = node.func.attr

                for arg in node.args:
                    val = self.evaluate(arg)

                    if isinstance(val, SymbolicValue) and val.tainted and method in DANGEROUS_METHODS:
                        trace = " → ".join(val.path + [method])
                        self.issues.append(
                            f"Command execution path: {trace}\n"
                            f"Suggested fix: Do not pass user input into system commands. "
                            f"Use subprocess.run([...], shell=False) and validate input."
                        )

                return None

            # ---------- eval / exec ----------
            if isinstance(node.func, ast.Name) and node.func.id in DANGEROUS_CALLS:
                for arg in node.args:
                    val = self.evaluate(arg)
                    if isinstance(val, SymbolicValue) and val.tainted:
                        trace = " → ".join(val.path + [node.func.id])
                        self.issues.append(
                            f"Code execution path: {trace}\n"
                            f"Suggested fix: Never execute user-controlled code. Remove eval/exec usage."
                        )
                return None

        # propagate taint through expressions
        if isinstance(node, ast.BinOp):
            left = self.evaluate(node.left)
            right = self.evaluate(node.right)
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
