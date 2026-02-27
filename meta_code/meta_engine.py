import ast

DANGEROUS_CALLS = {"eval", "exec"}
OS_COMMAND_METHODS = {"system", "popen"}
SUBPROCESS_METHODS = {"Popen", "run", "call"}
SQL_METHODS = {"execute", "executemany"}
DESERIALIZE_METHODS = {"loads", "load"}  # pickle, yaml, marshal
REQUEST_CONTAINERS = {"args", "form", "json", "values", "headers", "cookies", "data"}


class SymbolicValue:
    def __init__(self, name, tainted=False, path=None, class_name=None):
        self.name = name
        self.tainted = tainted
        self.path = path or [name]
        self.class_name = class_name

    def copy(self):
        return SymbolicValue(self.name, self.tainted, list(self.path), self.class_name)

    def merge(self, other):
        merged = SymbolicValue(self.name, self.tainted or other.tainted, list(self.path), self.class_name)
        merged.path = list(dict.fromkeys(self.path + other.path))
        return merged

    def add_step(self, step):
        self.path.append(step)


class SymbolicAnalyzer:
    def __init__(self):
        self.symbols = {}
        self.functions = {}
        self.classes = {}
        self.issues = []
        self.symbolic_counter = 0
        self.return_value = None

    def new_symbol(self, source="input"):
        self.symbolic_counter += 1
        return SymbolicValue(f"{source}_{self.symbolic_counter}", True, [source])

    def run(self, tree):
        for stmt in tree.body:
            self.execute(stmt)

        for func in self.functions.values():
            saved = self.symbols
            self.symbols = self.symbols.copy()

            for arg in func.args.args:
                self.symbols[arg.arg] = self.new_symbol("param")

            self.execute_block(func.body)
            self.symbols = saved

    def execute_block(self, body):
        for stmt in body:
            if self.execute(stmt) == "return":
                break

    def execute(self, node):

        if isinstance(node, ast.FunctionDef):
            self.functions[node.name] = node
            return

        if isinstance(node, ast.ClassDef):
            self.classes[node.name] = node
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

    def is_request_container(self, node):
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "request":
                if node.attr in REQUEST_CONTAINERS:
                    return True
        return False

    def execute_method(self, obj, method_name, args):
        if obj.class_name not in self.classes:
            return None

        class_node = self.classes[obj.class_name]

        for item in class_node.body:
            if isinstance(item, ast.FunctionDef) and item.name == method_name:

                saved_symbols = self.symbols
                saved_return = self.return_value

                local = {}
                local["self"] = obj

                params = item.args.args[1:]
                for param, arg in zip(params, args):
                    val = self.evaluate(arg)
                    if isinstance(val, SymbolicValue):
                        val.add_step(f"param:{param.arg}")
                    local[param.arg] = val

                self.symbols = local
                self.return_value = None

                self.execute_block(item.body)

                ret = self.return_value

                self.symbols = saved_symbols
                self.return_value = saved_return

                return ret

    def evaluate(self, node):

        if node is None:
            return None

        if isinstance(node, ast.Constant):
            return node.value

        if isinstance(node, ast.Name):
            return self.symbols.get(node.id, None)

        # class instantiation
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in self.classes:
                return SymbolicValue(node.func.id, False, [node.func.id], class_name=node.func.id)

        # request containers
        if self.is_request_container(node):
            return self.new_symbol("request")

        if isinstance(node, ast.Call):

            # input()
            if isinstance(node.func, ast.Name) and node.func.id == "input":
                return self.new_symbol("input")

            # request.args.get(...)
            if isinstance(node.func, ast.Attribute):
                if self.is_request_container(node.func.value):
                    sym = self.new_symbol("request")
                    sym.add_step(node.func.attr)
                    return sym

                obj = self.evaluate(node.func.value)

                if isinstance(obj, SymbolicValue) and obj.class_name:
                    ret = self.execute_method(obj, node.func.attr, node.args)
                    if ret:
                        return ret

                method = node.func.attr

                shell_true = any(
                    kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in node.keywords
                )

                for arg in node.args:
                    val = self.evaluate(arg)

                    # command injection
                    if isinstance(val, SymbolicValue) and val.tainted and method in OS_COMMAND_METHODS:
                        trace = " → ".join(val.path + [method])
                        self.issues.append(f"Command execution path: {trace}")

                    if isinstance(val, SymbolicValue) and val.tainted and method in SUBPROCESS_METHODS and shell_true:
                        trace = " → ".join(val.path + ["subprocess(shell=True)"])
                        self.issues.append(f"Shell injection path: {trace}")

                    # SQL injection
                    if isinstance(val, SymbolicValue) and val.tainted and method in SQL_METHODS:
                        trace = " → ".join(val.path + ["SQL execute"])
                        self.issues.append(f"SQL injection path: {trace}")

                    # DESERIALIZATION RCE
                    if isinstance(val, SymbolicValue) and val.tainted and method in DESERIALIZE_METHODS:
                        trace = " → ".join(val.path + ["unsafe deserialization"])
                        self.issues.append(f"Deserialization RCE path: {trace}")

                return None

        # string taint
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


class AnalysisReport:
    def __init__(self, issues):
        self.issues = issues
        self.complexity_metrics = {}
        self.structural_analysis = {}
        self.resolution_predictions = []


class MetaCodeEngine:
    def orchestrate(self, code):
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return AnalysisReport([f"Syntax error: {e}"])

        analyzer = SymbolicAnalyzer()
        analyzer.run(tree)
        return AnalysisReport(analyzer.issues)
