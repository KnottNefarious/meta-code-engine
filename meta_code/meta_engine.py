import ast
import zlib


# ---------- Symbolic Reasoning Layer ----------
class SymbolicAnalyzer(ast.NodeVisitor):
    def __init__(self):
        # Preloaded Python built-ins
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
        self.issues = []

    # Track assignments
    def visit_Assign(self, node):
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            value = self.evaluate(node.value)
            self.symbols[name] = value
        self.generic_visit(node)

    # Detect use before assignment
    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load):
            if node.id not in self.symbols:
                self.issues.append(f"Variable '{node.id}' used before assignment")

    # Detect pointless conditions
    def visit_If(self, node):
        condition = self.evaluate(node.test)

        if condition is True:
            self.issues.append("If condition is always TRUE")
        elif condition is False:
            self.issues.append("If condition is always FALSE")

        self.generic_visit(node)

    # Evaluate expressions
    def evaluate(self, node):

        # constants
        if isinstance(node, ast.Constant):
            return node.value

        # variable lookup
        if isinstance(node, ast.Name):
            return self.symbols.get(node.id, None)

        # math operations
        if isinstance(node, ast.BinOp):
            left = self.evaluate(node.left)
            right = self.evaluate(node.right)

            if left is not None and right is not None:
                if isinstance(node.op, ast.Add):
                    return left + right
                if isinstance(node.op, ast.Sub):
                    return left - right
                if isinstance(node.op, ast.Mult):
                    return left * right
                if isinstance(node.op, ast.Div):
                    return left / right

        # -------- NEW: logical comparison reasoning --------
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

        return None


# ---------- Report ----------
class AnalysisReport:
    def __init__(self, issues, complexity_metrics, structural_analysis, resolution_predictions):
        self.issues = issues
        self.complexity_metrics = complexity_metrics
        self.structural_analysis = structural_analysis
        self.resolution_predictions = resolution_predictions


# ---------- Main Engine ----------
class MetaCodeEngine:
    def __init__(self):
        pass

    def orchestrate(self, code):
        issues = []
        resolution_predictions = []

        # Syntax check
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            issues.append(f"Syntax error: {e}")
            return AnalysisReport(
                issues,
                {"raw_size": len(code), "compressed_size": 0, "ratio": 0, "patterns": {}},
                {"depth": 0, "branching_factor": 0, "node_type_distribution": {}},
                []
            )

        # Symbolic reasoning
        analyzer = SymbolicAnalyzer()
        analyzer.visit(tree)
        issues.extend(analyzer.issues)

        # Pattern detection
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                issues.append("Import detected (check security).")
            if isinstance(node, ast.While):
                issues.append("While loop detected (possible infinite loop).")

        # Complexity
        raw_size = len(code.encode())
        compressed = zlib.compress(code.encode())
        compressed_size = len(compressed)
        ratio = compressed_size / raw_size if raw_size > 0 else 0

        complexity_metrics = {
            "raw_size": raw_size,
            "compressed_size": compressed_size,
            "ratio": round(ratio, 3),
            "patterns": {
                "lines": len(code.splitlines()),
                "functions": sum(isinstance(n, ast.FunctionDef) for n in ast.walk(tree)),
            },
        }

        # Structural analysis
        max_depth = 0

        def depth(node, level=0):
            nonlocal max_depth
            max_depth = max(max_depth, level)
            for child in ast.iter_child_nodes(node):
                depth(child, level + 1)

        depth(tree)

        node_counts = {}
        for n in ast.walk(tree):
            name = type(n).__name__
            node_counts[name] = node_counts.get(name, 0) + 1

        structural_analysis = {
            "depth": max_depth,
            "branching_factor": round(len(node_counts) / (max_depth + 1), 2),
            "node_type_distribution": node_counts,
        }

        # Suggestions
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

        return AnalysisReport(
            issues,
            complexity_metrics,
            structural_analysis,
            resolution_predictions
        )
