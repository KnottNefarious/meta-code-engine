import ast
import zlib


class AnalysisReport:
    def __init__(self, issues, complexity_metrics, structural_analysis, resolution_predictions):
        self.issues = issues
        self.complexity_metrics = complexity_metrics
        self.structural_analysis = structural_analysis
        self.resolution_predictions = resolution_predictions


class MetaCodeEngine:
    def __init__(self):
        pass

    def orchestrate(self, code):
        issues = []
        resolution_predictions = []

        # ---------- 1. Syntax Check ----------
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

        # ---------- 2. Simple Static Analysis ----------
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                issues.append("Import detected (check security).")

            if isinstance(node, ast.While):
                issues.append("While loop detected (possible infinite loop).")

        # ---------- 3. Complexity ----------
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

        # ---------- 4. Structural Analysis ----------
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

        # ---------- 5. Resolution Suggestions ----------
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
