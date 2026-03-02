"""
core.py — Data models for Meta-Code Engine.
"""


class Program:
    """Represents a program being analyzed."""

    def __init__(self, name, version, source_code=None, ast_tree=None):
        self.name = name
        self.version = version
        self.source_code = source_code
        self.ast_tree = ast_tree
        self.signatures = []

    def add_signature(self, signature):
        self.signatures.append(signature)

    def __repr__(self):
        return f"Program(name={self.name!r}, version={self.version!r})"


class SemanticSignature:
    """A compressed semantic fingerprint of a program or code block."""

    def __init__(self, signature_id, description, compressed_form=None, node_types=None):
        self.signature_id = signature_id
        self.description = description
        self.compressed_form = compressed_form if compressed_form is not None else []
        self.node_types = node_types if node_types is not None else {}

    def __repr__(self):
        return f"SemanticSignature(id={self.signature_id!r})"


class DissonanceReport:
    """Accumulated result of a dissonance (semantic quality) analysis run."""

    def __init__(self, report_id, program, issues):
        self.report_id = report_id
        self.program = program
        self.issues = list(issues)
        self.complexity_metrics = {}
        self.structural_analysis = {}
        self.resolution_predictions = []

    def add_issue(self, issue):
        self.issues.append(issue)

    def __repr__(self):
        return f"DissonanceReport(id={self.report_id!r}, issues={len(self.issues)})"


class ExecutionTrace:
    """Step-by-step execution record produced by the ExecutionMonitor."""

    def __init__(self, trace_id, program):
        self.trace_id = trace_id
        self.program = program
        self.steps = []
        self.output = ""
        self.errors = []
        self.variable_states = []

    def add_step(self, step):
        self.steps.append(step)

    def __repr__(self):
        return f"ExecutionTrace(id={self.trace_id!r}, steps={len(self.steps)})"


class BehaviorType:
    """Classifies the behavioral category of a program or function."""

    def __init__(self, behavior_id, description):
        self.behavior_id = behavior_id
        self.description = description

    def __repr__(self):
        return f"BehaviorType(id={self.behavior_id!r}, description={self.description!r})"