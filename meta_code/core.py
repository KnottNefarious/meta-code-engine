class Program:
    def __init__(self, name, version):
        self.name = name
        self.version = version
        self.signatures = []

    def add_signature(self, signature):
        self.signatures.append(signature)

class SemanticSignature:
    def __init__(self, signature_id, description):
        self.signature_id = signature_id
        self.description = description

class DissonanceReport:
    def __init__(self, report_id, program, issues):
        self.report_id = report_id
        self.program = program
        self.issues = issues

    def add_issue(self, issue):
        self.issues.append(issue)

class ExecutionTrace:
    def __init__(self, trace_id, program):
        self.trace_id = trace_id
        self.program = program
        self.steps = []

    def add_step(self, step):
        self.steps.append(step)

class BehaviorType:
    def __init__(self, behavior_id, description):
        self.behavior_id = behavior_id
        self.description = description

class SupportingClass:
    def __init__(self, attr1, attr2):
        self.attr1 = attr1
        self.attr2 = attr2

    def perform_action(self):
        pass