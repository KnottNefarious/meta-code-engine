import ast
import builtins
import io
import sys
import textwrap


# Node types that are explicitly forbidden inside user-submitted code.
_FORBIDDEN_NODES = (
    ast.Import,
    ast.ImportFrom,
    ast.Global,
    ast.Nonlocal,
)

# Built-in names allowed inside the restricted execution sandbox.
_SAFE_BUILTINS = {
    'print', 'len', 'range', 'enumerate', 'zip', 'map', 'filter',
    'sorted', 'reversed', 'sum', 'min', 'max', 'abs', 'round',
    'int', 'float', 'str', 'bool', 'list', 'dict', 'set', 'tuple',
    'isinstance', 'type', 'repr', 'hasattr', 'getattr',
    'True', 'False', 'None',
}


def _safe_builtins_dict():
    """Build a restricted builtins dict using the builtins module directly."""
    return {k: getattr(builtins, k) for k in _SAFE_BUILTINS if hasattr(builtins, k)}


def _validate(tree):
    """Raise ValueError if the AST contains forbidden constructs."""
    for node in ast.walk(tree):
        if isinstance(node, _FORBIDDEN_NODES):
            raise ValueError(
                f"Forbidden construct in code: {node.__class__.__name__}"
            )
        if isinstance(node, ast.Call):
            func = node.func
            name = None
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                name = func.attr
            if name in ('exec', 'eval', 'compile', '__import__', 'open',
                        'breakpoint', 'input'):
                raise ValueError(f"Forbidden call: {name}")


class HarmonicExecutor:
    """Safely execute Python code in a restricted sandbox and capture output."""

    def __init__(self):
        pass

    def execute(self, task):
        """
        Execute *task* (a source-code string) safely.

        Returns a dict with keys:
          - success (bool)
          - output (str)
          - errors (list[str])
          - variables (dict)
        """
        result = {'success': False, 'output': '', 'errors': [], 'variables': {}}
        try:
            source = textwrap.dedent(task)
            tree = ast.parse(source)
            _validate(tree)

            safe_globals = {
                '__builtins__': _safe_builtins_dict(),
            }
            local_vars = {}
            stdout_capture = io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = stdout_capture
            try:
                exec(compile(tree, '<sandbox>', 'exec'), safe_globals, local_vars)  # noqa: S102
            finally:
                sys.stdout = old_stdout

            result['success'] = True
            result['output'] = stdout_capture.getvalue()
            result['variables'] = {
                k: repr(v) for k, v in local_vars.items()
                if not k.startswith('_')
            }
        except Exception as exc:
            result['errors'].append(str(exc))
        return result


class ExecutionMonitor:
    """Monitor code execution by tracking variable states and call flow."""

    def __init__(self):
        pass

    def monitor(self, execution):
        """
        Execute *execution* (source code string) while recording a trace.

        Returns a dict with:
          - steps (list[dict]) — one entry per top-level statement
          - output (str)
          - errors (list[str])
          - final_variables (dict)
        """
        trace = {'steps': [], 'output': '', 'errors': [], 'final_variables': {}}
        try:
            source = textwrap.dedent(execution)
            tree = ast.parse(source)
            _validate(tree)

            safe_globals = {
                '__builtins__': _safe_builtins_dict(),
            }
            local_vars = {}
            stdout_capture = io.StringIO()
            old_stdout = sys.stdout
            sys.stdout = stdout_capture

            try:
                for stmt in tree.body:
                    stmt_source = ast.unparse(stmt)
                    step = {
                        'statement': stmt_source,
                        'node_type': stmt.__class__.__name__,
                    }
                    try:
                        mini_tree = ast.Module(body=[stmt], type_ignores=[])
                        exec(compile(mini_tree, '<sandbox>', 'exec'), safe_globals, local_vars)  # noqa: S102
                        step['variables_after'] = {
                            k: repr(v) for k, v in local_vars.items()
                            if not k.startswith('_')
                        }
                        step['error'] = None
                    except Exception as stmt_exc:
                        step['variables_after'] = {}
                        step['error'] = str(stmt_exc)
                        trace['errors'].append(str(stmt_exc))
                    trace['steps'].append(step)
            finally:
                sys.stdout = old_stdout

            trace['output'] = stdout_capture.getvalue()
            trace['final_variables'] = {
                k: repr(v) for k, v in local_vars.items()
                if not k.startswith('_')
            }
        except Exception as exc:
            trace['errors'].append(str(exc))
        return trace

