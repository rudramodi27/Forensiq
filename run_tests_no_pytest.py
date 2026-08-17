#!/usr/bin/env python3
"""
Minimal pytest-compatible test runner.

This sandbox has no network access, so `pytest` (a dev-only dependency,
see pyproject.toml's [project.optional-dependencies].dev) and `PyQt6`
cannot be installed here. This script implements just enough of pytest's
fixture/raises/skip surface (verified by grep against tests/*.py — only
pytest.fixture, pytest.raises, and pytest.skip are used anywhere in the
suite) to actually execute the real test files unmodified and report real
pass/fail/skip/error results, rather than claiming the suite passes
without running it.

Not a pytest reimplementation — no collection plugins, no parametrize,
no scopes beyond function-scope fixtures (matches this suite: every
fixture in conftest.py / test_integrity.py is a plain `@pytest.fixture`
with no scope argument, i.e. function-scoped).
"""

import importlib
import inspect
import pathlib
import sys
import tempfile
import traceback
import types


ROOT = pathlib.Path(__file__).parent.resolve()
sys.path.insert(0, str(ROOT))


# ── Minimal `pytest` shim ────────────────────────────────────────────────────

class _Skipped(Exception):
    def __init__(self, reason=""):
        super().__init__(reason)
        self.reason = reason


class _RaisesContext:
    def __init__(self, expected_exception):
        self.expected_exception = expected_exception
        self.value = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            raise AssertionError(f"DID NOT RAISE {self.expected_exception}")
        if not issubclass(exc_type, self.expected_exception):
            return False
        self.value = exc_val
        return True


def _fixture(func=None, **kwargs):
    def wrap(f):
        f._is_fixture = True
        return f
    if func is not None:
        return wrap(func)
    return wrap


def _raises(expected_exception, *a, **k):
    return _RaisesContext(expected_exception)


def _skip(reason=""):
    raise _Skipped(reason)


class _Mark:
    @staticmethod
    def skip(*a, **k):
        def wrap(f):
            f._skip = True
            return f
        return wrap

    @staticmethod
    def parametrize(*a, **k):
        def wrap(f):
            return f
        return wrap


pytest_shim = types.ModuleType("pytest")
pytest_shim.fixture = _fixture
pytest_shim.raises = _raises
pytest_shim.skip = _skip
pytest_shim.mark = _Mark()
sys.modules["pytest"] = pytest_shim


# ── Built-in fixtures pytest normally provides ──────────────────────────────

def _tmp_path_fixture():
    return pathlib.Path(tempfile.mkdtemp())


BUILTIN_FIXTURES = {
    "tmp_path": _tmp_path_fixture,
}


# ── Fixture collection ───────────────────────────────────────────────────────

def collect_fixtures(module) -> dict:
    fixtures = {}
    for name, obj in vars(module).items():
        if callable(obj) and getattr(obj, "_is_fixture", False):
            fixtures[name] = obj
    return fixtures


def resolve(name, registry, cache):
    if name in cache:
        return cache[name]
    if name not in registry:
        raise LookupError(f"fixture '{name}' not found")
    func = registry[name]
    sig = inspect.signature(func)
    kwargs = {p: resolve(p, registry, cache) for p in sig.parameters}
    value = func(**kwargs)
    cache[name] = value
    return value


# ── Test discovery + execution ──────────────────────────────────────────────

class Result:
    PASS, FAIL, SKIP, ERROR = "PASS", "FAIL", "SKIP", "ERROR"

    def __init__(self, test_id, status, detail=""):
        self.test_id = test_id
        self.status = status
        self.detail = detail


def run_callable(func, registry, extra_self=None):
    sig = inspect.signature(func)
    cache = {}
    kwargs = {}
    for pname in sig.parameters:
        if pname == "self":
            continue
        kwargs[pname] = resolve(pname, registry, cache)
    if extra_self is not None:
        func(extra_self, **kwargs)
    else:
        func(**kwargs)


def main():
    tests_dir = ROOT / "tests"
    conftest_mod = importlib.import_module("tests.conftest")
    base_fixtures = dict(BUILTIN_FIXTURES)
    base_fixtures.update(collect_fixtures(conftest_mod))

    test_files = sorted(tests_dir.glob("test_*.py"))

    results = []
    for tf in test_files:
        mod_name = f"tests.{tf.stem}"
        try:
            mod = importlib.import_module(mod_name)
        except Exception as e:
            results.append(Result(f"{tf.name} (import)", Result.ERROR,
                                   "".join(traceback.format_exception(type(e), e, e.__traceback__))))
            continue

        registry = dict(base_fixtures)
        registry.update(collect_fixtures(mod))

        # Module-level test_* functions
        for name, obj in list(vars(mod).items()):
            if name.startswith("test_") and inspect.isfunction(obj) and obj.__module__ == mod.__name__:
                test_id = f"{tf.stem}::{name}"
                try:
                    run_callable(obj, registry)
                    results.append(Result(test_id, Result.PASS))
                except _Skipped as s:
                    results.append(Result(test_id, Result.SKIP, s.reason))
                except Exception as e:
                    status = Result.FAIL if isinstance(e, AssertionError) else Result.ERROR
                    results.append(Result(test_id, status,
                                           "".join(traceback.format_exception(type(e), e, e.__traceback__))))

        # Test* classes
        for cname, cls in list(vars(mod).items()):
            if cname.startswith("Test") and inspect.isclass(cls) and cls.__module__ == mod.__name__:
                class_registry = dict(registry)
                class_registry.update(collect_fixtures(cls))
                for mname, mobj in list(vars(cls).items()):
                    if mname.startswith("test_") and inspect.isfunction(mobj):
                        test_id = f"{tf.stem}::{cname}::{mname}"
                        try:
                            instance = cls()
                            run_callable(mobj, class_registry, extra_self=instance)
                            results.append(Result(test_id, Result.PASS))
                        except _Skipped as s:
                            results.append(Result(test_id, Result.SKIP, s.reason))
                        except Exception as e:
                            status = Result.FAIL if isinstance(e, AssertionError) else Result.ERROR
                            results.append(Result(test_id, status,
                                                   "".join(traceback.format_exception(type(e), e, e.__traceback__))))

    passed  = [r for r in results if r.status == Result.PASS]
    failed  = [r for r in results if r.status == Result.FAIL]
    errored = [r for r in results if r.status == Result.ERROR]
    skipped = [r for r in results if r.status == Result.SKIP]

    print(f"\n{'='*70}\nRESULTS: {len(passed)} passed, {len(failed)} failed, "
          f"{len(errored)} errors, {len(skipped)} skipped  "
          f"(total {len(results)})\n{'='*70}")

    if skipped:
        print("\n-- SKIPPED --")
        for r in skipped:
            print(f"  SKIP  {r.test_id}  ({r.detail})")

    if failed or errored:
        print("\n-- FAILURES / ERRORS --")
        for r in failed + errored:
            print(f"\n  {r.status}  {r.test_id}")
            print("  " + "\n  ".join(r.detail.strip().splitlines()[-8:]))

    return 0 if not (failed or errored) else 1


if __name__ == "__main__":
    sys.exit(main())
