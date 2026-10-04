"""Live suites are not even imported unless they were asked for (`-m live`): their module-level checks call
docker / the claude and codex CLIs, which must never run (or hang) during the offline suite."""


def pytest_ignore_collect(collection_path, config):
    expr = (config.getoption("markexpr") or "").replace(" ", "")
    if collection_path.name == "conftest.py":
        return None
    return True if ("live" not in expr or "notlive" in expr) else None
