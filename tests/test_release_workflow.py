"""Guard-Tests für .github/workflows/docker.yml (Release-Weg nach Prod).

Ein Tag setzt :latest, und Watchtower rollt :latest nachts auf Prod aus. Deshalb darf nur ein
reiner Release-Tag vX.Y.Z auf einem Commit, der auf main liegt, zu :latest werden — nicht ein
Sicherungs-Tag wie "vorher-umbau" oder ein Semver-Tag auf einem ungemergten Branch.
"""
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "docker.yml"


def _workflow():
    with open(WORKFLOW, encoding="utf-8") as f:
        wf = yaml.safe_load(f)
    # PyYAML liest den Schlüssel "on" als Boolean True
    wf["on"] = wf.pop(True, wf.get("on"))
    return wf


def _steps():
    return _workflow()["jobs"]["build"]["steps"]


def _step_index(pred):
    for i, st in enumerate(_steps()):
        if pred(st):
            return i
    raise AssertionError("Schritt nicht gefunden")


def _guard_step():
    steps = _steps()
    return steps[_step_index(lambda s: s.get("id") == "release")]


def _gh_filter_matches(pattern, ref_name):
    """Minimaler Nachbau der GitHub-Filtermuster (*, **, +, ?, [..]) für Tag-Namen."""
    rx, i = "", 0
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("**", i):
            rx += ".*"
            i += 2
            continue
        if c == "*":
            rx += "[^/]*"
        elif c in "+?":
            rx += c
        elif c == "[":
            j = pattern.index("]", i)
            rx += pattern[i:j + 1]
            i = j + 1
            continue
        else:
            rx += re.escape(c)
        i += 1
    return re.fullmatch(rx, ref_name) is not None


def _triggers(tag):
    return any(_gh_filter_matches(p, tag) for p in _workflow()["on"]["push"]["tags"])


@pytest.mark.parametrize("tag", ["v0.22.1", "v1.0.0", "v10.20.30"])
def test_release_tags_trigger(tag):
    assert _triggers(tag)


@pytest.mark.parametrize("tag", ["vorher-umbau", "v-test", "v1.2", "v1.2.3-rc1", "v2.20.1-1", "version"])
def test_non_release_tags_do_not_trigger(tag):
    assert not _triggers(tag)


def test_latest_only_via_release_guard():
    meta = _steps()[_step_index(lambda s: str(s.get("uses", "")).startswith("docker/metadata-action"))]
    tags = meta["with"]["tags"]
    assert "startsWith(github.ref, 'refs/tags/v')" not in tags
    assert "type=raw,value=latest,enable=${{ steps.release.outputs.release == 'true' }}" in tags
    # kein zusätzliches automatisches :latest aus type=semver an der Guard vorbei
    assert "latest=false" in meta["with"].get("flavor", "")


def test_guard_runs_before_build_with_full_history():
    steps = _steps()
    guard = _step_index(lambda s: s.get("id") == "release")
    meta = _step_index(lambda s: str(s.get("uses", "")).startswith("docker/metadata-action"))
    build = _step_index(lambda s: str(s.get("uses", "")).startswith("docker/build-push-action"))
    checkout = _step_index(lambda s: str(s.get("uses", "")).startswith("actions/checkout"))
    assert checkout < guard < meta < build
    assert steps[checkout].get("with", {}).get("fetch-depth") == 0
    assert steps[guard].get("if") == "github.ref_type == 'tag'"


# --- Verhalten des Guard-Skripts in einem echten Wegwerf-Repo -------------------------------

def _git(cwd, *args, env):
    return subprocess.run(["git", *args], cwd=cwd, env=env, check=True,
                          capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    if not shutil.which("git") or not shutil.which("bash"):
        pytest.skip("git/bash fehlt")
    env = {**os.environ,
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
    origin = tmp_path / "origin.git"
    seed = tmp_path / "seed"
    _git(tmp_path, "init", "-q", "--bare", "-b", "main", str(origin), env=env)
    _git(tmp_path, "init", "-q", "-b", "main", str(seed), env=env)
    _git(seed, "commit", "-q", "--allow-empty", "-m", "a", env=env)
    old_main = _git(seed, "rev-parse", "HEAD", env=env)
    _git(seed, "commit", "-q", "--allow-empty", "-m", "b", env=env)
    _git(seed, "checkout", "-q", "-b", "feature", env=env)
    _git(seed, "commit", "-q", "--allow-empty", "-m", "feature", env=env)
    _git(seed, "tag", "v9.9.9", "feature", env=env)      # Semver-Tag, aber ungemergt
    _git(seed, "tag", "v1.0.0", old_main, env=env)       # älterer main-Stand
    _git(seed, "tag", "v1.1.0", "main", env=env)         # main-Spitze
    _git(seed, "tag", "vorher-umbau", "main", env=env)   # Sicherungs-Tag
    _git(seed, "push", "-q", str(origin), "main", "feature", "--tags", env=env)
    work = tmp_path / "work"
    _git(tmp_path, "clone", "-q", str(origin), str(work), env=env)
    return work, env


def _run_guard(repo, tag):
    work, env = repo
    _git(work, "checkout", "-q", "--detach", f"refs/tags/{tag}", env=env)
    out = work.parent / f"out-{tag}"
    out.write_text("")
    script = _guard_step()["run"]
    assert "${{" not in script  # das Skript muss ohne Actions-Ausdrücke lauffähig sein
    res = subprocess.run(["bash", "-c", script], cwd=work, capture_output=True, text=True,
                         env={**env, "GITHUB_REF_NAME": tag, "GITHUB_OUTPUT": str(out)})
    return res.returncode, out.read_text()


@pytest.mark.parametrize("tag", ["v1.1.0", "v1.0.0"])
def test_guard_accepts_release_tag_on_main(repo, tag):
    rc, output = _run_guard(repo, tag)
    assert rc == 0
    assert "release=true" in output


def test_guard_rejects_semver_tag_on_unmerged_branch(repo):
    rc, output = _run_guard(repo, "v9.9.9")
    assert rc != 0
    assert "release=true" not in output


def test_guard_rejects_non_semver_tag(repo):
    rc, output = _run_guard(repo, "vorher-umbau")
    assert rc != 0
    assert "release=true" not in output
