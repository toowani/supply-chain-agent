import json

from sca.ingest.manifests import npm_lock_graph, requirements_direct
from sca.versions import compare, is_newer, sort_versions


def test_numeric_not_lexicographic():
    assert compare("pypi", "2.10.0", "2.9.0") == 1
    assert compare("npm", "2.10.0", "2.9.0") == 1


def test_pep440_prerelease_and_post():
    assert sort_versions("pypi", ["1.0", "1.0rc1", "1.0.post1", "0.9"]) == ["0.9", "1.0rc1", "1.0", "1.0.post1"]


def test_semver_prerelease_order():
    order = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
             "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"]
    assert sort_versions("npm", list(reversed(order))) == order


def test_is_newer_handles_garbage():
    assert not is_newer("npm", "not-a-version", "1.0.0")


def test_requirements_direct(tmp_path):
    f = tmp_path / "r.txt"
    f.write_text("# c\nPyYAML>=6\nhuggingface_hub<1.0   # note\n-r other.txt\nrequests[socks]==2.0 ; python_version>'3'\n")
    assert requirements_direct(f) == ["pyyaml", "huggingface-hub", "requests"]


def test_npm_lock_nested_resolution(tmp_path):
    lock = {"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"a": "^1"}, "devDependencies": {"b": "^1"}},
        "node_modules/a": {"version": "1.0.0", "dependencies": {"c": "^2"}},
        "node_modules/a/node_modules/c": {"version": "2.0.0"},
        "node_modules/b": {"version": "1.0.0", "dev": True, "dependencies": {"c": "^1"}},
        "node_modules/c": {"version": "1.5.0", "dev": True},
    }}
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    nodes, edges = npm_lock_graph(tmp_path)
    assert ("npm:a@1.0.0", "npm:c@2.0.0") in edges      # nested copy wins
    assert ("npm:b@1.0.0", "npm:c@1.5.0") in edges      # hoisted copy
    assert ("ROOT", "npm:b@1.0.0") in edges
    assert nodes["npm:c@1.5.0"]["dev"] and not nodes["npm:a@1.0.0"]["dev"]
