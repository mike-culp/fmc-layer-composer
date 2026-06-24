from fmc_layer_composer.composer import state
from fmc_layer_composer.composer.state import build_plan_signature, sha256_bytes


def test_plan_signature_is_stable_and_changes_with_inputs():
    acps = [{"id": "a", "name": "ACP A"}, {"id": "b", "name": "ACP B"}]
    one = build_plan_signature("1.2.3.4", "domain", acps, "x.csv", "abc", "target", {"match_mode": "exact"})
    two = build_plan_signature("1.2.3.4", "domain", acps, "x.csv", "abc", "target", {"match_mode": "exact"})
    three = build_plan_signature("1.2.3.4", "domain", list(reversed(acps)), "x.csv", "abc", "target", {"match_mode": "exact"})
    assert one == two
    assert one != three


def test_sha256_bytes_preserves_uploaded_csv_identity():
    assert sha256_bytes(b"name\nrule\n") == sha256_bytes(b"name\nrule\n")
    assert sha256_bytes(b"name\nrule\n") != sha256_bytes(b"name\nother\n")


def test_config_persistence_filters_sensitive_values(tmp_path, monkeypatch):
    path = tmp_path / "config.json"
    monkeypatch.setattr(state, "get_config_path", lambda: path)
    state.save_user_config(
        {
            "fmc_host": "10.0.0.1",
            "verify_tls": False,
            "username": "admin",
            "password": "secret",
            "access_token": "token",
        }
    )
    loaded = state.load_user_config()
    assert loaded == {"fmc_host": "10.0.0.1", "verify_tls": False}
    assert "password" not in path.read_text()
