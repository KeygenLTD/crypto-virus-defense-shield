from src.cvds.paths import install_canaries, remove_canaries


def test_canary_lifecycle_is_scoped_to_manifest(tmp_path, monkeypatch):
    state = tmp_path / "state"
    protected = tmp_path / "protected"
    protected.mkdir()
    monkeypatch.setenv("CVDS_STATE_DIR", str(state))
    installed = install_canaries([protected], "0123456789abcdef")
    assert len(installed) == 3
    unrelated = protected / "unrelated.txt"
    unrelated.write_text("keep", encoding="utf-8")
    assert remove_canaries() == 3
    assert unrelated.read_text(encoding="utf-8") == "keep"
