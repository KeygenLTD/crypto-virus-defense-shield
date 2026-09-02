from src.simulator.fake_ransomware import is_safe_root, prepare, run
from src.simulator.restore import restore


def test_simulator_requires_exact_safe_root_name(tmp_path):
    unsafe = tmp_path / "anything"
    assert prepare(unsafe) == 2
    assert not is_safe_root(unsafe)


def test_simulator_round_trip(tmp_path):
    root = tmp_path / "cvds-safe-simulation"
    assert prepare(root) == 0
    assert run(root, 0) == 0
    assert list(root.glob("*.cvdslocked"))
    assert restore(root) == 0
    assert not list(root.glob("*.cvdslocked"))
