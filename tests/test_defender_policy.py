from src.cvds.defender import ASR_RULES, BALANCED_ASR_ACTIONS


def test_entry_shield_has_auditable_complete_action_map():
    assert len(ASR_RULES) == 18
    assert set(ASR_RULES) == set(BALANCED_ASR_ACTIONS)
    assert set(BALANCED_ASR_ACTIONS.values()) <= {1, 2}
    assert BALANCED_ASR_ACTIONS["c1db55ab-c21a-4637-bb3f-a12568109d35"] == 1
    assert BALANCED_ASR_ACTIONS["d1e49aac-8f56-4280-b9ba-993a6d77406c"] == 2
