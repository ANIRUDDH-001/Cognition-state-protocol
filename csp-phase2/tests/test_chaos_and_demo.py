"""Chaos faults + the demo entry point itself.

The demo is the deliverable, so it is regression-tested like anything else: if
`python -m demo.run_demo --chaos --charts` cannot complete, that is a failing
test, not a surprise discovered in front of judges.
"""
from __future__ import annotations

import pytest

from chaos import inject
from core.types import STATUS_QUARANTINED, STATUS_REVOKED, STATUS_VERIFIED
from loadgen.tasks import generate
from nodes import Mesh


@pytest.fixture(scope="module")
def warm_mesh():
    """A mesh that has already learned one insight the honest way."""
    m = Mesh(seed=42, out_dir="out/test-chaos")
    for t in generate(42, 20):
        r = m.run_task(t)
        if r["incident"]:
            m.pipeline_step(m.nodes[r["node"]], r["incident"])
    assert any(i["status"] == STATUS_VERIFIED for i in m.nodes["N1"].state().values())
    return m


def test_f1_a_node_that_was_down_catches_up_on_gossip_alone(warm_mesh):
    r = inject.f1_node_down(warm_mesh)
    assert r["detect"]["victim_missing_insight"], "N3 must actually miss the announce"
    assert r["detect"]["digest_diverged"]
    assert r["repair"]["victim_has_insight"], "restored node must catch up"
    assert r["integrity"]["converged"] and r["integrity"]["chains_valid"]


@pytest.fixture(scope="module")
def f2(warm_mesh):
    return inject.f2_poisoned(warm_mesh)


@pytest.mark.parametrize("tag,expected_stage", [
    ("a", "guardrail"), ("b", "guardrail"), ("c", "guardrail"), ("d", "replay"),
])
def test_f2_every_poisoned_update_is_blocked_at_the_right_layer(f2, tag, expected_stage):
    row = next(x for x in f2["rows"] if x["tag"] == tag)
    assert row["blocked"], f"{tag} reached VERIFIED -- the fabric is poisoned"
    assert row["status"] in (STATUS_QUARANTINED, STATUS_REVOKED)
    assert row["stage"] == expected_stage, (
        f"{tag} was caught at {row['stage']}, expected {expected_stage}: "
        "the defence layers are not doing what we claim they do"
    )
    # Every peer that ruled on it must have ruled against it.
    assert row["verdicts"] and all(not ok for _n, ok, _r in row["verdicts"])


def test_f2_pruning_removes_the_subtree_and_keeps_everything_else(f2):
    assert f2["prune"]["descendant"] in f2["prune"]["tombstoned"], "descendants go with the parent"
    assert f2["prune"]["surviving_verified"], "pruning must not reset collective memory"
    assert f2["integrity"]["entries_deleted"] == 0, "tombstone, never delete"
    assert f2["integrity"]["chains_valid"]


def test_f3_partition_diverges_then_heals(warm_mesh):
    r = inject.f3_partition(warm_mesh)
    assert r["detect"]["majority_has"] and not r["detect"]["minority_has"]
    assert r["detect"]["digest_split"], "a partition must actually split the fabric"
    assert r["repair"]["minority_has"], "healing must be automatic"
    assert r["integrity"]["converged"] and r["integrity"]["chains_valid"]
    assert len(set(r["integrity"]["digests"].values())) == 1


# --- the demo entry point -----------------------------------------------------


def test_demo_runs_end_to_end_with_chaos_and_charts(tmp_path):
    from demo import run_demo
    rc = run_demo.main(["--seed", "42", "--chaos", "--charts", "--no-color",
                        "--out", str(tmp_path)])
    assert rc == 0
    assert (tmp_path / "summary.md").exists()
    assert (tmp_path / "telemetry.jsonl").exists()
    for n in ("N1", "N2", "N3"):
        assert (tmp_path / f"fabric_{n}.jsonl").exists()
    charts = sorted(p.name for p in (tmp_path / "charts").glob("*.png"))
    assert charts == ["1_duration.png", "2_rounds.png", "3_latency_p95.png", "4_guardrail.png"]

    body = (tmp_path / "summary.md").read_text(encoding="utf-8")
    assert "fabric converged: **True**" in body
    assert "chains valid: **True**" in body


def test_handshake_demo_runs(tmp_path):
    from demo import run_handshake
    assert run_handshake.main(["--seed", "42", "--no-color"]) == 0
    assert run_handshake.main(["--seed", "42", "--no-color", "--flip"]) == 0


def test_the_demo_is_reproducible(tmp_path):
    """Same seed, same run -- this is what 'rehearse with seed 42' depends on."""
    from demo.run_demo import run, summarize

    a_mesh, a_rows, _ = run(42, True, quiet=True, out_dir=str(tmp_path / "a"))
    b_mesh, b_rows, _ = run(42, True, quiet=True, out_dir=str(tmp_path / "b"))

    assert a_mesh.nodes["N1"].log.digest() == b_mesh.nodes["N1"].log.digest()
    assert summarize(a_mesh, a_rows) == summarize(b_mesh, b_rows)
    assert [r["result"].transcript_hash for r in a_rows] == \
           [r["result"].transcript_hash for r in b_rows]


def test_a_different_seed_produces_a_different_run_but_the_same_ratchet():
    from demo.run_demo import run

    for seed in (7, 99):
        mesh, rows, marks = run(seed, True, quiet=True, out_dir=f"out/test-seed{seed}")
        assert marks["verified_at"], f"seed {seed}: no insight was ever verified"
        warm = [r for r in rows if r["warm"]]
        assert warm, f"seed {seed}: the ratchet never engaged"
        assert all(r["result"].rounds <= 2 for r in warm), "warm start must collapse rounds"
        assert mesh.converged() and all(n.log.verify_chain() for n in mesh.nodes.values())
