"""scripts/sweep.py: what a run over a repository says about terrahunter's coverage."""

import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("sweep", Path(__file__).parents[1] / "scripts" / "sweep.py")
sweep = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sweep)


def test_a_run_s_coverage_gaps_and_report():
    run = {
        "status": "ok",
        "seconds": 1.5,
        "last": "",
        "graphs": [
            {
                "resources": [
                    {"type": "aws_s3_bucket", "mode": "managed"},
                    {"type": "digitalocean_droplet", "mode": "managed"},
                    {"type": "null_resource", "mode": "managed"},  # a utility, not a gap
                    {"type": "aws_ami", "mode": "data"},
                ],
                "unknown": [{"status": "download"}],
                "notes": ["main.tf: couldn't be parsed (ValueError)"],
                "info": [],
            }
        ],
    }
    row = sweep.summarise("acme/infra", "abc", run)
    assert row["resources"] == 3 and row["uncatalogued"] == {"digitalocean_droplet": 1}
    assert row["unknown_modules"] == {"download": 1}
    crash = {**row, "repo": "acme/broken", "status": "crash", "last": "KeyError: 'x'", "uncatalogued": {}, "notes": []}
    md = sweep.markdown([row, crash])
    assert "`digitalocean_droplet` | 1 | 1" in md and "| acme/broken | crash | `KeyError: 'x'` |" in md
    assert "<file>: couldn't be parsed" in md
