#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 tests/run_tests.py
python3 tests/test_safe_exec.py
python3 tests/test_lease_proof.py
python3 - <<'PY'
import json, subprocess
e1 = json.loads(subprocess.check_output(["python3", "run_e1.py"]))
assert e1["pass"] and e1["benign_allowed"] == 20 and e1["malicious_denied"] == 40, e1
print("E1:", e1["benign_allowed"], "/20 benign,", e1["malicious_denied"], "/40 malicious denied, p50", e1["latency_p50_ms"], "ms")
out = subprocess.check_output(["python3", "run_e2.py"]).decode()
e2 = json.JSONDecoder().raw_decode(out[out.index("{"):])[0]
assert e2["true_claim"]["ok"] and not e2["replay_second"]["ok"] and e2["false_confirmed"] == 0, e2
print("E2: replay rejected, false_confirmed 0")
PY
