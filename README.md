[![CI](https://github.com/gamai-io/polymorph/actions/workflows/ci.yml/badge.svg)](https://github.com/gamai-io/polymorph/actions/workflows/ci.yml)

> **Live evidence dashboard:** https://gamai-io.github.io/demo/

# Polymorph

**A capability may change shape, but it may not gain scope.**

Polymorph is a small, dependency-free layer for agents that execute plans:

1. **Effect lease** — a signed envelope of allowed effects (`fs.read`, `fs.write`, `net.connect`, `exec`, `db.read`, `send`) and exact scopes.
2. **Static admission** — a plan is allowed only if every step stays inside the lease. Unknown keys, nested args, duplicate JSON keys, percent-encoded and fullwidth traversal are denied.
3. **Pinned execution** — `safe_exec` opens the file without following symlinks, checks its SHA-256, and records the executed hash in a receipt.
4. **Signed bundles** — a claim is bound to lease id, genome hash, command hash, nonce, audience and expiry; replay, wrong audience, wrong status or tampering are rejected.

The point is the mutation property: a semantics-preserving or malicious variant may rewrite syntax, but it may not widen the capability envelope.

## Measured (offline, no model)

| Check | Result |
|---|---|
| E1 benign plans allowed | **20/20** |
| E1 malicious plans denied | **40/40** |
| E1 malicious plans with a recorded capability gain | **40/40** |
| E1 false allow / false deny | **0 / 0** |
| E1 static check latency | **p50 6.2 µs**, p95 27.5 µs |
| E2 true claim | accepted |
| E2 replay (second use) | **rejected** (`replay`) |
| E2 tampered report / lease id / audience / expiry | **rejected**, `false_confirmed: 0` |
| Unit tests | **15/15 + 3/3 + 5/5** |

## Quickstart

```bash
python3 run_e1.py            # capability widening corpus
python3 run_e2.py            # signed bundle: replay + tamper
python3 tests/run_tests.py   # lease admission
python3 tests/test_safe_exec.py
python3 tests/test_lease_proof.py
```

Or one command:

```bash
./repro.sh
```

## Lease example

```python
from effect_lease import Lease, check

lease = Lease.from_dict({"effects": {
    "fs.read": ["/in"],
    "fs.write": ["/out"],
    "net.connect": ["api.internal"],
    "exec": ["/bin/true", "/bin/echo"],
    "db.read": ["/in/cache.db"],
    "send": ["mail", "chat"],
}})

check({"id": "b", "steps": [
    {"op": "fs.read", "path": "/in/a"},
    {"op": "fs.write", "path": "/out/a"},
]}, lease)
# {'allow': True, 'capability_gain': [], ...}

check({"id": "m", "steps": [
    {"op": "fs.write", "path": "/out/../etc/x"},
]}, lease)
# {'allow': False, 'capability_gain': ['fs.write'], ...}
```

## Pinned execution

```python
from safe_exec import run_pinned  # via executed-style wrapper in tests
```

`safe_exec` refuses symlinks, checks the expected SHA-256 before execution, and writes a receipt with the hash actually executed. See `tests/test_safe_exec.py`.

## Honest limits

- This is **static admission**, not a sandbox. Execution isolation (bubblewrap, runc, gVisor, Firecracker) is a separate layer.
- It does not prove safety against an adaptive attacker who can alter the lease signer.
- The E3 German cross-language probe against the *lexical* detector blocks only **1/30** attacks (0/15 false positives). That is a real limit of lexical matching, not a claim of multilingual coverage; use `gamai-guard`'s embedding cascade for that layer.
- The E4 semantic-gate prototype is optional and not part of the measured core.
- Corpus is small and authored for this check.

## Files

```
effect_lease.py       strict plan admission against a lease
lease_proof.py        HMAC-signed bundles, audience/expiry/replay checks
safe_exec.py          open-no-follow + pinned hash + receipt
semantic_gate.py      optional local-LLM gate (not in core results)
corpus/e1.jsonl       20 benign + 40 malicious plans
tests/                admission, safe exec, lease proof
```

## License

Apache-2.0.