# Cognition Fabric -- run summary

- contracts: **27**, aborts: **3**
- insights: {'VERIFIED': 3, 'QUARANTINED': 3, 'REVOKED': 2}, guardrail denials: **18**
- fabric converged: **True**, chains valid: **True**
- fabric digest: `8043c4be5a51bc56b0641750d54659eb...`

## The ratchet (lossy tasks only, same seed, same eras)

| | fabric OFF | fabric ON | change |
|---|---|---|---|
| mean contract duration | 9311 ms | 7023 ms | **-25%** |
| mean rounds | 4.67 | 1.53 | **-67%** |
| timed out entirely | 6 / 18 | 3 / 18 | **-3** |

## F1 node down during propagation

```json
{
 "fault": "F1 node down during propagation",
 "detect": {
  "victim_down": true,
  "victim_missing_insight": true,
  "digest_diverged": true
 },
 "repair": {
  "gossip_rounds_to_catch_up": 2,
  "victim_has_insight": true
 },
 "integrity": {
  "digests": {
   "N1": "b9f71c51481d67d17ddf013fe348331adeed72d1e8761ada0f79245538f6662e",
   "N2": "b9f71c51481d67d17ddf013fe348331adeed72d1e8761ada0f79245538f6662e",
   "N3": "b9f71c51481d67d17ddf013fe348331adeed72d1e8761ada0f79245538f6662e"
  },
  "converged": true,
  "chains_valid": true
 },
 "insight_id": "ins-c3ebd5bfd16b"
}
```

## F2 poisoned updates

| # | attack | expected | caught at | status |
|---|---|---|---|---|
| a | tampered claim, stale signature | INVALID_SIG | guardrail | **QUARANTINED** |
| b | eps=0.9 (bounds are [0.01, 0.2]) | BOUNDS_VIOLATION | guardrail | **QUARANTINED** |
| c | warm_start disables inspection | POLICY_VIOLATION | guardrail | **QUARANTINED** |
| d | valid signature, fabricated metric_after | REPLAY_DIVERGENCE | replay | **QUARANTINED** |

Pruned `['ins-9bbe61518388', 'ins-19ca0427825d']` (incl. descendant `ins-19ca0427825d`); still-verified: `['ins-35400cf2191d', 'ins-c3ebd5bfd16b']` -- pruning is not a reset.

## F3 partition / heal

```json
{
 "fault": "F3 partition / heal",
 "detect": {
  "partition": [
   [
    "N1",
    "N3"
   ],
   [
    "N2",
    "N3"
   ]
  ],
  "majority_has": true,
  "minority_has": false,
  "digest_split": true
 },
 "repair": {
  "gossip_rounds_to_converge": 2,
  "minority_has": true
 },
 "integrity": {
  "digests": {
   "N1": "8043c4be5a51bc56b0641750d54659ebd9304550cdf13c14e9c201e0e3d95ef6",
   "N2": "8043c4be5a51bc56b0641750d54659ebd9304550cdf13c14e9c201e0e3d95ef6",
   "N3": "8043c4be5a51bc56b0641750d54659ebd9304550cdf13c14e9c201e0e3d95ef6"
  },
  "converged": true,
  "chains_valid": true
 },
 "insight_id": "ins-22cfb6735080"
}
```
