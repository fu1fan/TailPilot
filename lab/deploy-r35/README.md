# R35 isolated native validation

Run only in the disposable `unified-lab-01` guest on the authorized dev host.
These scripts assert that hostname. They are not production deployment commands.

Provide a real apt/systemd base, a new independent fixture state path, loopback
`lab/appc-e2e` testcontrol, explicit lab inventory/exclusions, the original v1
release at `/root/r35-old19`, sealed final release at `/root/r35-final`, and the
reviewed executor at `/root/r35/deploy`. Use a QEMU overlay with restricted user
networking, retaining its original backing image. Do not clear an existing state
or remove recovery files; finish pending transactions through their recovery API.

`run.py bootstrap` executes old native rehearsal and commit. The VM commit
attestation is labeled LAB ONLY and does not attest production external E2E.
`upgrade-rehearsal` then `upgrade` execute the new native phases. Set new
`R35_ATTEMPT` IDs for every attempt, `R35_REHEARSAL` to the successful rehearsal,
and optionally `R35_CONFIG` to a reviewed strict v2 all-off candidate whose exact
bytes match an already staged release. Keep all prior failure artifacts.

`R35_UPGRADE=<formal-name> python3 policy-flow.py cycle` runs actual batch TTL
operations and daemon restarts; `failure` injects real systemd worker failures in
both directions and verifies pending intent recovery after daemon restart;
`reverse` runs the actual committed rollback batch. It only removes its own
content-matched fault-injection drop-in. It never adopts or resets routes.

`collect.py` verifies the final named round, exact runtime source hashes, lifecycle
results and policy-only state migration. It exports no raw state or command
output: stdout/stderr are replaced with SHA256 digests. For a new round, update
its explicit final-round names; do not silently reuse an earlier result.

See `evidence/round35.md` for the performed run, iterations and proof boundaries.
