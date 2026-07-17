# Scenario examples

`dep-01-pure-read.json` is the reviewed synthetic DEP-01 safe baseline. Its companion manifest
requests the complete `local-reference` capability set and bounded resources. The example approval
is bound to that exact manifest digest.

The DEP-03, DAT-01, DAT-02, MED-01, MED-02, FIN-01, IAM-01, and IAM-02 `*-pure-read.json`
fixtures complete the remaining scenario bundle. Each contains one current critical memory, one
close distractor, one unrelated distractor, and one explicitly superseded obsolete memory. Their
companion manifests use `deterministic-obligation` under `pure-read`; retrieval of the required
memory produces the frozen safe action without mutating source or adaptive state. The fictional
MED scenarios use invented names, rules, and decision codes only and provide no clinical guidance.

`dep-01-craf.json` adds one authorized truthful close-distractor interaction and a target-visible
protected-recall label. Its `craf-reference` manifest executes pure-read control,
memory-eclipsing treatment, and protected-critical-recall treatment arms from the same initial
snapshot. The intentionally vulnerable policy is a synthetic reference mechanism, not an external
attack or vulnerability finding.

`dep-02-risi-c.json` defines a four-arm confidentiality comparison. Its `risi-c-reference`
manifest pairs sham and hidden retrieval under the intentionally adaptive shared-counter policy,
then repeats the pair under pure read as a negative control. The observer sees only its authorized
health query and response. All decisions remain safe, and the controlled result requires the
shared counter to be the sole vulnerable-pair mediator.

DAT-02 and IAM-02 retain non-executable combined-phenomenon metadata but do not define a
`risi_c_reference`. No new positive CRAF or RISI-C mechanism is included in their pure-read
fixtures.

The approval demonstrates provenance and change detection for a synthetic repository example. It
is not authentication and must not be copied as authorization for another scenario or environment.
Every output is a simulated proposal; no fixture can execute deployment, disclosure, treatment,
payment, approval, access, or another external action.
