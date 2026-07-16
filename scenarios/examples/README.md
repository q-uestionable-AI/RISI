# Scenario examples

`dep-01-pure-read.json` is the reviewed synthetic DEP-01 safe baseline. Its companion manifest
requests the complete `local-reference` capability set and bounded resources. The example approval
is bound to that exact manifest digest.

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

The approval demonstrates provenance and change detection for a synthetic repository example. It
is not authentication and must not be copied as authorization for another scenario or environment.
