# Security policy

pii-gate is a guard rail. Its threat model, including what it deliberately does not cover, is in
[docs/threat-model.md](docs/threat-model.md); please read it before reporting, because several
limits there are by design.

If you find a way to get personal data or secrets past the gate (a detector bypass, a tamper-rule
gap, an exfiltration command it does not know, a hook-protocol edge case that fails open), please
report it privately: open a
[GitHub security advisory](https://github.com/sdursun1979/pii-gate/security/advisories/new) on this
repository. Include a **synthetic** reproduction (`tests/_synthetic.py` generates valid identifiers),
never real data.

You will get an acknowledgement within a week. Fixes ship as a patch release with a changelog entry
that credits you, if you wish.

Supported: the latest minor release.
