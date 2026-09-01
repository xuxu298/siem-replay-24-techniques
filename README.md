# 24 techniques replayed against a default SIEM build. 3 produced an alert.

This is the record of one replay run: which ATT&CK techniques were executed against a
default-configured Wazuh build, which ones made a rule fire, and which ones did not.

The whole quiet chain — discovery, collection, exfiltration, command-and-control — produced
nothing at all.

## Why this is not a coverage number

Most coverage claims mean one thing: "we have a rule for technique X." That is a statement about
a ruleset. It can be true while the technique runs end to end and nobody hears about it.

The statement measured here is a different one: "when technique X actually ran, did a rule fire?"
A ruleset can be counted from a config file. Firing can only be observed by running something.

## How it was measured

Isolated lab, three machines: an attacker host, a victim host running the agent, and the manager
on an out-of-the-box configuration — the stock Wazuh ruleset plus a small number of community
rules, which is what a build looks like before anyone has tuned it.

For each of the 24 techniques:

1. execute a real action on the victim, safely and in isolation — not a simulation, not a
   signature test file;
2. query the SIEM within a 15–25 second window;
3. record ALERTED, with the rule id that fired and whether it carried a MITRE mapping, or MISSED.

Techniques were spread across the kill chain rather than clustered where detection is easy.

## Alerted — 3 of 24

| Technique | What fired |
|---|---|
| T1136.001 — Create account | Default rule 5902 (MITRE-mapped) |
| T1110.001 — SSH brute force | Default rule 5503 (PAM) plus a custom rule |
| T1486 — Ransomware encryption / mass rename | Real-time file integrity monitoring: default rule 553 plus a custom rule |

All three are loud, high-volume, filesystem- or auth-level events. That is the pattern, and it is
the finding: the build detects noise well.

## Silent — 21 of 24, zero alerts

| Stage | Techniques |
|---|---|
| Discovery | T1046 · T1082 · T1016 · T1049 · T1033 · T1518 · T1087 · T1057 |
| Credential access | reading /etc/shadow (T1003.008) · credentials in files (T1552.001) |
| Collection and staging | T1005 · T1074 |
| Exfiltration | T1048 |
| Command and control | T1071.001 |
| Defence evasion | obfuscation T1027 · file deletion T1070.004 |
| Ingress tooling | T1105 |
| File-based persistence | cron (T1053.003) · sudoers (T1548.003) · SSH keys (T1098.004) · permission change (T1222.002) |

Read the middle of that list again. Discovery, collection, exfiltration and C2 form a complete
chain — land, look around, gather, take it out, keep talking to it. On this build that chain runs
from end to end and the alert console stays empty.

## Three uncomfortable truths

**1. Having a rule is not detecting.** The build lit up on the three noisiest actions and missed
every quiet one. A rule count would have described this deployment as broadly covered.

**2. Configuration decides — and the default chooses for you.** Real-time file integrity
monitoring caught ransomware. Scheduled file integrity monitoring missed every file-based
persistence technique that was run. Same product, same ruleset, opposite outcome. Nobody made
that trade-off on purpose; the default made it.

**3. A host SIEM is blind to the network.** Exfiltration and C2 produced zero alerts because
there was no network sensor in the build. From the alert console there is no way to tell that
data is leaving.

## What this does not say — stated here, not buried at the bottom

- **It is one reference configuration, and it is not a verdict on Wazuh.** It characterises the
  build that was configured. It is not a measurement of any organisation's live environment and
  it does not generalise to "all SOCs".
- **Some misses are missing telemetry, not missing rules.** The default agent did not have
  command auditing enabled, so a portion of the silent techniques were never observable to the
  ruleset in the first place. Telemetry gaps are cheap to fix; rule gaps are not.
- **The per-technique split between telemetry gap and rule gap is not in this file.** It was
  recorded during the run. It is not published here, so do not read the 21 as 21 missing rules.
- **The two custom rules are not identified.** Two of the three alerting lines say "plus a custom
  rule" and no id is given for them. Three default rule ids are published; the full set of rules
  that participated is larger than three.
- **15–25 seconds is the window the SIEM was queried in, not a time-to-detect.** Same unit,
  different quantity. Nothing here measures how fast anything was detected.
- **This is vendor-authored.** It was measured by the party that built the bench. That is the
  reason the method and the full technique list are above rather than a summary: so the number
  can be argued with instead of believed.

## If you think this is wrong

Run the same techniques against your own build and see whether you get a different answer. The
method above is complete enough to do that. A measurement that cannot come out badly is not a
measurement.
