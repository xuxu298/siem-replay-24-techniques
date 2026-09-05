# 24 techniques replayed against a default SIEM build. 3 produced an alert.

This is the record of one replay run: which ATT&CK techniques were executed against a
default-configured Wazuh build, which ones made a rule fire, and which ones did not.

The whole quiet chain — discovery, collection, exfiltration, command-and-control — produced
nothing at all.

## Correction — 3 September 2026

A Wazuh engineer read this file, asked for the version, the OS, the agent configuration and the exact command behind each of the 24 techniques, and we could not hand any of them over. Two statements below are wrong because of that, and the silent count needs narrowing.

**"The method above is complete enough to do that" is not true.** No Wazuh version, no agent configuration and no per-technique command or path is published anywhere in this repository. Until they are, 3-of-24 cannot be reproduced from this file by anyone outside our company. Read it as our claim, not as a result you can check.

**Three of the 21 silent techniques are an artefact of our observation window, not a finding about the build.** cron (T1053.003), sudoers (T1548.003) and permission change (T1222.002) are reported by file integrity monitoring, which on a default build runs as a scheduled scan rather than in real time. The 15-25 second query window below is shorter than that scan interval, so those three could not have alerted inside it whatever the ruleset said.

**Two more rows we got wrong in the other direction.** SSH keys (T1098.004) is not a window problem at all: `~/.ssh/authorized_keys` is outside the default monitored scope, so nothing was watching it. And file deletion (T1070.004) may belong with the first three — it depends on whether the deleted file sat in a default-monitored path, and we did not record which path we used. That is the same failure as the paragraph above, showing up as a row we can no longer classify.

**So the split is three states, not two.** No telemetry collected; telemetry collected and no rule matched; a detection that exists and did not fire inside the window we looked in. This file separated the first two and folded the third into the second.

The alerted count is unchanged. What changes is what the silent count is allowed to be used for: it is 21 observed silences, not 21 missing rules, and at least three of them are our measurement rather than the build.

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

---

# The same technique, three SIEMs

Everything above is one run against one default build. Everything below is a **different set of
runs, on tuned builds, in June 2026**. Do not read the two halves as one measurement: the 3-of-24
figure is what a stock install does, and the table below is what happens when someone has already
written the rule.

T1110.001 (brute force) is the one technique we have run end-to-end on all three platforms.

| SIEM | Setup | Result | MTTD |
|---|---|---|---|
| **Wazuh 4.14.2** | SSH brute force, 20+ failed logins, custom rule `100113` | ALERTED ×2, coverage 100% | **25s / 45s** |
| **IBM QRadar CE 7.3.3** | hydra, 50 SSH login attempts against a live victim host | ALERTED | **~4s** |
| **Splunk Enterprise** | `winsrv01`, 12× EventCode 4625 — **events replayed into Splunk, not generated by a live attack** | ALERTED | **0s** |

**Read the third row differently from the first two.** Wazuh and QRadar were measured against a real
attack on a real host: hydra and a live SSH brute force, with the alert coming back out of the
platform. The Splunk row is a real Splunk Enterprise, a real detection-as-code rule, and a real
query — but the 4625 events were replayed in rather than produced by an attack we ran. That makes
it a valid test of the connector and the rule. It is not a test of Splunk's ingest path, and we are
not going to let it read as one.

🔴 **Do not read this table as a race either.** The three numbers are not comparable and we are not
going to pretend they are. Splunk's `0s` is not Splunk being six times faster than QRadar — it is
Windows 4625 events already sitting in the index before the clock started, while the Wazuh figure
includes agent-to-manager-to-indexer propagation on a technique we had to write a rule for.
Different telemetry, different clocks, different work. Published anyway, with the caveats attached,
because a table with an honest asterisk is worth more than three separate write-ups with none.

The `MISSED` row is the one we care about most. Alongside `winsrv01`, we ran `cleanhost` — a host
with no events at all — and the connector correctly returned **MISSED**. A benchmark where nothing
can fail is not a benchmark. That negative control is what makes the other rows mean anything. A
third host, `dbsrv02`, carried events timestamped 4s late and returned MTTD 4s, so the clock is
measuring something real rather than returning zero by construction.

## Two more findings from the same lab — and two things withheld

- Real ransomware encrypting real files → caught by Wazuh file integrity monitoring in real-time
  mode. Two things are withheld here on purpose: the detection time, because the figure in our
  internal notes does not appear in any published report we can point you at, and the rule id, on
  the same ground.
- SSH brute force → alert **and an actual firewall drop** that reached the host and stayed there.
  The rule ids for that one are withheld on the same ground.

We had both sets of ids written down and we have taken them back out. An id you cannot trace to a
source file is a claim nobody can check, which is worse than no id at all. If we find the file, we
will put them back and say so here.

## Dates, because they matter

The three-SIEM measurements were taken in June 2026, not last week. The Wazuh 4.14.2 lab run is
15 June, the Splunk connector proof 26 June, the QRadar proof 29 June. Nothing here has been
re-run since. If any of these platforms has changed its default rule set in the meantime, our
numbers are stale and we would like to know.

## Why we can publish this and a vendor cannot

Every SIEM vendor can measure their own product. None of them can publish a table where their
product is one row among three, because the row that looks worst is the one paying for the
marketing team. We sell neither Wazuh, QRadar, nor Splunk. That is the entire reason this table
exists.

We will also tell you what we have not measured. We have not run this against Sentinel or
Elastic on live systems. We have no third-party audit of any of it — every number above is our own
measurement of our own lab, and you should discount it accordingly until someone outside our
company reproduces one.

## Run it yourself

The detection library behind this is 71 scenarios, 84 Sigma rules, 84 techniques, with zero gap
between scenarios and rules, plus 6 named threat-actor campaigns. Rules translate to Splunk SPL,
Sentinel KQL, Elastic and Wazuh from the same detection-as-code source.

If you run any of those SIEMs and want your own number instead of ours, say so — we would rather
argue with your data than with our own.

## If you think this is wrong

Run the same techniques against your own build and see whether you get a different answer. The
method above is complete enough to do that. A measurement that cannot come out badly is not a
measurement.

That second sentence is wrong, and we have left it standing rather than edited it away: see
[Correction — 3 September 2026](#correction--3-september-2026) at the top of this file.

**Corrections wanted.** If you think the 3/24 is wrong, tell us which technique should have fired
and on what rule. We will re-run it and publish the correction with the same prominence as the
original claim.

## Who ran this

This replay was run by ATK, a security company that measures detection coverage and post-quantum readiness. Two other measurement records from the same team, both with raw data published:

- [PQReadinessIndex](https://github.com/xuxu298/PQReadinessIndex) — post-quantum front-door support across 350 hosts, three runs (April, May, September 2026), including the hosts that went backwards.
- [crowdsec-appsec-rdns-latency](https://github.com/xuxu298/crowdsec-appsec-rdns-latency) — in-band AppSec latency, a number we could not find published anywhere else.
