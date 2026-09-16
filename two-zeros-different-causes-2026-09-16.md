# Two coverage zeros, two different causes

On 16 September 2026 we wrote detection rules for two classes our bench had never
covered, industrial control (OT) and Kubernetes, and loaded them onto our own
Wazuh rig. Both classes had measured zero before. Loading the rules told us
something the coverage count never could: **the two zeros do not have the same
cause, and only one of them is fixable by writing rules.**

The zeros themselves were measured and published before any of these rules existed: [ot-k8s-rule-layer-2026-09-15.md](ot-k8s-rule-layer-2026-09-15.md).

## What we ran

Rig: a stock Wazuh manager, `v4.14.7` (revision `rc1`), with the shipped ruleset.
Two agents, both `v4.14.7`: one Linux host running a PLC runtime, one running k3s.
We wrote our own rules in a separate file and did not modify a byte of the stock
ruleset. `wazuh-analysisd -t` exits 0; the rules load.

## The Kubernetes zero

We tagged a rule with `T1611` (Escape to Host, from the ATT&CK Containers matrix).
The tool accepted it and echoed `mitre.id: ['T1611']`. No warning.

We replayed a real event against it (a pod requesting `privileged`, `hostPID` and
`hostNetwork`) and the alert came back at the level we assigned.

So the Containers technique exists in the platform's technique database. Nothing in
the platform was missing. What was missing was a rule, and a rule is something you
can hire someone to write.

## The OT zero

We tagged a rule with `T0886` (Remote Services, from the ATT&CK ICS matrix). The
same tool, in the same run, printed:

```
** Wazuh-Logtest: WARNING: Mitre Technique ID 'T0886' not found in database.
```

The rule still loads, and replaying a matching log line through the tool produces the
alert. But the technique it claims to cover is not a technique the platform knows
about. You can write the rule; you cannot make the
platform carry the tag.

That is a different kind of zero. Writing rules does not close it.

## Why we are reporting the control, not just the finding

A tool that prints "not found in database" for every identifier you hand it would
produce exactly the output above, and would mean nothing. The `T1611` result is the
control: same tool, same run, same rule file, with one identifier accepted silently
and one rejected with a warning. Without that pair, the warning is not evidence.

We also counted what the stock ruleset does carry: 97 distinct `T1xxx` identifiers
across 168 rule files. The ruleset is not untagged. It is tagged, thoroughly, in a
matrix that does not include ICS.

## What this does not say

Both results above were produced by `wazuh-logtest`, replaying a log line through the
rule engine. They are not measurements of a live event stream. On this rig the OT
source had stopped emitting entirely by the time the rules were loaded, so the OT
rule has produced no alert from live traffic at all: a separate problem, and one a
rule cannot fix.

This is one rig, one version, one revision: `4.14.7 rc1`, not a GA build. We have
not tested another SIEM, and we have not checked whether a later release ships the
ICS matrix. We are not saying the product does not support OT; we are saying that on
this build, an ICS technique identifier is not in the technique database, and that
this is a different problem from an empty ruleset even though both show up as a zero
on a coverage chart.

We also found stock rules that mention Kubernetes: 61 of them, in the AWS Security
Hub file, covering EKS. Their groups are compliance groups (CIS, PCI DSS, and an
800-53 control set). Across all 61 rules we count 7 MITRE blocks and 6 distinct technique
identifiers, none of them from the Containers matrix. We mention this because a reader checking our claim
will find those 61 rules in about thirty seconds, and we would rather name them than
have them look like something we missed.

## The question worth asking your own stack

If you run a stock install against OT or Kubernetes log sources, the useful number
is not how many rules you have. It is: **when your coverage says zero, which of the
two zeros is it?** One of them a rule author can close. The other one cannot.

If you have run this and got a different result, particularly on a GA build, the
identifier and the tool output would be useful to us. Send it: [open an issue](https://github.com/xuxu298/siem-replay-24-techniques/issues) or email dongnx.biz@gmail.com.
