# Two Wazuh lab hosts, 484 events apart, produced identical alert counts

On 15 September 2026 we measured detection coverage on two of our own lab hosts, both running a stock Wazuh manager with the shipped ruleset and no custom rules written. One host, LAB-OT, runs Conpot. The other, LAB-K8S, runs LocalStack and k3s. The numbers were frozen before anyone here wrote a first rule line, because writing the rule first destroys the measurement.

At 15:21Z the two agents had sent 399 and 608 events. The manager showed 320 alerts for each host, the same six rules on both. A 209-event difference in input, and no difference at all in output.

One match like that still reads as coincidence. So instead of repeating the measurement, we widened the input and measured again. At 15:45Z the two agents had sent 678 and 1162 events. The manager showed 370 alerts for each host.

| host | sent 15:21Z | sent 15:45Z | alerts 15:45Z |
|---|---|---|---|
| LAB-OT | 399 | 678 | 370 |
| LAB-K8S | 608 | 1162 | 370 |
| difference | 209 | 484 | 0 |

The gap in what the two hosts sent more than doubled. The gap in what the manager reported stayed at zero. A counter that can't see a difference growing from 209 to 484 isn't counting the thing that is growing.

## Versions

The manager was Wazuh v4.14.7, revision rc1, not GA. Its container was created 2026-09-14T05:08:30Z, started three seconds later, and has not been restarted since, so the build that ran on 15 September is the build still running. There is no /var/ossec/ruleset/VERSION file on this build, so the ruleset carries no identity of its own beyond the image it shipped in: the shipped ruleset of image wazuh/wazuh-manager:4.14.7. Both agents, LAB-OT (id 005) and LAB-K8S (id 006), ran Wazuh v4.14.7 on Linux 6.8.0-139-generic x86_64.

The first version of this page said our own notes did not record a version. That was wrong about us; the correction section at the end says how.

## It is not a collection failure

ossec.log prints "Analyzing file:" for the Conpot logs on LAB-OT and for LocalStack plus eight k3s pod logs on LAB-K8S. The events leave the sensor, reach the manager, and die at the rule layer, because nothing in the shipped ruleset matches those log lines.

## The half you can check without our rig

In wazuh/wazuh at tag v4.14.7, ruleset/rules holds 168 files and ruleset/decoders holds 120. Reading both lists for modbus, s7comm, opcua, dnp3, iec6, profinet, scada, conpot, kubernetes, k8s, k3s or localstack returns nothing. Reading the same two lists for docker returns three files and for aws returns two, so the lists are readable and the absence is real.

That is a filename check, and reading the file contents changes two of those answers. In the shipped ruleset, kubernetes appears in two files and containerd appears in two. The kubernetes hits are in rules/0998-aws-security-hub-rules.xml, a single group of 61 EKS control rules. The containerd hits are decoders/0410-docker_decoders.xml and rules/0455-docker_rules.xml. Anyone with grep finds those 61 rules in half a minute, so they belong in the post rather than in the replies.

Those 61 EKS rules are compliance controls rather than container detection rules. Their group tags are compliance benchmark tags, cis_aws_foundations_benchmark_* and pci_dss_* and an 800-53 control set, not detection tags. Seven of the 61 carry a `<mitre>` block at all, six carry any T1xxx code, and none of them maps a technique from the Containers matrix.

## The claim that survives a grep

Counting filenames was the weak way to ask this. The ruleset answers it directly through its own MITRE mappings: across the shipped ruleset, ICS techniques (T0xxx) map to zero rules and Containers techniques (T1605 to T1613) map to zero rules, while 97 other T1xxx techniques are mapped. The 97 is what makes the two zeros readable. Without a positive control beside them, a zero reads like a broken query rather than an absence.

## What this does not say

The repository check above is at the filename level, so on its own it does not rule out a Modbus or Kubernetes pattern living inside a generically named file; the content-level counts are the two cases where that turned out to matter. Two lab hosts are two hosts, not a survey. Nothing here says the shipped ruleset is good or bad overall, only which of these log sources have a rule that matches them.

The rig measurement is what covers the rule bodies: the log lines arrived and no rule claimed them.

## Why this is a different class from the 24-technique replay

The replay in this repository measured techniques that the shipped ruleset does have rules for, which stayed silent for configuration reasons. This measures log sources the shipped ruleset has no rule for at all. Counting alerts answers which rules are firing. It never answers whether a sensor is running, and the two questions feel identical right up to the moment they disagree. A sensor running perfectly with no rule that matches it is invisible in every alert count you will ever pull.

Rules for these two classes are next. The zero got published first because once the rules exist it can't be measured on this rig again.

## Correction, 16 September 2026

Two things in the first version of this page were wrong, corrected here rather than removed.

The version sentence said the rig measurement was reported without a version because our own notes did not record one. Our notes did record one, at the time of the measurement, in an internal file written one minute after the 15:45Z reading. It was never carried across to this page. The numbers are in the Versions section above.

The repository check reported a filename-level absence and did not report that at content level the shipped ruleset does contain kubernetes in two files and containerd in two. The sentence as written was narrow and true, but a reader who ran grep would have found 61 rules with kubernetes in them and had every reason to stop trusting the rest of the page. Those rules, and what they actually are, are in the body above.

If you have run a stock install against OT or Kubernetes log sources and seen something different, the counts you got would be useful to me.
