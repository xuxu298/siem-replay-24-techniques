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

## It is not a collection failure

ossec.log prints "Analyzing file:" for the Conpot logs on LAB-OT and for LocalStack plus eight k3s pod logs on LAB-K8S. The events leave the sensor, reach the manager, and die at the rule layer, because nothing in the shipped ruleset matches those log lines.

## The half you can check without our rig

In wazuh/wazuh at tag v4.14.7, ruleset/rules holds 168 files and ruleset/decoders holds 120. Reading both lists for modbus, s7comm, opcua, dnp3, iec6, profinet, scada, conpot, kubernetes, k8s, k3s or localstack returns nothing. Reading the same two lists for docker returns three files and for aws returns two, so the lists are readable and the absence is real.

## What this does not say

That repository check is at the filename level, so it doesn't rule out a Modbus or Kubernetes pattern living inside a generically named file. Two lab hosts are two hosts, not a survey. The version of the shipped ruleset named above is v4.14.7; the rig measurement is reported without a version because our own notes did not record one, and we are not going to supply a number we did not measure.

The rig measurement is what covers the rule bodies: the log lines arrived and no rule claimed them.

## Why this is a different class from the 24-technique replay

The replay in this repository measured techniques that the shipped ruleset does have rules for, which stayed silent for configuration reasons. This measures log sources the shipped ruleset has no rule for at all. Counting alerts answers which rules are firing. It never answers whether a sensor is running, and the two questions feel identical right up to the moment they disagree. A sensor running perfectly with no rule that matches it is invisible in every alert count you will ever pull.

Rules for these two classes are next. The zero got published first because once the rules exist it can't be measured on this rig again.

If you have run a stock install against OT or Kubernetes log sources and seen something different, the counts you got would be useful to me.
