# Fourteen shipped decoders that no rule is rooted at

A SIEM install ships two halves that have to line up. Decoders turn a log line into
fields. Rules decide whether those fields are worth an alert. We counted the decoders
shipped in `v4.14.7` that have no rule keyed to them.

Fourteen.

This is a static read of the tagged source, not a measurement on a running manager.
The method is at the bottom and it is four greps.

## What we counted

At tag `v4.14.7` of `wazuh/wazuh`:

- `ruleset/rules/`: 168 files, 4,515 rules
- `ruleset/decoders/`: 120 files, 1,581 `<decoder>` blocks, of which **171 are
  top-level** (no `<parent>` element) and 475 are children

A rule can reach a decoder in three ways visible in the shipped XML:

1. `<decoded_as>name</decoded_as>`, naming the decoder directly
2. `<category>x</category>`, which reaches every decoder whose `<type>` is `x`
3. by naming the log source some other way: `<program_name>`, `<match>`

Route 1: the ruleset uses **166 distinct `decoded_as` values, 233 times**. 145 of those
are among the 171 top-level decoders. The other 21 are child decoders, or decoders
built into the manager rather than shipped as XML: `syscheck_*`, `rootcheck`, `sca`,
`syscollector`, `windows_eventchannel`.

Route 2: the entire ruleset uses **7 distinct categories**: `ossec` (19 rules),
`windows` (5), `firewall` (3), `ids` (3), `squid` (2), `web-log` (2), `syslog` (1).

Twenty-six top-level decoders are not named by any `decoded_as`. Nine of them declare a
`<type>` matching one of those 7 categories, so rules do reach them that way:
`windows`, `windows-ntsyslog`, `windows-snare`, `web-accesslog`, `squid-accesslog`,
`squid-cachelog`, `aix-ipsec`, `ipfilter`, `suhosin`.

Three more are reached by route 3, in `0020-syslog_rules.xml` and
`0285-systemd_rules.xml`: `mountd` via `<match>^rpc.mountd: refused mount request
from</match>`, `systemd` via `<program_name>^systemd$|^systemctl$</program_name>`, and
`useradd` via `<program_name>useradd</program_name>`.

Fourteen are left:

```
aws-eks-authenticator    grandstream-ata    ossec-alert     pvepw-logger
barracuda-svf-admin      groupadd           portsentry      pvestatd
barracuda-svf-email      isakmpd            pveproxy
checkpoint-syslog        openvassd
chfn
```

Each ships a parser. None is named anywhere in the 168 rule files, not in a
`decoded_as`, not in a `match`, not in a `program_name`, not in a comment. None
declares a `<type>`, so no category reaches them either.

## The control

A pattern match that finds nothing everywhere proves nothing. The same substring scan
over the same 168 files finds `windows` in 39 files, `sshd` in 5, `web-accesslog` in 1.
The scan is not blind. The fourteen zeros are absences.

## Why this is the same shape as a sensor with no rule

`groupadd` is the one worth sitting with. `useradd` has a rule at
`0020-syslog_rules.xml` line 627. `groupadd` ships a decoder beside it and has none. A
host that adds a user and a host that adds a group emit log lines the product parses
equally well, and only one of those can raise anything.

`aws-eks-authenticator` is the other one. It parses the component that decides who gets
into an EKS cluster, and no rule is rooted at it. We had already measured this
ruleset's Kubernetes coverage a different way, by technique identifier:
[ot-k8s-rule-layer-2026-09-15.md](ot-k8s-rule-layer-2026-09-15.md). Two instruments,
pointing at the same hole.

An event from one of the fourteen does not vanish. It falls through to the generic
low-level syslog rules and is counted as traffic. That is what makes it hard to see.
It is not silence; it is a number going up. Which is the same failure seen from the
other side here:
[broad-rule-ate-the-narrow-one-2026-09-16.md](broad-rule-ate-the-narrow-one-2026-09-16.md).

## What this does not say

We read shipped XML at one tag. We did not run a manager. We are not claiming these
sources produce no alert at all; they produce generic ones. The claim is narrower: no
rule is rooted at the decoder.

We treated a decoder as reachable by category when its `<type>` string is one of the 7
the rules use. We did not verify the manager's internal type-to-category mapping. If
that mapping is looser than a string match, fourteen is too high.

Route 3 we tested by raw substring scan across the rule files. That test is generous
(it would count a mention inside a comment) and three candidates left the set because
of it. A route we have not thought of would shrink the number again. We would rather
publish fourteen and be corrected than publish seventeen and be right by accident.

One tag, one repository, one read. We did not check whether a later release adds rules
for any of these, and we did not look at any ruleset other than the one that ships.

## Re-running it

```
# clone the wazuh/wazuh repository at tag v4.14.7, then:
cd wazuh/ruleset

# decoder names the rules key off
grep -ho '<decoded_as>[^<]*' rules/*.xml | sed 's/.*>//' | sort -u

# categories the rules use
grep -ho '<category>[^<]*' rules/*.xml | sed 's/.*>//' | sort | uniq -c

# top-level decoder names, and the type each one declares
grep -h -A4 '<decoder name=' decoders/*.xml

# then, for one decoder name N: does it appear in the rules at all?
grep -rl 'N' rules/ | wc -l
```

If you run this against a build we did not (a later tag, or a manager with an extra
ruleset loaded) and the set comes out different, the list you got is the useful part.
[Open an issue](https://github.com/xuxu298/siem-replay-24-techniques/issues) or email
dongnx.biz@gmail.com. A version and the names is enough.
