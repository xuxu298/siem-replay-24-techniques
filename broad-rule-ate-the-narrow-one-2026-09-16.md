# The alert view was full the whole time

We wrote two detection rules for our own Kubernetes lab and got one of them filed
under the other. The alert view never went quiet, no rule errored, and the counts
looked healthy. The event we most wanted to see, a container escape, was recorded
at the severity of a routine lookup.

This is a short write-up of a mistake in our own rules, because the shape of it is
reusable and it is not specific to our stack.

## The two rules

Against the Kubernetes API audit log we wrote:

- **level 10**: a pod requesting `privileged`, `hostPID`, `hostNetwork` or `hostIPC`
- **level 6**: resource enumeration in the cluster

For the level 6 rule, the first pattern we reached for was the request path,
`/api/v1/namespaces/`. It reads like discovery. It is also present in the request
path of every *namespaced* request the API server logs, which included both records
we replayed, among them the one for creating a privileged pod. (Cluster-scoped
requests do not carry it; we did not survey what share of our audit volume that is.)

## What happened

We replayed a real audit record (the creation of a pod with `privileged: true` and
`hostPID: true`) through the rule engine. It came back as the **level 6** rule, with
the discovery technique attached. The level 10 rule never evaluated: the broad rule
sat earlier and matched first.

Here is where the ratio comes from, since this piece is about instruments: these are
cumulative counts of rule ids in the manager's live alert log (`alerts.json`), read
after the fix was already in place, not a snapshot of the broken window. Our first
read showed 153 discovery alerts against 1 escape alert. Forty minutes later the same
command returned **949 discovery alerts, still 1 escape**.

That growth is the point. The discovery count is routine cluster chatter, `list` and
`watch` calls a healthy cluster makes all day, and it climbs without bound. One
escape event filed into that stream does not lower any number, does not raise any
number, and does not look like anything.

The mis-filing does not show up anywhere in those counts. Both rules were firing.
Neither logged an error. The only way we found it was to replay an event whose
correct verdict we already knew, and check which rule id came back.

## The fix

We restructured into an anchor and ordered the children narrowest first:

```
anchor (level 0)   : any Kubernetes audit record, never alerts
  ├── level 10     : privileged / hostPID / hostNetwork / hostIPC
  ├── level  8     : exec into a container
  ├── level  8     : access to secrets
  └── level  6     : verb is list or watch      ← narrowed from the request path
```

Two changes, and the second matters more than the first: the discovery rule now
matches the *verb*, not a substring of the path every record contains. Ordering alone
would have left a rule that still matches everything.

After the change, the escape event is recorded by the level 10 rule and carries its
own count in the alert log.

## What this does not say

The "before" was observed in `wazuh-logtest`, replaying a real audit record. The
"after" was observed in the live alert log. Those are two different instruments, and
we are reporting them as such rather than presenting a single clean before/after
number we did not take with one tool.

These were our rules, on our lab, written the same afternoon. We are not describing
anyone else's configuration, and we have not surveyed how common this is. One rig,
one ruleset, one day.

## The part worth borrowing

A broad rule placed before a narrow one means the narrow rule never runs, and
because the alert view stays full, nothing looks missing. Silence would have been
easier to notice than a healthy-looking count.

The check is cheap and does not need our lab: take the event you would least like to
miss, replay it, and read back **which rule id claimed it**. Not whether an alert
fired: which one. We had a 153-to-1 ratio sitting in front of us and it told us
nothing, because the ratio was the symptom of the bug and looked like the shape of
normal traffic.

If you run that check on your own ruleset and the id that comes back is not the one
you expected, we would like to hear what it was: [open an issue](https://github.com/xuxu298/siem-replay-24-techniques/issues) or email dongnx.biz@gmail.com. A rule id and
the event you replayed is enough. We are not asking for anything about your
environment.
