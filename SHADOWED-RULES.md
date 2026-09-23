# Shadowed rules in the shipped Wazuh ruleset: I looked for them and found zero

Companion to the replay in this repo. That one asked which rules fired. This one asks the
opposite question, statically:

> In the shipped ruleset, how many rules can **never** fire because an earlier rule under the
> same parent catches a set that is equal or wider?

**Answer on `wazuh/wazuh` `v4.14.7`: 0.**

That is a negative result, and the useful part is not the zero. It is that the first two
answers I got were `8` and then `5`, and both were wrong. The detector was broken, not the
ruleset. Details in "What the detector got wrong" below.

## What was measured

| field | value |
|---|---|
| repo | `wazuh/wazuh` (public) |
| tag | `v4.14.7` (latest stable; `v4.14.8-rc*` and `v5.0.0-beta*` excluded) |
| commit | `a42268a27c555d9348d5598fb8751eaf4c8e9024` |
| denominator | `168` files `ruleset/rules/*.xml`, `1,603,626` bytes |
| tree truncated | `false` |
| files actually read | `168 / 168` |
| bytes actually read | `1,603,626` (byte-exact against the tree listing) |

`truncated=false` and the byte match are printed because without them the denominator is a
lower bound, not a count.

## Result

| quantity | count |
|---|---|
| `<rule>` elements | 4512 |
| of those, with `<if_sid>` | 3865 |
| of those, with no filtering condition at all | 17 |
| **rules unreachable under the undeniable test** | **0** |

Weaker second number, stated separately because it rests on an assumption: concatenating all
168 files in filename order also yields **0**. Real load order is decided by `ossec.conf`, not
by the ruleset, so that number is not measurable from this artifact alone.

## The test

A rule B is counted unreachable only when all of:

1. some rule A appears earlier in the same file;
2. A carries no filtering condition whatsoever, so it matches every event reaching its parent;
3. B's parent set is a **subset** of A's parent set (`<if_sid>` may list several parents).

Subset, not equality: if B lists a parent that A does not cover, B is still reachable through
that parent, and it is not counted.

## What the detector got wrong

Both errors made it **over-report**, and both were found by opening the file it accused.

**Run 1 said 8.** It accused rule `7201` in `0115-arpwatch_rules.xml` of eating `7202` through
`7209`. Rule `7201` carries `<if_fts />`, so it fires only the first time a host is seen. That
is a condition, written as a self-closing tag, and my allow-list of condition tags lacked it.

**Run 2 said 5.** It accused rule `31115` in `0245-web_rules.xml` of eating five SQL injection
rules under parent `31100`. Rule `31115` is `<rule id="31115" level="13" maxsize="7900">`, so it
only matches log lines longer than 7900 bytes. The condition sat in a rule **attribute**, and I
was only reading child tags.

The fix in both cases had the same shape: stop enumerating what counts as a condition, and
enumerate what does not. A rule now counts as unconditional only if every child tag is one of
`description`, `group`, `mitre`, `info`, `options`, `if_sid`, and every attribute is one of
`id`, `level`, `noalert`, `overwrite`. Anything unrecognised, including tags that did not exist
when this was written, counts as a condition. The check fails toward "not a shadow".

A shadow detector that over-reports is worse than none. It sends you to delete working rules.

## Controls

Both directions run on synthetic rules before the real ruleset is touched, and the run aborts
if any control fails.

| control | expect | got |
|---|---|---|
| positive: a pair built to be a shadow | 1 | 1 |
| positive: `<mitre><id>` must not read as the `<id>` filter tag | 1 | 1 |
| positive: later rule's parent set is a subset of the earlier one's | 1 | 1 |
| negative: earlier rule has a narrow `<match>` | 0 | 0 |
| negative: earlier rule has `<if_fts />`, the run 1 bug | 0 | 0 |
| negative: condition in the `maxsize` attribute, the run 2 bug | 0 | 0 |
| negative: later rule lists one extra parent | 0 | 0 |

The positive controls are why the `0` is a measurement rather than a blind spot. The same
scorer that returns `0` on the real ruleset returns `1` on rules built to be caught.

## Limits, stated rather than implied

1. This reads rule text. It does not run `wazuh-analysisd`. The claim is "unreachable by
   structure", not "observed silent on your box".
2. One repo, one tag. Nothing here transfers to any other ruleset or version.
3. User rules (`local_rules.xml`) and any custom `<rule_dir>` sit outside the denominator.
4. Only the unconditional predecessor case is counted. Two rules with overlapping but not
   identical regexes can also shadow each other. That is a harder question and is not measured
   here, so `0` is the count for this test, not proof the ruleset holds no dead rules.
5. `<if_group>` is treated as a condition, which is conservative and can only reduce the count.

## Reproduce

`tools/shadow-check.js` in this repo is the exact script, pinned to the same commit. It prints
every count shown here and refuses to report a number if a control fails.

It is also fully specified in words, so it can be checked without running my code at all:

1. Read the file list for that commit from the repository host's tree API. Keep
   `ruleset/rules/*.xml`. Expect 168 entries and `truncated: false`. If it says `true`, stop:
   your denominator is a lower bound.
2. Fetch each blob at that commit. Expect 1,603,626 bytes total. If the byte count does not
   match the tree listing, stop.
3. Strip XML comments, then per `<rule>` record: id, level, `<if_sid>` split on commas, whether
   `overwrite="yes"`, and whether any condition is present. A rule is unconditional only when
   every child tag is in {`description`, `group`, `mitre`, `info`, `options`, `if_sid`} and
   every attribute is in {`id`, `level`, `noalert`, `overwrite`}. Strip `<mitre>` before listing
   child tags, or its nested `<id>` reads as the `<id>` filter tag.
4. Walk each file in order, keeping the unconditional rules seen so far. Count a later rule as
   unreachable when its parent set is a subset of some earlier unconditional rule's parent set.
5. Run the seven controls first and refuse to report a number if any fails.

The 17 unconditional rules, so the step 3 call can be checked one by one. Format is
`rule id (its if_sid)`:

`510 (509)`, `607 (600)`, `3107 (3101)`, `4333 (4330,4331,4332)`, `31410 (31401,31404)`,
`31420 (31402,31405)`, `31430 (31403,31406)`, `64017 (64014,64015,64016)`, `65501 (65500)`,
`67101 (67100)`, `67103 (67102)`, `80475 (80452)`, `80491 (80490)`,
`81603 (81600,81601,81602,81641)`, `82202 (82200,82201)`, `88801 (88800)`, `150101 (150100)`.

None of the 17 is followed, in its own file, by a rule whose parent set it covers. That is the
entire reason the answer is zero.

Counts of what got called a condition, so the deny-list can be argued with rather than trusted:
`field` 3183, `match` 782, `id` 286, `decoded_as` 233, `frequency` 208, `if_matched_sid` 205,
`timeframe` 200, `regex` 148, `if_group` 130, `same_source_ip` 123, `action` 77, `status` 72,
`ignore` 49, `url` 47, `category` 35, `program_name` 33, `list` 25, `extra_data` 9, `if_fts` 8,
`same_field` 7, `if_matched_group` 6, `same_id` 5, `user` 5, `different_url` 5, `check_diff` 3,
`same_user` 3, `check_if_ignored` 3, `compiled_rule` 3, `location` 2, `maxsize` 2, `ignore` 2,
`hostname` 1, `time` 1, `weekday` 1, `same_location` 1.
