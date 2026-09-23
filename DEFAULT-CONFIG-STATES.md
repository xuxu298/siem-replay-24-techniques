# Enabled, disabled, or neither: the shipped Wazuh default config declares no state for 56 of 145 blocks

Companion to the shadowed-rules check in this repo. That one asked a question about the
ruleset. This one asks about the config that ships beside it:

> In the default configuration shipped with the project, how many collection/module blocks are
> shipped explicitly **off**, how many explicitly **on**, and how many declare **no state at
> all**?

**Answer on `wazuh/wazuh` `v4.14.7`: 7 off, 78 on, 56 declare nothing, 4 exist only inside
comments.** A binary on/off reading covers `85 / 145` = **58.62%** of what is shipped.

The useful part is not the 7. It is the 56, and the fact that 42 of those 56 are `<localfile>`,
the blocks that decide which logs get read at all.

## Why this question, and who asked it first

I did not invent the framing. On 15 September 2026, in a public Wazuh mailing-list thread,
Francisco Sousa built three Ubuntu 22.04 containers to check a claim someone else had made
about audit logs, and wrote:

> «there are three states, not two, and each has its own check»

<https://groups.google.com/g/wazuh/c/JFaiCE4ZkUw>

He was talking about one data source on a running host. The question I had was whether that
shape holds in the shipped text itself, across every block, before any host exists. It does,
and it is worse than three.

## What was measured

| field | value |
|---|---|
| repo | `wazuh/wazuh` (public) |
| tag | `v4.14.7` (latest stable; `v4.14.8-rc*` and `v5.0.0-beta*` excluded) |
| commit | `a42268a27c555d9348d5598fb8751eaf4c8e9024` |
| scope | `etc/ossec*.conf` + `etc/templates/config/**` |
| excluded | `internal_options`, `preloaded-vars`, `local_internal_options`, `sca.files`, `README` |
| denominator | `111` files, `90,596` bytes |
| tree truncated | `false` |
| files actually read | `111 / 111` |
| bytes actually read | `90,596` (byte-exact against the tree listing) |

`truncated=false` and the byte match are printed because without them the denominator is a
lower bound, not a count.

## Result

| state | count |
|---|---|
| explicitly off | 7 |
| explicitly on | 78 |
| **declares no state** | **56** |
| exists only inside a comment | 4 |
| **total blocks shipped** | **145** |

The 7 shipped off, in full, so anyone can open the exact line:

| file | block |
|---|---|
| `ossec.conf`, `ossec-agent.conf`, `ossec-local.conf`, `ossec-server.conf` | `wodle name="open-scap"` |
| `templates/config/generic/cluster.template` | `cluster` |
| `templates/config/generic/osquery.template` | `wodle name="osquery"` |
| `templates/config/generic/wodle-ciscat.template` | `wodle name="cis-cat"` |

The 56 that declare nothing, by tag family: `localfile` 42, `global` 8, `remote` 4,
`logging` 2.

## Two idioms, opposite polarity

Blocks that do declare state do not agree on how:

| idiom | blocks |
|---|---|
| `<disabled>yes\|no</disabled>` | 81 |
| `<enabled>yes\|no</enabled>` | 4 |

`<disabled>no</disabled>` and `<enabled>yes</enabled>` mean the same thing and are written
inversely. The four on the minority idiom are `sca` (generic and darwin templates), `indexer`,
and `vulnerability-detection`, that is, the newer subsystems.

## The test

A block is counted **off** only when the block itself carries `<disabled>yes</disabled>` or
`<enabled>no</enabled>` at its own level. Specifically:

1. comment regions are removed first, and any block lying wholly inside one is counted in the
   comment bucket instead, never as config;
2. before looking for a state tag, every nested block of a known family is stripped, so a
   child's `<disabled>` is never attributed to its parent;
3. a block with neither idiom goes to its own bucket. It is **not** assumed on.

Point 3 is the whole design. A block's behaviour when it declares nothing is decided in the C
source, not in the shipped text. Calling it "on" would be reading a default out of a file that
does not contain one. That is a guess wearing the clothes of a measurement.

## What the detector got wrong

The first run of this tool knew only the `<disabled>` idiom. It printed **60** declaring
nothing and **74** on. Both were wrong: the four `<enabled>` blocks fell through into "declares
nothing", because a checker that knows one spelling reads every other spelling as absence.

That is the same failure mode as the shadowed-rules tool in this repo, which over-reported
twice for the same reason, and it points the same direction: a detector built on a list of
markers it knows will always err toward "nothing here". The fix both times was to make the
unknown case land in a bucket of its own instead of silently joining a real one.

I am reporting this because the corrected number is only trustworthy if the wrong one is on
the record next to it.

## Controls

Nine synthetic cases run before the real files are touched; the tool refuses to print any
real number if one fails.

| case | expected |
|---|---|
| block declares `<disabled>yes</disabled>` | off |
| block declares `<disabled>no</disabled>` | on |
| block declares nothing | neither bucket |
| block lies wholly inside `<!-- -->` | comment bucket |
| two blocks in one file, one off one on | one each, not file-level |
| `<disabled>yes</disabled>` inside a comment **within** a live block | ignored; live value wins |
| nested block's `<disabled>` | attributed to the child, not the parent |
| `<enabled>no</enabled>` | off |
| `<enabled>yes</enabled>` | on |

## Limits, stated by me

1. This measures **shipped text**, not a running install. It answers "what does the project
   ship", not "what is on your host". Sousa's other two checks (`auditctl -l`, and the loaded
   rules' keys against the keys list) need a host and are out of scope here.
2. The installer composes a final `ossec.conf` from these templates per platform. Which
   templates a given install receives is decided by installer logic, not by the text measured
   here, so no per-platform total is claimed.
3. One repo, one tag. Nothing here carries to any other ruleset, distribution or fork.
4. Anything an operator adds later is outside the denominator by construction.
5. "Declares no state" is a statement about the text, not a defect. For `<localfile>`,
   presence is the state by design, which is exactly why "is source X enabled?" cannot be
   answered by grepping for a state tag.

## Reproduce

1. Fetch the git tree for commit `a42268a2…` with `?recursive=1` and confirm `truncated` is
   `false`.
2. Keep blobs matching `etc/ossec*.conf` or `etc/templates/config/**`, minus the five excluded
   names above. Expect 111 files, 90,596 bytes.
3. Fetch each from `raw.githubusercontent.com` at that commit and check the received byte total
   against the tree's.
4. Strip comment regions, then bucket each block of a known family by its own state tag.
5. Print the four buckets, the idiom split, and the full list of blocks shipped off.

`tools/config-state-check.js` in this repo does exactly these steps and prints the controls
first. It runs in a browser console on any origin without a restrictive CSP.
