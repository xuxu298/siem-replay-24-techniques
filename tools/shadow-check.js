// shadow-check.js - are there rules in the shipped ruleset that can never fire?
//
// A rule B is counted unreachable only when ALL of:
//   1. some rule A appears earlier in the same file;
//   2. A carries no filtering condition at all, so it matches every event reaching its parent;
//   3. B's parent set is a SUBSET of A's parent set (<if_sid> may list several parents).
//
// Run it in a browser console (or over CDP). Synchronous XHR is used on purpose: it keeps the
// whole thing one expression with no promise plumbing, and the host serves both endpoints with
// Access-Control-Allow-Origin: *. Open a page with a permissive CSP first; a page whose CSP
// restricts connect-src will block the reads.
//
// Prints every intermediate count. Refuses to report if a control fails.

(() => {
  const SHA = 'a42268a27c555d9348d5598fb8751eaf4c8e9024';   // wazuh/wazuh v4.14.7
  const get = (u) => {
    const x = new XMLHttpRequest();
    x.open('GET', u, false);
    x.send(null);
    return x.status === 200 ? x.responseText : null;
  };
  const L = [];
  const say = (s) => L.push(s);

  // DENY-LIST, not an allow-list. These are the only child tags that do NOT narrow the set of
  // events a rule matches (output and description tags, plus the parent selector). Every other
  // tag, including
  // tags that did not exist when this was written, counts as a condition. Fails toward
  // "not a shadow". An earlier allow-list version of this missed <if_fts/> and over-reported.
  const NOT_A_FILTER_TAG = { description: 1, group: 1, mitre: 1, info: 1, options: 1, if_sid: 1 };
  // Conditions also live in rule ATTRIBUTES (maxsize, frequency, ignore...), not only in child
  // tags. Same deny-list treatment. Missing this over-reported too.
  const NOT_A_FILTER_ATTR = { id: 1, level: 1, noalert: 1, overwrite: 1 };

  const parse = (txt, fname) => {
    const clean = txt.replace(/<!--[\s\S]*?-->/g, '');
    const out = [];
    const re = /<rule\s([^>]*?)>([\s\S]*?)<\/rule>/g;
    let m;
    while ((m = re.exec(clean)) !== null) {
      const attr = m[1], body = m[2];
      const idm = attr.match(/\bid\s*=\s*"(\d+)"/);
      if (!idm) continue;
      const ow = /\boverwrite\s*=\s*"yes"/i.test(attr);

      const attrConds = [];
      const are = /([a-z_0-9]+)\s*=\s*"/gi;
      let a;
      while ((a = are.exec(attr)) !== null) {
        const n = a[1].toLowerCase();
        if (!NOT_A_FILTER_ATTR[n]) attrConds.push(n);
      }

      const ifsidM = body.match(/<if_sid>\s*([^<]*?)\s*<\/if_sid>/);
      // <mitre> nests <id>, and <id> is a real filter tag. Strip <mitre> before listing child
      // tags, otherwise ATT&CK metadata masquerades as a filter and the rule looks conditional.
      const noMitre = body.replace(/<mitre>[\s\S]*?<\/mitre>/gi, '');
      const childTags = [];
      const tre = /<([a-z_0-9]+)[\s/>]/gi;
      let t;
      while ((t = tre.exec(noMitre)) !== null) childTags.push(t[1].toLowerCase());
      const tagConds = childTags.filter(n => !NOT_A_FILTER_TAG[n]);

      out.push({
        id: idm[1],
        lvl: (attr.match(/\blevel\s*=\s*"(-?\d+)"/) || [])[1] || '?',
        ow: ow,
        ifsid: ifsidM ? ifsidM[1].replace(/\s+/g, '') : null,
        par: ifsidM ? ifsidM[1].replace(/\s+/g, '').split(',').filter(Boolean) : [],
        cond: tagConds.length > 0 || attrConds.length > 0,
        why: tagConds.concat(attrConds.map(s => '@' + s)).join(','),
        f: fname
      });
    }
    return out;
  };

  const isSubset = (small, big) => small.every(s => big.indexOf(s) >= 0);
  const scoreSeq = (arr) => {
    const pairs = [], eaters = [];
    arr.forEach(r => {
      if (!r.ifsid || r.ow) return;
      for (let i = 0; i < eaters.length; i++) {
        if (isSubset(r.par, eaters[i].par)) {
          pairs.push({ f: r.f, sid: r.ifsid, eater: eaters[i].id, ef: eaters[i].f, eaten: r.id, lvl: r.lvl });
          return;
        }
      }
      if (!r.cond) eaters.push(r);
    });
    return pairs;
  };
  // Within one file. Does not depend on how analysisd orders the files, so this is the strong one.
  const score = (rules) => {
    const byFile = {};
    rules.forEach(r => { (byFile[r.f] = byFile[r.f] || []).push(r); });
    let pairs = [];
    Object.keys(byFile).forEach(f => { pairs = pairs.concat(scoreSeq(byFile[f])); });
    return pairs;
  };

  // ================= CONTROLS, BOTH DIRECTIONS, BEFORE THE REAL RULESET =================
  const P1 = '<group name="t"><rule id="900100" level="3"><if_sid>1000</if_sid><description>eats all</description></rule>'
    + '<rule id="900101" level="5"><if_sid>1000</if_sid><match>abc</match><description>unreachable</description></rule></group>';
  const N1 = '<group name="t"><rule id="900200" level="3"><if_sid>2000</if_sid><match>foo</match><description>narrow</description></rule>'
    + '<rule id="900201" level="5"><if_sid>2000</if_sid><description>still reachable</description></rule></group>';
  const N2 = '<group name="t"><rule id="900300" level="4"><if_sid>3000</if_sid><if_fts />'
    + '<description>first time seen only</description></rule>'
    + '<rule id="900301" level="9"><if_sid>3000</if_sid><match>x</match><description>still reachable</description></rule></group>';
  const P2 = '<group name="t"><rule id="900400" level="3"><if_sid>4000</if_sid>'
    + '<mitre><id>T1095</id></mitre><description>eats all, only mitre metadata</description></rule>'
    + '<rule id="900401" level="5"><if_sid>4000</if_sid><match>y</match><description>unreachable</description></rule></group>';
  const N3 = '<group name="t"><rule id="900500" level="13" maxsize="7900"><if_sid>5000</if_sid>'
    + '<description>only fires on long log lines</description></rule>'
    + '<rule id="900501" level="5"><if_sid>5000</if_sid><url>z</url><description>still reachable</description></rule></group>';
  const P3 = '<group name="t"><rule id="900600" level="3"><if_sid>6000,6001</if_sid><description>eats both parents</description></rule>'
    + '<rule id="900601" level="5"><if_sid>6000</if_sid><match>w</match><description>unreachable</description></rule></group>';
  const N4 = '<group name="t"><rule id="900700" level="3"><if_sid>7000</if_sid><description>eats 7000 only</description></rule>'
    + '<rule id="900701" level="5"><if_sid>7000,7001</if_sid><match>v</match><description>reachable via 7001</description></rule></group>';

  const CTRL = [
    ['POS  built to be a shadow          ', P1, 1],
    ['POS  <mitre><id> is not a filter   ', P2, 1],
    ['POS  parent set is a subset        ', P3, 1],
    ['NEG  earlier rule has narrow match ', N1, 0],
    ['NEG  earlier rule has <if_fts/>    ', N2, 0],
    ['NEG  condition in maxsize attribute', N3, 0],
    ['NEG  later rule adds a new parent  ', N4, 0],
  ];
  say('== CONTROLS ==');
  let broken = 0;
  CTRL.forEach(c => {
    const got = score(parse(c[1], 'CTRL'));
    const ok = got.length === c[2];
    if (!ok) broken++;
    say(c[0] + ' expect ' + c[2] + ' got ' + got.length + '  '
      + (got.length ? got.map(p => p.eater + '>' + p.eaten).join(',') + '  ' : '') + (ok ? 'PASS' : 'FAIL'));
  });
  if (broken) return L.join('\n') + '\n\nSTOP: ' + broken + ' control(s) failed. No number below is usable.';

  // ================= STEP 1 - LOAD =================
  const treeRaw = get('https://api.github.com/repos/wazuh/wazuh/git/trees/' + SHA + '?recursive=1');
  if (!treeRaw) return L.join('\n') + '\nSTOP: could not read the tree.';
  const tree = JSON.parse(treeRaw);
  const files = tree.tree.filter(t => t.type === 'blob' && /^ruleset\/rules\/[^/]+\.xml$/.test(t.path));
  const declared = files.reduce((a, b) => a + (b.size || 0), 0);
  say('');
  say('== STEP 1 LOAD ==');
  // truncated=true would make the denominator a lower bound, not a count. Print it.
  say('tree.truncated=' + tree.truncated + ' | ruleset/rules/*.xml = ' + files.length
    + ' files | bytes declared in tree = ' + declared);
  let got = 0, bytes = 0;
  const miss = [];
  let all = [];
  files.forEach(t => {
    const body = get('https://raw.githubusercontent.com/wazuh/wazuh/' + SHA + '/' + t.path);
    if (body === null) { miss.push(t.path); return; }
    got++;
    bytes += new Blob([body]).size;
    all = all.concat(parse(body, t.path.replace('ruleset/rules/', '')));
  });
  say('read ' + got + '/' + files.length + ' | bytes actually received = ' + bytes
    + ' | matches tree: ' + (bytes === declared));
  if (miss.length) say('MISSED: ' + miss.join(' '));

  // ================= STEP 2 - EXTRACT =================
  const withSid = all.filter(r => r.ifsid);
  const uncond = all.filter(r => r.ifsid && !r.cond && !r.ow);
  say('');
  say('== STEP 2 EXTRACT ==');
  say('rules = ' + all.length + ' | with <if_sid> = ' + withSid.length
    + ' | of those, no filtering condition at all = ' + uncond.length);
  say('the unconditional ones, so anyone can open these exact lines:');
  uncond.forEach(r => say('  ' + r.f + ' rule ' + r.id + ' level=' + r.lvl + ' if_sid=' + r.ifsid));
  say('tags/attributes counted as conditions, so each call can be argued with:');
  const tally = {};
  all.forEach(r => (r.why ? r.why.split(',') : []).forEach(v => { tally[v] = (tally[v] || 0) + 1; }));
  say('  ' + Object.keys(tally).sort((a, b) => tally[b] - tally[a]).map(k => k + ':' + tally[k]).join(' '));

  // ================= STEP 3 - SCORE =================
  const pairs = score(all);
  const eaten = {}; pairs.forEach(p => { eaten[p.eaten] = 1; });
  say('');
  say('== STEP 3 SCORE ==');
  say('shadowed pairs = ' + pairs.length + ' | rules that can never fire = ' + Object.keys(eaten).length
    + ' | of ' + all.length + ' rules = ' + (100 * Object.keys(eaten).length / all.length).toFixed(2) + '%');

  // Weaker second number, and the assumption is stated: all 168 files concatenated in filename
  // order. Real load order is decided by ossec.conf and is not readable from the ruleset alone.
  const glob = scoreSeq(all.slice().sort((a, b) => (a.f < b.f ? -1 : a.f > b.f ? 1 : 0)));
  const eatenG = {}; glob.forEach(p => { eatenG[p.eaten] = 1; });
  say('weaker (files concatenated in filename order, ASSUMPTION not a measurement): pairs = '
    + glob.length + ' | rules = ' + Object.keys(eatenG).length);
  glob.forEach(p => say('  ' + p.ef + ' -> ' + p.f + ' | ' + p.eater + '>' + p.eaten + '@' + p.sid));

  say('');
  say('== SHADOWED PAIRS (file | eater>eaten@if_sid) ==');
  const byF = {};
  pairs.forEach(p => { (byF[p.f] = byF[p.f] || []).push(p.eater + '>' + p.eaten + '@' + p.sid); });
  Object.keys(byF).sort().forEach(f => say(f + ' | ' + byF[f].join(' ')));
  if (!pairs.length) say('(none)');
  return L.join('\n');
})()
