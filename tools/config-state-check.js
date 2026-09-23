// config-state-check.js
//
// Counts, in the default configuration shipped with wazuh/wazuh at a pinned commit, how many
// collection/module blocks are shipped explicitly off, explicitly on, declare no state at all,
// or exist only inside a comment.
//
// Companion to DEFAULT-CONFIG-STATES.md in this repo. Paste into a browser console on any
// origin without a restrictive CSP (example.com works). It uses synchronous XHR on purpose so
// the whole run returns one string. Both endpoints it reads (the tree API and the raw file
// host, spelled out in the code below) answer with Access-Control-Allow-Origin: *.
//
// It runs nine synthetic controls first and refuses to print any real number if one fails.

(() => {
  const SHA = 'a42268a27c555d9348d5598fb8751eaf4c8e9024';
  const get = (u) => {
    const x = new XMLHttpRequest();
    x.open('GET', u, false);
    x.send(null);
    return x.status === 200 ? x.responseText : null;
  };
  const L = [];
  const say = (s) => L.push(s);

  // Families treated as a collection or module block.
  const FAM = ['localfile', 'wodle', 'syscheck', 'rootcheck', 'sca', 'osquery',
    'vulnerability-detection', 'active-response', 'cluster', 'integration',
    'logging', 'global', 'remote', 'auth', 'agent-upgrade', 'task-manager',
    'indexer', 'socket', 'gcp-pubsub', 'github', 'office365', 'ms-graph'];

  // One level of <tag ...> ... </tag>. Deliberately not DOMParser: DOMParser repairs malformed
  // markup, which would hide exactly the kind of defect worth seeing in a shipped file.
  const blocks = (txt, tag) => {
    const out = [];
    const re = new RegExp('<' + tag + '(\\s[^>]*)?>', 'gi');
    let m;
    while ((m = re.exec(txt)) !== null) {
      const end = txt.indexOf('</' + tag + '>', m.index);
      if (end < 0) continue;
      out.push({ attr: m[1] || '', body: txt.slice(m.index, end + tag.length + 3) });
    }
    return out;
  };

  // The state tag belonging to THIS block: one level down, never a nested block's.
  //
  // There are two idioms, not one, and they are written inversely:
  //   <disabled>yes|no</disabled>   and   <enabled>yes|no</enabled>
  // The first version of this tool knew only the first idiom, so the four blocks using the
  // second fell through into "declares nothing". A checker that knows one spelling reads every
  // other spelling as absence.
  const state = (body, tag) => {
    let t = body.slice(tag.length + 1);
    t = t.replace(new RegExp('<(' + FAM.join('|') + ')(\\s[^>]*)?>[\\s\\S]*?</\\1>', 'gi'), '');
    const d = t.match(/<disabled>\s*(yes|no)\s*<\/disabled>/i);
    if (d) return { st: d[1].toLowerCase() === 'yes' ? 'off' : 'on', idiom: 'disabled' };
    const e = t.match(/<enabled>\s*(yes|no)\s*<\/enabled>/i);
    if (e) return { st: e[1].toLowerCase() === 'yes' ? 'on' : 'off', idiom: 'enabled' };
    return null;   // declares nothing. NOT assumed on: that default lives in the C source,
  };               // not in the shipped text, so claiming it would be a guess, not a reading.

  const scan = (raw, name) => {
    // Comment regions come out first. A block lying wholly inside one was shipped as
    // documentation, not as configuration, and is counted separately.
    const cmts = [];
    const live = raw.replace(/<!--[\s\S]*?-->/g, (s) => { cmts.push(s); return ' '; });
    const r = { off: [], on: [], undeclared: [], commented: [], idiom: {} };
    const walk = (txt, inComment) => {
      FAM.forEach(tag => blocks(txt, tag).forEach(b => {
        // Read the capture off the match object, not off the RegExp global: that global is set
        // by whatever regex ran last, so it is a side channel this loop cannot own.
        const nm = b.attr.match(/name\s*=\s*"([^"]*)"/i);
        const label = name + ':' + tag + (nm ? '(' + nm[1] + ')' : '');
        if (inComment) { r.commented.push(label); return; }
        const s = state(b.body, tag);
        if (!s) { r.undeclared.push(label); return; }
        r.idiom[s.idiom] = (r.idiom[s.idiom] || 0) + 1;
        r[s.st].push(label + '[' + s.idiom + ']');
      }));
    };
    walk(live, false);
    cmts.forEach(c => walk(c, true));
    return r;
  };

  // ---------------- controls, before any real file is touched ----------------
  const CTRL = [
    ['declares off', '<wodle name="t"><disabled>yes</disabled></wodle>', { off: 1, on: 0, undeclared: 0, commented: 0 }],
    ['declares on', '<wodle name="t"><disabled>no</disabled></wodle>', { off: 0, on: 1, undeclared: 0, commented: 0 }],
    ['declares nothing', '<localfile><location>/v/l/s</location></localfile>', { off: 0, on: 0, undeclared: 1, commented: 0 }],
    ['wholly inside a comment', '<!-- <wodle name="t"><disabled>yes</disabled></wodle> -->', { off: 0, on: 0, undeclared: 0, commented: 1 }],
    ['two blocks, one state each', '<wodle name="a"><disabled>yes</disabled></wodle><wodle name="b"><disabled>no</disabled></wodle>', { off: 1, on: 1, undeclared: 0, commented: 0 }],
    ['commented state inside a live block', '<wodle name="t"><!-- <disabled>yes</disabled> --><disabled>no</disabled></wodle>', { off: 0, on: 1, undeclared: 0, commented: 0 }],
    ['nested block state stays with the child', '<wodle name="p"><wodle name="c"><disabled>yes</disabled></wodle></wodle>', { off: 1, on: 0, undeclared: 1, commented: 0 }],
    ['second idiom, off', '<indexer><enabled>no</enabled></indexer>', { off: 1, on: 0, undeclared: 0, commented: 0 }],
    ['second idiom, on', '<indexer><enabled>yes</enabled></indexer>', { off: 0, on: 1, undeclared: 0, commented: 0 }],
  ];
  say('== controls ==');
  let bad = 0;
  CTRL.forEach(([name, txt, want]) => {
    const r = scan(txt, 'CTRL');
    const got = { off: r.off.length, on: r.on.length, undeclared: r.undeclared.length, commented: r.commented.length };
    const ok = Object.keys(want).every(k => got[k] === want[k]);
    if (!ok) bad++;
    say('  ' + (ok ? 'PASS' : 'FAIL') + ' | ' + name
      + ' | got off=' + got.off + ' on=' + got.on + ' undeclared=' + got.undeclared + ' commented=' + got.commented);
  });
  if (bad) return L.join('\n') + '\n\nSTOP: ' + bad + ' control(s) failed. No real number is valid from this run.';

  // ---------------- denominator ----------------
  const treeRaw = get('https://api.github.com/repos/wazuh/wazuh/git/trees/' + SHA + '?recursive=1');
  if (!treeRaw) return L.join('\n') + '\nSTOP: could not read the git tree.';
  const tree = JSON.parse(treeRaw);
  const files = tree.tree.filter(t => t.type === 'blob'
    && /^etc\/(ossec[a-z-]*\.conf|templates\/config\/.+)$/.test(t.path)
    && !/(internal_options|preloaded-vars|sca\.files|README)/.test(t.path));
  const declared = files.reduce((a, b) => a + (b.size || 0), 0);
  say('');
  say('== denominator ==');
  say('tree.truncated=' + tree.truncated + ' | files in scope = ' + files.length
    + ' | bytes declared by the tree = ' + declared);

  let got = 0, bytes = 0;
  const miss = [];
  const T = { off: [], on: [], undeclared: [], commented: [] };
  const IDIOM = {};
  files.forEach(t => {
    const body = get('https://raw.githubusercontent.com/wazuh/wazuh/' + SHA + '/' + t.path);
    if (body === null) { miss.push(t.path); return; }
    got++;
    bytes += new Blob([body]).size;
    const r = scan(body, t.path.replace(/^etc\//, ''));
    ['off', 'on', 'undeclared', 'commented'].forEach(k => { T[k] = T[k].concat(r[k]); });
    Object.keys(r.idiom).forEach(k => { IDIOM[k] = (IDIOM[k] || 0) + r.idiom[k]; });
  });
  say('files read = ' + got + '/' + files.length + ' | bytes received = ' + bytes
    + ' | byte-exact against tree: ' + (bytes === declared));
  if (miss.length) say('MISSED: ' + miss.join(' '));
  // Without truncated=false AND the byte match, the denominator is a lower bound, not a count.

  // ---------------- result ----------------
  const total = T.off.length + T.on.length + T.undeclared.length + T.commented.length;
  const binary = T.off.length + T.on.length;
  say('');
  say('== result ==');
  say('blocks shipped = ' + total);
  say('  explicitly off (<disabled>yes</disabled> or <enabled>no</enabled>)  = ' + T.off.length);
  say('  explicitly on  (<disabled>no</disabled>  or <enabled>yes</enabled>) = ' + T.on.length);
  say('  declares no state (neither idiom present)                           = ' + T.undeclared.length);
  say('  exists only inside a comment                                        = ' + T.commented.length);
  say('=> a binary on/off reading covers ' + binary + '/' + total
    + ' = ' + (100 * binary / total).toFixed(2) + '% of what is shipped.');

  say('');
  say('== state idioms (blocks that do declare) ==');
  say('  ' + Object.keys(IDIOM).sort().map(k => '<' + k + '>:' + IDIOM[k]).join('  ')
    + '  | distinct idioms = ' + Object.keys(IDIOM).length);

  say('');
  say('== shipped off, in full ==');
  T.off.forEach(s => say('  ' + s));

  say('');
  say('== exists only inside a comment ==');
  T.commented.forEach(s => say('  ' + s));

  const byFam = {};
  T.undeclared.forEach(s => { const k = s.split(':')[1]; byFam[k] = (byFam[k] || 0) + 1; });
  say('');
  say('== declares no state, by tag family ==');
  say('  ' + Object.keys(byFam).sort((a, b) => byFam[b] - byFam[a]).map(k => k + ':' + byFam[k]).join(' '));
  return L.join('\n');
})()
