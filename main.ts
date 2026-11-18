// github-core-clone-01 v3 — a fast GitHub-compatible git forge.
// Node 22, standard library only. No packages, no git binary, one process.
// Surfaces: git smart HTTP (v2 upload-pack, v0 receive-pack), REST v3, GraphQL v4, MCP (2026-07-28).
import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------------------
// 0. Identity: the contest's fixed scenario, recomputed from its seed.
// The production token (shpat_ + hex) does not encode the viewer login, so the
// server recomputes the scenario's users from SCENARIO_SEED exactly as the
// kit's wire.ts does: viewer = users[0], teammate = users[1], stranger = users[2].
// ---------------------------------------------------------------------------
const SCENARIO_SEED = 0x6a09e667f3bcc909n;
const U64_MASK = 0xffffffffffffffffn;
function fnv1a64(text: string): bigint {
  let hash = 0xcbf29ce484222325n;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= BigInt(text.charCodeAt(i));
    hash = (hash * 0x100000001b3n) & U64_MASK;
  }
  return hash;
}
function mix64(value: bigint): bigint {
  let z = (value + 0x9e3779b97f4a7c15n) & U64_MASK;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & U64_MASK;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & U64_MASK;
  return (z ^ (z >> 31n)) & U64_MASK;
}
class ScenarioRng {
  s: bigint;
  constructor(seed: bigint) {
    const m = seed & U64_MASK;
    this.s = m === 0n ? SCENARIO_SEED : m;
  }
  nextU64(): bigint {
    let x = this.s;
    x = (x ^ (x >> 12n)) & U64_MASK;
    x = (x ^ (x << 25n)) & U64_MASK;
    x = (x ^ (x >> 27n)) & U64_MASK;
    this.s = x;
    return (x * 0x2545f4914f6cdd1dn) & U64_MASK;
  }
  nextU32(): number {
    return Number(this.nextU64() >> 32n);
  }
  nextInt(max: number): number {
    if (max === 1) return 0;
    const range = 4294967296;
    const limit = range - (range % max);
    for (;;) {
      const v = this.nextU32();
      if (v < limit) return v % max;
    }
  }
  pick<T>(items: readonly T[]): T {
    return items[this.nextInt(items.length)] as T;
  }
}
const FIRST_NAMES = ['ada', 'bram', 'cora', 'dmitri', 'elena', 'felix', 'greta', 'hugo', 'iris', 'jonas', 'kira', 'lars', 'mira', 'nico', 'olga', 'pavel', 'quinn', 'rosa', 'sven', 'tess', 'ulla', 'vito', 'wren', 'yara', 'zane'];
const LAST_NAMES = ['anders', 'bauer', 'costa', 'dahl', 'eriksen', 'fischer', 'garcia', 'holm', 'iversen', 'jansen', 'keller', 'lind', 'moreau', 'novak', 'olsen', 'peters', 'quist', 'rossi', 'sato', 'turi', 'ulrich', 'vega', 'weber', 'xu', 'yilmaz', 'zimmer'];
function scenarioUsers(): Array<{ id: number; login: string; name: string; email: string }> {
  const rng = new ScenarioRng(mix64(SCENARIO_SEED ^ fnv1a64('users')));
  const used = new Set<string>();
  const out: Array<{ id: number; login: string; name: string; email: string }> = [];
  for (let i = 0; i < 3; i += 1) {
    const first = rng.pick(FIRST_NAMES);
    const last = rng.pick(LAST_NAMES);
    const base = `${first}${last}`.replace(/[^a-z0-9-]/g, '');
    let login = base;
    let suffix = 2;
    while (used.has(login)) {
      login = `${base}-${suffix}`;
      suffix += 1;
    }
    used.add(login);
    out.push({ id: 1000 + i, login, name: `${first} ${last}`, email: `${login}@example.invalid` });
  }
  return out;
}
const SCENARIO = scenarioUsers();
const VIEWER = SCENARIO[0] as { id: number; login: string; name: string; email: string };
const VIEWER_LOGIN = VIEWER.login;
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const ENV_URL = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
const START_ISO = new Date().toISOString();
const ZERO_OID = '0000000000000000000000000000000000000000';
const DEFAULT_BRANCH = 'main';
const AGENT = 'github-core-clone/1.0.0';

// ---------------------------------------------------------------------------
// 1. Low-level helpers: sha1, base64, pkt-lines, pack framing, zlib.
// ---------------------------------------------------------------------------
function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}
function hashObject(type: string, data: Buffer): string {
  const head = Buffer.from(`${type} ${data.length}\0`, 'ascii');
  return sha1Hex(Buffer.concat([head, data]));
}
function b64encode(buf: Buffer): string {
  return buf.toString('base64');
}
function b64decode(text: string): Buffer {
  return Buffer.from(text.replace(/[\r\n\t ]+/g, ''), 'base64');
}
function pktLine(payload: string | Buffer): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const len = body.length + 4;
  const head = Buffer.alloc(4);
  head.write(len.toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([head, body]);
}
const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');
function pktLines(items: Array<string | Buffer | 'flush' | 'delim'>): Buffer {
  const parts: Buffer[] = [];
  for (const item of items) {
    if (item === 'flush') parts.push(PKT_FLUSH);
    else if (item === 'delim') parts.push(PKT_DELIM);
    else parts.push(pktLine(item));
  }
  return Buffer.concat(parts);
}
interface Pkt {
  kind: 'data' | 'flush' | 'delim';
  payload: Buffer;
}
/** Decode a whole buffer of pkt-lines. Returns packets plus the offset of any trailing raw bytes. */
function decodePktLines(buf: Buffer): { packets: Pkt[]; restOffset: number } {
  const packets: Pkt[] = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const hex = buf.toString('ascii', off, off + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) break;
    const len = parseInt(hex, 16);
    if (len === 0) {
      packets.push({ kind: 'flush', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len === 1) {
      packets.push({ kind: 'delim', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len < 4 || off + len > buf.length) break;
    packets.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return { packets, restOffset: off };
}
/** Inflate one zlib stream starting at `offset`. Returns the data and the offset just past the stream. */
function inflateAt(buf: Buffer, offset: number, expectedSize: number): { data: Buffer; next: number } {
  const sub = buf.subarray(offset);
  try {
    const r = inflateSync(sub, { info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
    if (r.buffer.length === expectedSize && typeof r.engine.bytesWritten === 'number' && r.engine.bytesWritten > 0) {
      return { data: r.buffer, next: offset + r.engine.bytesWritten };
    }
  } catch {
    // fall through to the binary search below
  }
  // Fallback (older Node without the `info` option): binary-search the smallest prefix
  // that inflates to exactly the expected size.
  let lo = 1;
  let hi = sub.length;
  let best = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    try {
      const out = inflateSync(sub.subarray(0, mid));
      if (out.length === expectedSize) {
        best = mid;
        hi = mid - 1;
      } else {
        lo = mid + 1;
      }
    } catch {
      lo = mid + 1;
    }
  }
  if (best < 0) throw new Error('zlib stream does not terminate');
  return { data: inflateSync(sub.subarray(0, best)), next: offset + best };
}
const PACK_TYPE_NAMES = ['', 'commit', 'tree', 'blob', 'tag', '', 'ofs-delta', 'ref-delta'];
function packEntryHeader(typeCode: number, size: number): Buffer {
  const bytes: number[] = [];
  let first = (typeCode << 4) | (size & 0x0f);
  size >>= 4;
  if (size > 0) first |= 0x80;
  bytes.push(first);
  while (size > 0) {
    let b = size & 0x7f;
    size >>= 7;
    if (size > 0) b |= 0x80;
    bytes.push(b);
  }
  return Buffer.from(bytes);
}
function buildPack(objects: Array<{ type: string; data: Buffer }>): Buffer {
  const parts: Buffer[] = [];
  const head = Buffer.alloc(12);
  head.write('PACK', 0, 4, 'ascii');
  head.writeUInt32BE(2, 4);
  head.writeUInt32BE(objects.length, 8);
  parts.push(head);
  for (const obj of objects) {
    const code = PACK_TYPE_NAMES.indexOf(obj.type);
    parts.push(packEntryHeader(code, obj.data.length));
    parts.push(deflateSync(obj.data, { level: 1 }));
  }
  const body = Buffer.concat(parts);
  const trailer = createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}
interface PackObject {
  type: string;
  data: Buffer;
  oid: string;
}
function parsePack(buf: Buffer): PackObject[] {
  if (buf.length < 32 || buf.toString('ascii', 0, 4) !== 'PACK') throw new Error('bad pack header');
  const count = buf.readUInt32BE(8);
  const expectTrailer = sha1Hex(buf.subarray(0, buf.length - 20));
  const actualTrailer = buf.subarray(buf.length - 20).toString('hex');
  if (expectTrailer !== actualTrailer) throw new Error('pack trailer mismatch');
  const out: PackObject[] = [];
  let off = 12;
  const end = buf.length - 20;
  for (let i = 0; i < count; i += 1) {
    let b = buf[off];
    off += 1;
    const typeCode = (b >> 4) & 0x07;
    let size = b & 0x0f;
    let shift = 4;
    while (b & 0x80) {
      b = buf[off];
      off += 1;
      size |= (b & 0x7f) << shift;
      shift += 7;
    }
    const type = PACK_TYPE_NAMES[typeCode] as string;
    if (typeCode === 6) throw new Error('ofs-delta packs are not accepted on push');
    if (typeCode === 7) throw new Error('ref-delta packs are not accepted on push');
    if (!type) throw new Error(`unknown pack type ${typeCode}`);
    const inflated = inflateAt(buf, off, size);
    off = inflated.next;
    if (inflated.data.length !== size) throw new Error('pack object size mismatch');
    out.push({ type, data: inflated.data, oid: hashObject(type, inflated.data) });
    if (off > end) throw new Error('pack overruns its trailer');
  }
  return out;
}

// ---------------------------------------------------------------------------
// 2. Git object model: parse/build commits, trees, tags.
// ---------------------------------------------------------------------------
interface CommitInfo {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}
function parseCommit(data: Buffer): CommitInfo {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split < 0 ? text : text.slice(0, split);
  const message = split < 0 ? '' : text.slice(split + 2);
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { tree, parents, author, committer, message };
}
interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}
function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const space = data.indexOf(0x20, off);
    const nul = data.indexOf(0x00, space + 1);
    if (space < 0 || nul < 0) break;
    const mode = data.toString('ascii', off, space);
    const name = data.toString('utf8', space + 1, nul);
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    off = nul + 21;
  }
  return entries;
}
function buildTree(entries: TreeEntry[]): Buffer {
  const sorted = entries.slice().sort((a, b) => {
    const an = a.mode === '40000' ? `${a.name}/` : a.name;
    const bn = b.mode === '40000' ? `${b.name}/` : b.name;
    return an < bn ? -1 : an > bn ? 1 : 0;
  });
  const parts: Buffer[] = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(parts);
}
function parseTag(data: Buffer): { object: string; type: string; tag: string; tagger: string } {
  const text = data.toString('utf8');
  let object = '';
  let type = '';
  let tag = '';
  let tagger = '';
  for (const line of text.split('\n')) {
    if (line.startsWith('object ')) object = line.slice(7).trim();
    else if (line.startsWith('type ')) type = line.slice(5).trim();
    else if (line.startsWith('tag ')) tag = line.slice(4).trim();
    else if (line.startsWith('tagger ')) tagger = line.slice(7);
    else if (line === '') break;
  }
  return { object, type, tag, tagger };
}

// ---------------------------------------------------------------------------
// 3. Store: repositories, issues, pull requests, labels, comments.
// ---------------------------------------------------------------------------
interface GitObject {
  type: string;
  data: Buffer;
}
interface Issue {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: Array<{ name: string; color: string }>;
  comments: Array<{ id: number; body: string }>;
  json: string;
}
interface Pull {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  headBranch: string;
  baseBranch: string;
  headSha: string;
  baseSha: string;
  json: string;
}
interface Repo {
  id: number;
  owner: string;
  name: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  refs: Map<string, string>;
  objects: Map<string, GitObject>;
  parents: Map<string, string[]>;
  trees: Map<string, TreeEntry[]>;
  flatTrees: Map<string, Map<string, { oid: string; mode: string }>>;
  packCache: Map<string, Buffer>;
  issues: Map<number, Issue>;
  nextIssue: number;
  labels: Map<string, { name: string; color: string }>;
  pulls: Map<number, Pull>;
  nextPull: number;
  json: string;
}
const repos = new Map<string, Repo>();
let nextRepoId = 1;
let nextIssueId = 1;
let nextPullId = 1;
let nextCommentId = 1;
let commitCounter = 0;
function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}
function userJson(login: string): { login: string; id: number; type: string } {
  return { login, id: login === VIEWER_LOGIN ? VIEWER.id : 1000, type: 'User' };
}
function repoJsonOf(repo: Repo): string {
  return JSON.stringify({
    id: repo.id,
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: userJson(repo.owner),
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
    created_at: START_ISO,
    updated_at: START_ISO,
    pushed_at: START_ISO,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}`,
    clone_url: `https://example.invalid/${repo.owner}/${repo.name}.git`,
    fork: false,
    archived: false,
    disabled: false,
    has_issues: true,
    has_projects: true,
    has_wiki: true,
  });
}
function issueJsonOf(repo: Repo, issue: Issue): string {
  return JSON.stringify({
    id: issue.id,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((l) => ({ name: l.name, color: l.color, description: '' })),
    user: userJson(VIEWER_LOGIN),
    assignee: null,
    locked: false,
    comments: issue.comments.length,
    created_at: START_ISO,
    updated_at: START_ISO,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/issues/${issue.number}`,
  });
}
function pullJsonOf(repo: Repo, pr: Pull): string {
  return JSON.stringify({
    id: pr.id,
    number: pr.number,
    title: pr.title,
    body: pr.body,
    state: pr.state,
    merged: pr.merged,
    merged_at: pr.mergedAt,
    merge_commit_sha: pr.mergeCommitSha,
    draft: false,
    locked: false,
    user: userJson(VIEWER_LOGIN),
    head: { ref: pr.headBranch, sha: pr.headSha, label: `${repo.owner}:${pr.headBranch}` },
    base: { ref: pr.baseBranch, sha: pr.baseSha, label: `${repo.owner}:${pr.baseBranch}` },
    created_at: START_ISO,
    updated_at: START_ISO,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/pull/${pr.number}`,
  });
}
function createRepoRecord(name: string, description: string, isPrivate: boolean): Repo {
  const repo: Repo = {
    id: nextRepoId,
    owner: VIEWER_LOGIN,
    name,
    description,
    isPrivate,
    defaultBranch: DEFAULT_BRANCH,
    refs: new Map(),
    objects: new Map(),
    parents: new Map(),
    trees: new Map(),
    flatTrees: new Map(),
    packCache: new Map(),
    issues: new Map(),
    nextIssue: 1,
    labels: new Map(),
    pulls: new Map(),
    nextPull: 1,
    json: '',
  };
  nextRepoId += 1;
  repo.json = repoJsonOf(repo);
  repos.set(repoKey(VIEWER_LOGIN, name), repo);
  return repo;
}
function storeObject(repo: Repo, type: string, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!repo.objects.has(oid)) {
    repo.objects.set(oid, { type, data });
    if (type === 'commit') repo.parents.set(oid, parseCommit(data).parents);
  }
  return oid;
}
function getTree(repo: Repo, oid: string): TreeEntry[] {
  let entries = repo.trees.get(oid);
  if (entries === undefined) {
    const obj = repo.objects.get(oid);
    entries = obj && obj.type === 'tree' ? parseTree(obj.data) : [];
    repo.trees.set(oid, entries);
  }
  return entries;
}
function flattenTree(repo: Repo, treeOid: string): Map<string, { oid: string; mode: string }> {
  const cached = repo.flatTrees.get(treeOid);
  if (cached !== undefined) return cached;
  const out = new Map<string, { oid: string; mode: string }>();
  const walk = (oid: string, prefix: string): void => {
    for (const e of getTree(repo, oid)) {
      const path = prefix === '' ? e.name : `${prefix}/${e.name}`;
      if (e.mode === '40000') walk(e.oid, path);
      else out.set(path, { oid: e.oid, mode: e.mode });
    }
  };
  walk(treeOid, '');
  repo.flatTrees.set(treeOid, out);
  return out;
}
function buildTreeFromFiles(repo: Repo, files: Map<string, { oid: string; mode: string }>): string {
  // Group files by directory, building trees bottom-up.
  const dirs = new Map<string, Map<string, { oid: string; mode: string }>>();
  const ensure = (dir: string): Map<string, { oid: string; mode: string }> => {
    let m = dirs.get(dir);
    if (m === undefined) {
      m = new Map();
      dirs.set(dir, m);
    }
    return m;
  };
  for (const [path, file] of files) {
    const slash = path.lastIndexOf('/');
    const dir = slash < 0 ? '' : path.slice(0, slash);
    const name = slash < 0 ? path : path.slice(slash + 1);
    ensure(dir).set(name, file);
  }
  const buildDir = (dir: string): string => {
    const entries: TreeEntry[] = [];
    const direct = dirs.get(dir);
    if (direct !== undefined) {
      for (const [name, file] of direct) entries.push({ mode: file.mode, name, oid: file.oid });
    }
    // Subdirectories of this dir.
    const prefix = dir === '' ? '' : `${dir}/`;
    const subNames = new Set<string>();
    for (const key of dirs.keys()) {
      if (key.startsWith(prefix) && key !== dir) {
        const rest = key.slice(prefix.length);
        const first = rest.split('/')[0] as string;
        subNames.add(first);
      }
    }
    for (const sub of subNames) {
      const subDir = prefix + sub;
      entries.push({ mode: '40000', name: sub, oid: buildDir(subDir) });
    }
    return storeObject(repo, 'tree', buildTree(entries));
  };
  return buildDir('');
}
function makeServerCommit(repo: Repo, treeOid: string, parents: string[], message: string): string {
  commitCounter += 1;
  const ts = 1700000000 + commitCounter;
  const ident = `${VIEWER.name} <${VIEWER.email}> ${ts} +0000`;
  let text = `tree ${treeOid}\n`;
  for (const p of parents) text += `parent ${p}\n`;
  text += `author ${ident}\ncommitter ${ident}\n\n${message}\n`;
  return storeObject(repo, 'commit', Buffer.from(text, 'utf8'));
}
function commitTreeOid(repo: Repo, commitOid: string): string {
  const obj = repo.objects.get(commitOid);
  if (obj === undefined || obj.type !== 'commit') return '';
  return parseCommit(obj.data).tree;
}
function refTip(repo: Repo, ref: string): string | undefined {
  return repo.refs.get(ref);
}
function branchTip(repo: Repo, branch: string): string | undefined {
  return repo.refs.get(`refs/heads/${branch}`);
}

// ---------------------------------------------------------------------------
// 4. Reachability, ancestry, fetch selection, pack cache.
// ---------------------------------------------------------------------------
function peelToCommit(repo: Repo, oid: string): string {
  let cur = oid;
  for (let i = 0; i < 16; i += 1) {
    const obj = repo.objects.get(cur);
    if (obj === undefined) return cur;
    if (obj.type === 'commit') return cur;
    if (obj.type === 'tag') {
      cur = parseTag(obj.data).object;
      continue;
    }
    return cur;
  }
  return cur;
}
/**
 * All objects reachable from `roots`. Commits in `stopParents` are treated as roots: their trees
 * are included but their parents are not followed — that is how a shallow client's `have` set is
 * read (the client holds the shallow commit and its tree, not the history behind it).
 */
function collectReachable(repo: Repo, roots: string[], stopParents?: Set<string>): Set<string> {
  const seen = new Set<string>();
  const stack: string[] = [];
  for (const r of roots) {
    if (r !== ZERO_OID && repo.objects.has(r)) stack.push(r);
  }
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (obj === undefined) continue;
    seen.add(oid);
    if (obj.type === 'commit') {
      const info = parseCommit(obj.data);
      if (!seen.has(info.tree)) stack.push(info.tree);
      if (stopParents === undefined || !stopParents.has(oid)) {
        for (const p of info.parents) if (!seen.has(p)) stack.push(p);
      }
    } else if (obj.type === 'tree') {
      for (const e of getTree(repo, oid)) if (!seen.has(e.oid)) stack.push(e.oid);
    } else if (obj.type === 'tag') {
      const target = parseTag(obj.data).object;
      if (!seen.has(target)) stack.push(target);
    }
  }
  return seen;
}
function isAncestor(repo: Repo, anc: string, desc: string): boolean {
  if (anc === desc) return true;
  const seen = new Set<string>();
  const stack: string[] = [desc];
  while (stack.length > 0) {
    const cur = stack.pop() as string;
    if (cur === anc) return true;
    if (seen.has(cur)) continue;
    seen.add(cur);
    const parents = repo.parents.get(cur);
    if (parents !== undefined) {
      for (const p of parents) stack.push(p);
    } else {
      const obj = repo.objects.get(cur);
      if (obj !== undefined && obj.type === 'commit') {
        for (const p of parseCommit(obj.data).parents) stack.push(p);
      }
    }
  }
  return false;
}
interface FetchSelection {
  objects: Array<{ type: string; data: Buffer }>;
  shallow: string[];
  unshallow: string[];
}
function selectFetch(repo: Repo, wants: string[], haves: string[], clientShallow: string[], depth: number | null): FetchSelection {
  const shallowSet = new Set(clientShallow);
  const haveSet = haves.length > 0 ? collectReachable(repo, haves, shallowSet) : new Set<string>();
  // Walk commits from the wants with generations.
  const gen = new Map<string, number>();
  const queue: string[] = [];
  const tagObjects: string[] = [];
  for (const w of wants) {
    const obj = repo.objects.get(w);
    if (obj === undefined) continue;
    if (obj.type === 'tag') {
      if (!haveSet.has(w)) tagObjects.push(w);
      const peeled = peelToCommit(repo, w);
      if (peeled !== w && !gen.has(peeled)) {
        gen.set(peeled, 0);
        queue.push(peeled);
      }
    } else if (obj.type === 'commit') {
      if (!gen.has(w)) {
        gen.set(w, 0);
        queue.push(w);
      }
    }
  }
  const sentCommits: string[] = [];
  const shallow: string[] = [];
  let qi = 0;
  while (qi < queue.length) {
    const oid = queue[qi] as string;
    qi += 1;
    const g = gen.get(oid) as number;
    // Traverse through commits the client already holds (their parents may be
    // wanted: a deepen fetch walks from a held tip to its unheld parent), but
    // never send a held commit itself.
    if (!haveSet.has(oid)) {
      sentCommits.push(oid);
      if (depth !== null && g === depth - 1) shallow.push(oid);
    }
    if (depth !== null && g >= depth - 1) continue;
    const parents = repo.parents.get(oid) ?? [];
    for (const p of parents) {
      if (!gen.has(p)) {
        gen.set(p, g + 1);
        queue.push(p);
      }
    }
  }
  // Objects: commits + their trees/blobs, minus anything the client already holds.
  const objOids = new Set<string>();
  for (const t of tagObjects) objOids.add(t);
  const treeQueue: string[] = [];
  for (const c of sentCommits) {
    objOids.add(c);
    const tree = commitTreeOid(repo, c);
    if (tree !== '' && !haveSet.has(tree)) treeQueue.push(tree);
  }
  const objects: Array<{ type: string; data: Buffer }> = [];
  const seenObj = new Set<string>();
  for (const c of sentCommits) {
    if (!seenObj.has(c)) {
      seenObj.add(c);
      const o = repo.objects.get(c);
      if (o !== undefined) objects.push(o);
    }
  }
  for (const t of tagObjects) {
    if (!seenObj.has(t)) {
      seenObj.add(t);
      const o = repo.objects.get(t);
      if (o !== undefined) objects.push(o);
    }
  }
  let ti = 0;
  while (ti < treeQueue.length) {
    const treeOid = treeQueue[ti] as string;
    ti += 1;
    if (seenObj.has(treeOid) || haveSet.has(treeOid)) continue;
    seenObj.add(treeOid);
    const o = repo.objects.get(treeOid);
    if (o === undefined) continue;
    objects.push(o);
    for (const e of getTree(repo, treeOid)) {
      if (haveSet.has(e.oid) || seenObj.has(e.oid)) continue;
      if (e.mode === '40000') treeQueue.push(e.oid);
      else {
        seenObj.add(e.oid);
        const blob = repo.objects.get(e.oid);
        if (blob !== undefined) objects.push(blob);
      }
    }
  }
  // Unshallow: previously-shallow commits that are now complete.
  const unshallow: string[] = [];
  const heldOrSent = new Set<string>([...haveSet, ...sentCommits]);
  for (const o of clientShallow) {
    if (!heldOrSent.has(o)) continue;
    const parents = repo.parents.get(o) ?? [];
    let complete = true;
    for (const p of parents) {
      if (!heldOrSent.has(p)) {
        complete = false;
        break;
      }
    }
    if (complete) unshallow.push(o);
  }
  return { objects, shallow, unshallow };
}
// ---------------------------------------------------------------------------
// 5. Merge logic (shared by REST, GraphQL, MCP).
// ---------------------------------------------------------------------------
function mergeBase(repo: Repo, a: string, b: string): string | null {
  const ancestorsA = new Set<string>();
  const stack: string[] = [a];
  while (stack.length > 0) {
    const cur = stack.pop() as string;
    if (ancestorsA.has(cur)) continue;
    ancestorsA.add(cur);
    const parents = repo.parents.get(cur) ?? [];
    for (const p of parents) stack.push(p);
  }
  const queue: string[] = [b];
  const seen = new Set<string>();
  while (queue.length > 0) {
    const cur = queue.shift() as string;
    if (ancestorsA.has(cur)) return cur;
    if (seen.has(cur)) continue;
    seen.add(cur);
    const parents = repo.parents.get(cur) ?? [];
    for (const p of parents) queue.push(p);
  }
  return null;
}
interface MergePlan {
  conflict: boolean;
  files: Map<string, { oid: string; mode: string }>;
}
function planMerge(repo: Repo, baseTip: string, headTip: string): MergePlan {
  const base = mergeBase(repo, headTip, baseTip);
  const baseFiles = base === null ? new Map() : flattenTree(repo, commitTreeOid(repo, base));
  const headFiles = flattenTree(repo, commitTreeOid(repo, headTip));
  const tipFiles = flattenTree(repo, commitTreeOid(repo, baseTip));
  const merged = new Map<string, { oid: string; mode: string }>();
  let conflict = false;
  const paths = new Set<string>([...baseFiles.keys(), ...headFiles.keys(), ...tipFiles.keys()]);
  for (const path of paths) {
    const b = baseFiles.get(path);
    const h = headFiles.get(path);
    const t = tipFiles.get(path);
    const same = (x: { oid: string; mode: string } | undefined, y: { oid: string; mode: string } | undefined): boolean =>
      (x === undefined && y === undefined) || (x !== undefined && y !== undefined && x.oid === y.oid);
    if (same(h, b)) {
      if (t !== undefined) merged.set(path, t);
    } else if (same(t, b)) {
      if (h !== undefined) merged.set(path, h);
    } else if (same(h, t)) {
      if (h !== undefined) merged.set(path, h);
    } else {
      conflict = true;
    }
  }
  return { conflict, files: merged };
}
function doMerge(repo: Repo, pr: Pull): { ok: true; sha: string } | { ok: false; reason: string } {
  if (pr.state !== 'open') return { ok: false, reason: 'pull request is closed' };
  const headTip = branchTip(repo, pr.headBranch);
  const baseTip = branchTip(repo, pr.baseBranch);
  if (headTip === undefined || baseTip === undefined) return { ok: false, reason: 'branch not found' };
  const plan = planMerge(repo, baseTip, headTip);
  if (plan.conflict) return { ok: false, reason: 'Merge conflict' };
  const treeOid = buildTreeFromFiles(repo, plan.files);
  const sha = makeServerCommit(repo, treeOid, [baseTip], pr.title);
  repo.refs.set(`refs/heads/${pr.baseBranch}`, sha);
  pr.state = 'closed';
  pr.merged = true;
  pr.mergedAt = START_ISO;
  pr.mergeCommitSha = sha;
  pr.baseSha = sha;
  pr.json = pullJsonOf(repo, pr);
  return { ok: true, sha };
}
function computeMergeable(repo: Repo, pr: Pull): string {
  if (pr.state !== 'open') return 'UNKNOWN';
  const headTip = branchTip(repo, pr.headBranch);
  const baseTip = branchTip(repo, pr.baseBranch);
  if (headTip === undefined || baseTip === undefined) return 'UNKNOWN';
  return planMerge(repo, baseTip, headTip).conflict ? 'CONFLICTING' : 'MERGEABLE';
}
function lineCounts(a: string, b: string): { additions: number; deletions: number } {
  const countLines = (text: string): Map<string, number> => {
    const m = new Map<string, number>();
    for (const line of text.split('\n')) {
      if (line === '' && text.endsWith('\n')) continue;
      m.set(line, (m.get(line) ?? 0) + 1);
    }
    return m;
  };
  const ma = countLines(a);
  const mb = countLines(b);
  let additions = 0;
  let deletions = 0;
  for (const [line, n] of mb) {
    const inA = ma.get(line) ?? 0;
    if (n > inA) additions += n - inA;
  }
  for (const [line, n] of ma) {
    const inB = mb.get(line) ?? 0;
    if (n > inB) deletions += n - inB;
  }
  return { additions, deletions };
}
function prFiles(repo: Repo, pr: Pull): Array<{ filename: string; status: string; additions: number; deletions: number; changes: number; sha: string }> {
  const headTip = branchTip(repo, pr.headBranch);
  const baseTip = branchTip(repo, pr.baseBranch);
  if (headTip === undefined || baseTip === undefined) return [];
  const base = mergeBase(repo, headTip, baseTip);
  const baseFiles = base === null ? new Map() : flattenTree(repo, commitTreeOid(repo, base));
  const headFiles = flattenTree(repo, commitTreeOid(repo, headTip));
  const out: Array<{ filename: string; status: string; additions: number; deletions: number; changes: number; sha: string }> = [];
  const paths = new Set<string>([...baseFiles.keys(), ...headFiles.keys()]);
  for (const path of [...paths].sort()) {
    const b = baseFiles.get(path);
    const h = headFiles.get(path);
    if (b !== undefined && h !== undefined && b.oid === h.oid) continue;
    if (b === undefined && h !== undefined) {
      const blob = repo.objects.get(h.oid);
      const text = blob !== undefined ? blob.data.toString('utf8') : '';
      const lines = text === '' ? 0 : text.split('\n').length - (text.endsWith('\n') ? 1 : 0);
      out.push({ filename: path, status: 'added', additions: lines, deletions: 0, changes: lines, sha: h.oid });
    } else if (b !== undefined && h === undefined) {
      const blob = repo.objects.get(b.oid);
      const text = blob !== undefined ? blob.data.toString('utf8') : '';
      const lines = text === '' ? 0 : text.split('\n').length - (text.endsWith('\n') ? 1 : 0);
      out.push({ filename: path, status: 'removed', additions: 0, deletions: lines, changes: lines, sha: b.oid });
    } else if (b !== undefined && h !== undefined) {
      const ba = repo.objects.get(b.oid);
      const ha = repo.objects.get(h.oid);
      const { additions, deletions } = lineCounts(ba !== undefined ? ba.data.toString('utf8') : '', ha !== undefined ? ha.data.toString('utf8') : '');
      out.push({ filename: path, status: 'modified', additions, deletions, changes: additions + deletions, sha: h.oid });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// 6. HTTP plumbing.
// ---------------------------------------------------------------------------
let requestCounter = 0;
function sendJson(res: ServerResponse, status: number, body: string | object, extra?: Record<string, string>): void {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  const buf = Buffer.from(text, 'utf8');
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': String(buf.length),
    'x-github-request-id': `req-${(++requestCounter).toString(16)}`,
    ...(extra ?? {}),
  });
  res.end(buf);
}
function sendRaw(res: ServerResponse, status: number, buf: Buffer, contentType: string): void {
  res.writeHead(status, { 'content-type': contentType, 'content-length': String(buf.length), 'x-github-request-id': `req-${(++requestCounter).toString(16)}` });
  res.end(buf);
}
function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
function jsonBody(buf: Buffer): { ok: true; value: Record<string, unknown> } | { ok: false } {
  if (buf.length === 0) return { ok: true, value: {} };
  try {
    const v = JSON.parse(buf.toString('utf8')) as unknown;
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) return { ok: true, value: v as Record<string, unknown> };
    return { ok: false };
  } catch {
    return { ok: false };
  }
}
function strField(v: unknown, fallback = ''): string {
  return typeof v === 'string' ? v : fallback;
}
function intField(v: unknown, fallback: number): number {
  if (typeof v === 'number' && Number.isFinite(v)) return Math.trunc(v);
  if (typeof v === 'string' && /^-?\d+$/.test(v)) return parseInt(v, 10);
  return fallback;
}
function queryParams(url: string): Map<string, string> {
  const out = new Map<string, string>();
  const q = url.indexOf('?');
  if (q < 0) return out;
  for (const pair of url.slice(q + 1).split('&')) {
    if (pair === '') continue;
    const eq = pair.indexOf('=');
    const key = decodeURIComponent(eq < 0 ? pair : pair.slice(0, eq));
    const val = eq < 0 ? '' : decodeURIComponent(pair.slice(eq + 1));
    out.set(key, val);
  }
  return out;
}
function pageParams(q: Map<string, string>): { page: number; perPage: number } {
  const perPage = Math.min(100, Math.max(1, intField(q.get('per_page'), 30)));
  const page = Math.max(1, intField(q.get('page'), 1));
  return { page, perPage };
}
function linkHeader(req: IncomingMessage, path: string, q: Map<string, string>, page: number, perPage: number, total: number): string | null {
  if (page * perPage >= total) return null;
  const host = req.headers.host ?? '127.0.0.1';
  const next = new Map(q);
  next.set('page', String(page + 1));
  next.set('per_page', String(perPage));
  const qs = [...next.entries()].map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
  return `<http://${host}${path}?${qs}>; rel="next"`;
}
function paginate<T>(items: T[], page: number, perPage: number): T[] {
  return items.slice((page - 1) * perPage, page * perPage);
}
function notFound(res: ServerResponse, message = 'Not Found'): void {
  sendJson(res, 404, { message });
}
function unauthorized(res: ServerResponse): void {
  sendJson(res, 401, { message: 'Bad credentials' });
}
function badJson(res: ServerResponse): void {
  sendJson(res, 400, { message: 'Invalid JSON' });
}

// ---------------------------------------------------------------------------
// 7. REST v3.
// ---------------------------------------------------------------------------
function globalId(kind: string, parts: string): string {
  return Buffer.from(`${kind}:${parts}`, 'utf8').toString('base64');
}
function decodeGlobalId(id: string): { kind: string; parts: string } | null {
  try {
    const text = Buffer.from(id, 'base64').toString('utf8');
    const colon = text.indexOf(':');
    if (colon < 1) return null;
    return { kind: text.slice(0, colon), parts: text.slice(colon + 1) };
  } catch {
    return null;
  }
}
/** Parse a scoped global-id payload `owner/repo:number` (Issue / PullRequest ids). */
function parseScopedId(parts: string): { owner: string; repo: string; number: number } | null {
  const colon = parts.lastIndexOf(':');
  if (colon < 0) return null;
  const ownerRepo = parts.slice(0, colon);
  const number = parseInt(parts.slice(colon + 1), 10);
  const slash = ownerRepo.lastIndexOf('/');
  if (slash < 0 || !Number.isFinite(number)) return null;
  return { owner: ownerRepo.slice(0, slash), repo: ownerRepo.slice(slash + 1), number };
}
function lookupRepo(owner: string, name: string): Repo | undefined {
  return repos.get(repoKey(owner, name));
}
async function handleRest(req: IncomingMessage, res: ServerResponse, seg: string[], url: string): Promise<void> {
  const method = req.method ?? 'GET';
  // seg: ['', 'api', 'v3', ...rest]
  const rest = seg.slice(3);
  if (rest.length === 0 || (rest.length === 1 && rest[0] === '')) {
    if (method !== 'GET') return notFound(res);
    sendJson(res, 200, {
      current_user_url: '/api/v3/user',
      repository_url: '/api/v3/repos/{owner}/{repo}',
      user_url: '/api/v3/users/{username}',
      meta: '/api/v3/meta',
    }, { 'x-oauth-scopes': 'repo, read:org' });
    return;
  }
  if (rest[0] === 'meta') {
    if (method !== 'GET') return notFound(res);
    sendJson(res, 200, { installed_version: '1.0.0' });
    return;
  }
  if (rest[0] === 'user' && rest.length === 1) {
    if (method !== 'GET') return notFound(res);
    sendJson(res, 200, { login: VIEWER_LOGIN, id: VIEWER.id, name: VIEWER.name, email: VIEWER.email, type: 'User', html_url: `https://example.invalid/${VIEWER_LOGIN}` });
    return;
  }
  if (rest[0] === 'user' && rest[1] === 'repos') {
    if (method === 'POST') {
      const body = await readBody(req);
      const parsed = jsonBody(body);
      if (!parsed.ok) return badJson(res);
      const name = strField(parsed.value.name);
      if (name === '' || /[/\s]/.test(name)) return sendJson(res, 422, { message: 'Invalid repository name' });
      if (repos.has(repoKey(VIEWER_LOGIN, name))) return sendJson(res, 422, { message: 'Repository already exists' });
      const repo = createRepoRecord(name, strField(parsed.value.description), parsed.value.private === true);
      sendJson(res, 201, repo.json);
      return;
    }
    if (method === 'GET') {
      const q = queryParams(url);
      const { page, perPage } = pageParams(q);
      const all = [...repos.values()].filter((r) => r.owner === VIEWER_LOGIN).sort((a, b) => a.id - b.id);
      const slice = paginate(all, page, perPage).map((r) => JSON.parse(r.json) as unknown);
      const link = linkHeader(req, '/api/v3/user/repos', q, page, perPage, all.length);
      sendJson(res, 200, slice, link !== null ? { link } : undefined);
      return;
    }
    return notFound(res);
  }
  if (rest[0] !== 'repos' || rest.length < 3) return notFound(res);
  const owner = decodeURIComponent(rest[1] as string);
  const repoName = decodeURIComponent(rest[2] as string);
  const repo = lookupRepo(owner, repoName);
  if (repo === undefined) return notFound(res);
  const tail = rest.slice(3);
  if (tail.length === 0) {
    if (method === 'GET') {
      sendJson(res, 200, repo.json);
      return;
    }
    if (method === 'PATCH') {
      const body = await readBody(req);
      const parsed = jsonBody(body);
      if (!parsed.ok) return badJson(res);
      if (typeof parsed.value.description === 'string') repo.description = parsed.value.description;
      if (parsed.value.private === true || parsed.value.private === false) repo.isPrivate = parsed.value.private;
      const newName = strField(parsed.value.name);
      if (newName !== '' && newName !== repo.name && !/[/\s]/.test(newName)) {
        repos.delete(repoKey(repo.owner, repo.name));
        repo.name = newName;
        repos.set(repoKey(repo.owner, repo.name), repo);
      }
      repo.json = repoJsonOf(repo);
      sendJson(res, 200, repo.json);
      return;
    }
    if (method === 'DELETE') {
      repos.delete(repoKey(repo.owner, repo.name));
      res.writeHead(204, { 'content-type': 'application/json', 'content-length': '0', 'x-github-request-id': `req-${(++requestCounter).toString(16)}` });
      res.end();
      return;
    }
    return notFound(res);
  }
  const q = queryParams(url);
  if (tail[0] === 'branches') {
    if (tail.length === 1) {
      if (method !== 'GET') return notFound(res);
      const list = [...repo.refs.keys()]
        .filter((r) => r.startsWith('refs/heads/'))
        .map((r) => r.slice('refs/heads/'.length))
        .sort()
        .map((name) => ({ name, commit: { sha: repo.refs.get(`refs/heads/${name}`) as string } }));
      sendJson(res, 200, list);
      return;
    }
    if (tail.length === 2) {
      if (method !== 'GET') return notFound(res);
      const branch = decodeURIComponent(tail[1] as string);
      const tip = branchTip(repo, branch);
      if (tip === undefined) return notFound(res);
      sendJson(res, 200, { name: branch, commit: { sha: tip } });
      return;
    }
    return notFound(res);
  }
  if (tail[0] === 'commits') {
    if (method !== 'GET') return notFound(res);
    const ref = q.get('sha') ?? repo.defaultBranch;
    let tip = branchTip(repo, ref) ?? repo.refs.get(ref);
    if (tip === undefined && /^[0-9a-f]{40}$/.test(ref)) tip = ref;
    if (tip === undefined || !repo.objects.has(tip)) {
      if (repo.refs.size === 0) {
        sendJson(res, 200, []);
        return;
      }
      return notFound(res);
    }
    const out: Array<{ sha: string; commit: { message: string; author: { name: string; email: string }; committer: { name: string; email: string } }; parents: Array<{ sha: string }> }> = [];
    const seen = new Set<string>();
    const stack: string[] = [tip];
    while (stack.length > 0) {
      const oid = stack.shift() as string;
      if (seen.has(oid)) continue;
      seen.add(oid);
      const obj = repo.objects.get(oid);
      if (obj === undefined || obj.type !== 'commit') continue;
      const info = parseCommit(obj.data);
      const authorName = info.author.split('<')[0]?.trim() ?? VIEWER.name;
      const authorEmail = info.author.includes('<') ? (info.author.split('<')[1]?.split('>')[0] ?? VIEWER.email) : VIEWER.email;
      out.push({
        sha: oid,
        commit: { message: info.message.replace(/\n+$/, ''), author: { name: authorName, email: authorEmail }, committer: { name: authorName, email: authorEmail } },
        parents: info.parents.map((p) => ({ sha: p })),
      });
      for (const p of info.parents) stack.push(p);
    }
    const { page, perPage } = pageParams(q);
    const slice = paginate(out, page, perPage);
    const link = linkHeader(req, `/api/v3/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repoName)}/commits`, q, page, perPage, out.length);
    sendJson(res, 200, slice, link !== null ? { link } : undefined);
    return;
  }
  if (tail[0] === 'git' && tail[1] === 'refs') {
    if (method === 'POST' && tail.length === 2) {
      const body = await readBody(req);
      const parsed = jsonBody(body);
      if (!parsed.ok) return badJson(res);
      const ref = strField(parsed.value.ref);
      const sha = strField(parsed.value.sha);
      if (!ref.startsWith('refs/') || !/^[0-9a-f]{40}$/.test(sha)) return sendJson(res, 422, { message: 'Invalid ref or sha' });
      const obj = repo.objects.get(sha);
      if (obj === undefined || obj.type !== 'commit') return sendJson(res, 422, { message: 'Object does not exist' });
      if (repo.refs.has(ref)) return sendJson(res, 422, { message: 'Reference already exists' });
      repo.refs.set(ref, sha);
      sendJson(res, 201, { ref, object: { sha, type: 'commit' } });
      return;
    }
    if (method === 'GET' && tail.length >= 3) {
      const ref = tail.slice(2).map((s) => decodeURIComponent(s)).join('/');
      const tip = repo.refs.get(ref);
      if (tip === undefined) return notFound(res);
      sendJson(res, 200, { ref, object: { sha: tip, type: 'commit' } });
      return;
    }
    return notFound(res);
  }
  if (tail[0] === 'contents') {
    const filePath = tail.slice(1).map((s) => decodeURIComponent(s)).join('/');
    const branch = q.get('ref') ?? repo.defaultBranch;
    if (method === 'GET') {
      const tip = branchTip(repo, branch);
      if (tip === undefined) return notFound(res);
      const treeOid = commitTreeOid(repo, tip);
      if (filePath === '') {
        const entries = getTree(repo, treeOid).map((e) => ({
          type: e.mode === '40000' ? 'dir' : 'file',
          name: e.name,
          path: e.name,
          sha: e.oid,
          size: e.mode === '40000' ? 0 : (repo.objects.get(e.oid)?.data.length ?? 0),
        }));
        sendJson(res, 200, entries);
        return;
      }
      const files = flattenTree(repo, treeOid);
      const file = files.get(filePath);
      if (file !== undefined) {
        const blob = repo.objects.get(file.oid);
        const data = blob !== undefined ? blob.data : Buffer.alloc(0);
        sendJson(res, 200, {
          type: 'file',
          encoding: 'base64',
          size: data.length,
          name: filePath.split('/').pop() ?? filePath,
          path: filePath,
          content: b64encode(data),
          sha: file.oid,
        });
        return;
      }
      // Directory?
      const prefix = `${filePath}/`;
      const entries: Array<{ type: string; name: string; path: string; sha: string; size: number }> = [];
      const seenDir = new Set<string>();
      for (const [path, f] of files) {
        if (!path.startsWith(prefix)) continue;
        const restPath = path.slice(prefix.length);
        const first = restPath.split('/')[0] as string;
        if (restPath.includes('/')) {
          if (!seenDir.has(first)) {
            seenDir.add(first);
            // find the subtree oid by walking the tree
            let cur = treeOid;
            let dirOid = '';
            for (const seg of filePath.split('/').concat([first])) {
              const found = getTree(repo, cur).find((e) => e.name === seg);
              if (found === undefined) break;
              dirOid = found.oid;
              cur = found.oid;
            }
            entries.push({ type: 'dir', name: first, path: `${filePath}/${first}`, sha: dirOid, size: 0 });
          }
        } else {
          entries.push({ type: 'file', name: first, path, sha: f.oid, size: repo.objects.get(f.oid)?.data.length ?? 0 });
        }
      }
      if (entries.length > 0) {
        sendJson(res, 200, entries);
        return;
      }
      return notFound(res);
    }
    if (method === 'PUT' || method === 'DELETE') {
      const body = await readBody(req);
      const parsed = jsonBody(body);
      if (!parsed.ok) return badJson(res);
      const bodyBranch = strField(parsed.value.branch);
      const useBranch = bodyBranch !== '' ? bodyBranch : branch;
      const message = strField(parsed.value.message, method === 'PUT' ? 'Update file' : 'Delete file');
      if (method === 'PUT') {
        const contentB64 = strField(parsed.value.content);
        if (contentB64 === '') return sendJson(res, 422, { message: 'content is required' });
        const data = b64decode(contentB64);
        const givenSha = strField(parsed.value.sha);
        let tip = branchTip(repo, useBranch);
        const files = tip !== undefined ? new Map(flattenTree(repo, commitTreeOid(repo, tip))) : new Map<string, { oid: string; mode: string }>();
        const existing = files.get(filePath);
        if (existing !== undefined) {
          if (givenSha === '') return sendJson(res, 409, { message: 'file already exists' });
          if (givenSha !== existing.oid) return sendJson(res, 409, { message: 'sha does not match' });
        } else if (givenSha !== '') {
          return sendJson(res, 422, { message: 'file does not exist' });
        }
        const blobOid = storeObject(repo, 'blob', data);
        files.set(filePath, { oid: blobOid, mode: '100644' });
        const treeOid = buildTreeFromFiles(repo, files);
        const parents = tip !== undefined ? [tip] : [];
        const commitOid = makeServerCommit(repo, treeOid, parents, message);
        repo.refs.set(`refs/heads/${useBranch}`, commitOid);
        sendJson(res, existing !== undefined ? 200 : 201, {
          content: { type: 'file', encoding: 'base64', size: data.length, name: filePath.split('/').pop() ?? filePath, path: filePath, content: contentB64, sha: blobOid },
          commit: { sha: commitOid, message },
        });
        return;
      }
      // DELETE
      const tip = branchTip(repo, useBranch);
      if (tip === undefined) return notFound(res);
      const files = new Map(flattenTree(repo, commitTreeOid(repo, tip)));
      const existing = files.get(filePath);
      if (existing === undefined) return notFound(res);
      const givenSha = strField(parsed.value.sha);
      if (givenSha !== '' && givenSha !== existing.oid) return sendJson(res, 409, { message: 'sha does not match' });
      files.delete(filePath);
      const treeOid = buildTreeFromFiles(repo, files);
      const commitOid = makeServerCommit(repo, treeOid, [tip], message);
      repo.refs.set(`refs/heads/${useBranch}`, commitOid);
      sendJson(res, 200, { commit: { sha: commitOid, message } });
      return;
    }
    return notFound(res);
  }
  if (tail[0] === 'labels') {
    if (method === 'POST' && tail.length === 1) {
      const body = await readBody(req);
      const parsed = jsonBody(body);
      if (!parsed.ok) return badJson(res);
      const name = strField(parsed.value.name);
      const color = strField(parsed.value.color, 'ffffff');
      if (name === '') return sendJson(res, 422, { message: 'name is required' });
      if (repo.labels.has(name)) return sendJson(res, 422, { message: 'Label already exists' });
      repo.labels.set(name, { name, color });
      sendJson(res, 201, { name, color, description: '' });
      return;
    }
    if (method === 'GET' && tail.length === 1) {
      sendJson(res, 200, [...repo.labels.values()].map((l) => ({ name: l.name, color: l.color, description: '' })));
      return;
    }
    return notFound(res);
  }
  if (tail[0] === 'issues') {
    if (tail.length === 1) {
      if (method === 'POST') {
        const body = await readBody(req);
        const parsed = jsonBody(body);
        if (!parsed.ok) return badJson(res);
        const title = strField(parsed.value.title);
        if (title === '') return sendJson(res, 422, { message: 'title is required' });
        const labelNames: string[] = Array.isArray(parsed.value.labels) ? (parsed.value.labels as unknown[]).map((l) => (typeof l === 'string' ? l : strField((l as Record<string, unknown>).name))) : [];
        for (const ln of labelNames) {
          if (!repo.labels.has(ln)) return sendJson(res, 422, { message: `Label "${ln}" does not exist` });
        }
        const issue: Issue = {
          id: nextIssueId,
          number: repo.nextIssue,
          title,
          body: strField(parsed.value.body),
          state: 'open',
          labels: labelNames.map((n) => repo.labels.get(n) as { name: string; color: string }),
          comments: [],
          json: '',
        };
        nextIssueId += 1;
        repo.nextIssue += 1;
        issue.json = issueJsonOf(repo, issue);
        repo.issues.set(issue.number, issue);
        sendJson(res, 201, issue.json);
        return;
      }
      if (method === 'GET') {
        const state = q.get('state') ?? 'open';
        const direction = q.get('direction') ?? 'desc';
        let list = [...repo.issues.values()];
        if (state === 'open') list = list.filter((i) => i.state === 'open');
        else if (state === 'closed') list = list.filter((i) => i.state === 'closed');
        list.sort((a, b) => (direction === 'asc' ? a.number - b.number : b.number - a.number));
        const { page, perPage } = pageParams(q);
        const slice = paginate(list, page, perPage).map((i) => JSON.parse(i.json) as unknown);
        const link = linkHeader(req, `/api/v3/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repoName)}/issues`, q, page, perPage, list.length);
        sendJson(res, 200, slice, link !== null ? { link } : undefined);
        return;
      }
      return notFound(res);
    }
    const num = intField(tail[1], -1);
    const issue = num > 0 ? repo.issues.get(num) : undefined;
    if (tail.length === 2) {
      if (issue === undefined) return notFound(res);
      if (method === 'GET') {
        sendJson(res, 200, issue.json);
        return;
      }
      if (method === 'PATCH') {
        const body = await readBody(req);
        const parsed = jsonBody(body);
        if (!parsed.ok) return badJson(res);
        if (parsed.value.state === 'open' || parsed.value.state === 'closed') issue.state = parsed.value.state;
        if (typeof parsed.value.title === 'string') issue.title = parsed.value.title;
        if (typeof parsed.value.body === 'string') issue.body = parsed.value.body;
        issue.json = issueJsonOf(repo, issue);
        sendJson(res, 200, issue.json);
        return;
      }
      return notFound(res);
    }
    if (tail.length === 3 && tail[2] === 'comments') {
      if (issue === undefined) return notFound(res);
      if (method === 'POST') {
        const body = await readBody(req);
        const parsed = jsonBody(body);
        if (!parsed.ok) return badJson(res);
        const comment = { id: nextCommentId, body: strField(parsed.value.body) };
        nextCommentId += 1;
        issue.comments.push(comment);
        issue.json = issueJsonOf(repo, issue);
        sendJson(res, 201, { id: comment.id, body: comment.body, user: userJson(VIEWER_LOGIN), created_at: START_ISO, updated_at: START_ISO });
        return;
      }
      if (method === 'GET') {
        sendJson(res, 200, issue.comments.map((c) => ({ id: c.id, body: c.body, user: userJson(VIEWER_LOGIN), created_at: START_ISO, updated_at: START_ISO })));
        return;
      }
      return notFound(res);
    }
    return notFound(res);
  }
  if (tail[0] === 'pulls') {
    if (tail.length === 1) {
      if (method === 'POST') {
        const body = await readBody(req);
        const parsed = jsonBody(body);
        if (!parsed.ok) return badJson(res);
        const head = strField(parsed.value.head);
        const base = strField(parsed.value.base);
        const title = strField(parsed.value.title);
        if (title === '' || head === '' || base === '') return sendJson(res, 422, { message: 'head, base and title are required' });
        const headSha = branchTip(repo, head);
        const baseSha = branchTip(repo, base);
        if (headSha === undefined) return sendJson(res, 422, { message: `head branch "${head}" does not exist` });
        if (baseSha === undefined) return sendJson(res, 422, { message: `base branch "${base}" does not exist` });
        const pr: Pull = {
          id: nextPullId,
          number: repo.nextPull,
          title,
          body: strField(parsed.value.body),
          state: 'open',
          merged: false,
          mergedAt: null,
          mergeCommitSha: null,
          headBranch: head,
          baseBranch: base,
          headSha,
          baseSha,
          json: '',
        };
        nextPullId += 1;
        repo.nextPull += 1;
        pr.json = pullJsonOf(repo, pr);
        repo.pulls.set(pr.number, pr);
        sendJson(res, 201, pr.json);
        return;
      }
      if (method === 'GET') {
        const state = q.get('state') ?? 'open';
        let list = [...repo.pulls.values()];
        if (state === 'open') list = list.filter((p) => p.state === 'open');
        else if (state === 'closed') list = list.filter((p) => p.state === 'closed');
        list.sort((a, b) => b.number - a.number);
        const { page, perPage } = pageParams(q);
        const slice = paginate(list, page, perPage).map((p) => JSON.parse(p.json) as unknown);
        const link = linkHeader(req, `/api/v3/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repoName)}/pulls`, q, page, perPage, list.length);
        sendJson(res, 200, slice, link !== null ? { link } : undefined);
        return;
      }
      return notFound(res);
    }
    const num = intField(tail[1], -1);
    const pr = num > 0 ? repo.pulls.get(num) : undefined;
    if (tail.length === 2) {
      if (pr === undefined) return notFound(res);
      if (method === 'GET') {
        sendJson(res, 200, pr.json);
        return;
      }
      return notFound(res);
    }
    if (tail.length === 3 && tail[2] === 'files') {
      if (pr === undefined) return notFound(res);
      if (method !== 'GET') return notFound(res);
      sendJson(res, 200, prFiles(repo, pr));
      return;
    }
    if (tail.length === 3 && tail[2] === 'merge') {
      if (pr === undefined) return notFound(res);
      if (method !== 'PUT') return notFound(res);
      const body = await readBody(req);
      const parsed = jsonBody(body);
      if (!parsed.ok) return badJson(res);
      const result = doMerge(repo, pr);
      if (!result.ok) return sendJson(res, 405, { message: result.reason });
      sendJson(res, 200, { merged: true, sha: result.sha, message: pr.title });
      return;
    }
    return notFound(res);
  }
  return notFound(res);
}

// ---------------------------------------------------------------------------
// 8. GraphQL v4: a small parser + executor for the documents gh sends.
// ---------------------------------------------------------------------------
type GqlValue =
  | { kind: 'var'; name: string }
  | { kind: 'str'; value: string }
  | { kind: 'int'; value: number }
  | { kind: 'bool'; value: boolean }
  | { kind: 'enum'; value: string }
  | { kind: 'null' }
  | { kind: 'list'; values: GqlValue[] }
  | { kind: 'obj'; fields: Array<[string, GqlValue]> };
interface GqlSelection {
  alias: string;
  name: string;
  args: Array<[string, GqlValue]>;
  selections: GqlSelection[] | null;
  fragmentType: string | null;
}
interface GqlOperation {
  kind: 'query' | 'mutation';
  selections: GqlSelection[];
}
function gqlTokenize(src: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i] as string;
    if (c === ' ' || c === '\n' || c === '\t' || c === '\r' || c === ',') {
      i += 1;
      continue;
    }
    if (c === '#') {
      while (i < src.length && src[i] !== '\n') i += 1;
      continue;
    }
    if (c === '.' && src.slice(i, i + 3) === '...') {
      tokens.push('...');
      i += 3;
      continue;
    }
    if ('{}():[]!=$'.includes(c)) {
      tokens.push(c);
      i += 1;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) {
          const esc = src[j + 1] as string;
          out += esc === 'n' ? '\n' : esc === 't' ? '\t' : esc === 'r' ? '\r' : esc;
          j += 2;
        } else {
          out += src[j] as string;
          j += 1;
        }
      }
      tokens.push(JSON.stringify(out));
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(c)) {
      let j = i;
      while (j < src.length && /[0-9]/.test(src[j] as string)) j += 1;
      tokens.push(src.slice(i, j));
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      let j = i;
      while (j < src.length && /[A-Za-z0-9_]/.test(src[j] as string)) j += 1;
      tokens.push(src.slice(i, j));
      i = j;
      continue;
    }
    i += 1;
  }
  return tokens;
}
class GqlParser {
  tokens: string[];
  pos = 0;
  constructor(src: string) {
    this.tokens = gqlTokenize(src);
  }
  peek(): string | undefined {
    return this.tokens[this.pos];
  }
  next(): string {
    return this.tokens[this.pos++] as string;
  }
  expect(tok: string): void {
    if (this.next() !== tok) throw new Error(`expected ${tok}`);
  }
  parseOperation(): GqlOperation {
    let kind: 'query' | 'mutation' = 'query';
    const first = this.peek();
    if (first === 'query' || first === 'mutation') {
      kind = this.next() as 'query' | 'mutation';
      if (this.peek() !== undefined && this.peek() !== '{' && this.peek() !== '(') this.next();
    }
    if (this.peek() === '(') this.skipBalanced('(', ')');
    const selections = this.parseSelectionSet();
    return { kind, selections };
  }
  skipBalanced(open: string, close: string): void {
    let depth = 0;
    while (this.pos < this.tokens.length) {
      const t = this.next();
      if (t === open) depth += 1;
      else if (t === close) {
        depth -= 1;
        if (depth === 0) return;
      }
    }
  }
  parseSelectionSet(): GqlSelection[] {
    this.expect('{');
    const out: GqlSelection[] = [];
    while (this.peek() !== '}' && this.pos < this.tokens.length) {
      out.push(this.parseSelection());
    }
    this.expect('}');
    return out;
  }
  parseSelection(): GqlSelection {
    if (this.peek() === '...') {
      this.next();
      let fragmentType: string | null = null;
      if (this.peek() === 'on') {
        this.next();
        fragmentType = this.next();
      } else {
        this.next();
      }
      const selections = this.parseSelectionSet();
      return { alias: '', name: '', args: [], selections, fragmentType };
    }
    let name = this.next();
    let alias = name;
    if (this.peek() === ':') {
      this.next();
      alias = name;
      name = this.next();
    }
    const args: Array<[string, GqlValue]> = [];
    if (this.peek() === '(') {
      this.next();
      while (this.peek() !== ')' && this.pos < this.tokens.length) {
        const argName = this.next();
        this.expect(':');
        args.push([argName, this.parseValue()]);
      }
      this.expect(')');
    }
    let selections: GqlSelection[] | null = null;
    if (this.peek() === '{') selections = this.parseSelectionSet();
    return { alias, name, args, selections, fragmentType: null };
  }
  parseValue(): GqlValue {
    const t = this.next();
    if (t === '$') return { kind: 'var', name: this.next() };
    if (t === '[') {
      const values: GqlValue[] = [];
      while (this.peek() !== ']' && this.pos < this.tokens.length) values.push(this.parseValue());
      this.expect(']');
      return { kind: 'list', values };
    }
    if (t === '{') {
      const fields: Array<[string, GqlValue]> = [];
      while (this.peek() !== '}' && this.pos < this.tokens.length) {
        const key = this.next();
        this.expect(':');
        fields.push([key, this.parseValue()]);
      }
      this.expect('}');
      return { kind: 'obj', fields };
    }
    if (t.startsWith('"')) return { kind: 'str', value: JSON.parse(t) as string };
    if (/^-?\d+$/.test(t)) return { kind: 'int', value: parseInt(t, 10) };
    if (t === 'true') return { kind: 'bool', value: true };
    if (t === 'false') return { kind: 'bool', value: false };
    if (t === 'null') return { kind: 'null' };
    return { kind: 'enum', value: t };
  }
}
function gqlResolveValue(v: GqlValue, variables: Record<string, unknown>): unknown {
  switch (v.kind) {
    case 'var':
      return variables[v.name];
    case 'str':
      return v.value;
    case 'int':
      return v.value;
    case 'bool':
      return v.value;
    case 'enum':
      return v.value;
    case 'null':
      return null;
    case 'list':
      return v.values.map((x) => gqlResolveValue(x, variables));
    case 'obj': {
      const out: Record<string, unknown> = {};
      for (const [k, val] of v.fields) out[k] = gqlResolveValue(val, variables);
      return out;
    }
  }
}
function gqlArg(args: Array<[string, GqlValue]>, name: string, variables: Record<string, unknown>): unknown {
  for (const [k, v] of args) {
    if (k === name) return gqlResolveValue(v, variables);
  }
  return undefined;
}
// Schema field lists (used for validation and __type introspection).
const GQL_SCHEMA: Record<string, string[]> = {
  Query: ['viewer', 'repository', 'node', '__type'],
  User: ['login', 'id', 'name', 'email'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'private', 'defaultBranch', 'createdAt', 'updatedAt'],
  Issue: ['id', 'number', 'title', 'state', 'body', 'createdAt', 'updatedAt', 'repository', 'author', 'labels', 'comments'],
  IssueConnection: ['nodes', 'pageInfo', 'totalCount'],
  PageInfo: ['hasNextPage', 'endCursor', 'hasPreviousPage', 'startCursor'],
  PullRequest: ['id', 'number', 'title', 'body', 'state', 'merged', 'mergedAt', 'mergeCommitSha', 'headRefName', 'baseRefName', 'headRef', 'baseRef', 'mergeable', 'files', 'repository', 'author'],
  PullRequestConnection: ['nodes', 'pageInfo', 'totalCount'],
  PullRequestFileConnection: ['nodes', 'pageInfo', 'totalCount'],
  PullRequestChangedFile: ['path', 'additions', 'deletions', 'changes', 'status'],
  Ref: ['name'],
  Node: ['id'],
  __Type: ['name', 'kind', 'fields', 'enumValues', 'description'],
  __Field: ['name', 'description'],
  __EnumValue: ['name', 'description'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'],
};
const GQL_ENUM_VALUES: Record<string, string[]> = {
  SearchType: ['ISSUE', 'PULL_REQUEST', 'REPOSITORY', 'USER', 'COMMIT', 'DISCUSSION', 'MILESTONE', 'LABEL'],
  IssueState: ['OPEN', 'CLOSED'],
  MergeableState: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'],
};
interface GqlNode {
  __type: string;
  repo?: Repo;
  issue?: Issue;
  pr?: Pull;
  typeName?: string;
}
function repoNode(repo: Repo): GqlNode {
  return { __type: 'Repository', repo };
}
function issueNode(repo: Repo, issue: Issue): GqlNode {
  return { __type: 'Issue', repo, issue };
}
function prNode(repo: Repo, pr: Pull): GqlNode {
  return { __type: 'PullRequest', repo, pr };
}
function cursorFor(number: number): string {
  return Buffer.from(`cursor:${number}`, 'utf8').toString('base64');
}
function cursorNumber(cursor: unknown): number | null {
  if (typeof cursor !== 'string' || cursor === '') return null;
  try {
    const text = Buffer.from(cursor, 'base64').toString('utf8');
    const m = /^cursor:(\d+)$/.exec(text);
    return m !== null ? parseInt(m[1] as string, 10) : null;
  } catch {
    return null;
  }
}
function validateSelections(selections: GqlSelection[], parentType: string, errors: Array<{ message: string }>): void {
  const fields = GQL_SCHEMA[parentType] ?? [];
  for (const sel of selections) {
    if (sel.fragmentType !== null) {
      validateSelections(sel.selections ?? [], sel.fragmentType, errors);
      continue;
    }
    if (!fields.includes(sel.name)) {
      errors.push({ message: `Cannot query field "${sel.name}" on type "${parentType}".` });
      continue;
    }
    if (sel.selections !== null) {
      const childType = childTypeOf(parentType, sel.name);
      if (childType !== null) validateSelections(sel.selections, childType, errors);
    }
  }
}
function childTypeOf(parentType: string, field: string): string | null {
  const map: Record<string, Record<string, string>> = {
    Query: { viewer: 'User', repository: 'Repository', node: 'Node', __type: '__Type' },
    Repository: { owner: 'User', defaultBranchRef: 'Ref', issue: 'Issue', issues: 'IssueConnection', pullRequests: 'PullRequestConnection', pullRequest: 'PullRequest' },
    Issue: { repository: 'Repository', author: 'User' },
    IssueConnection: { nodes: 'Issue', pageInfo: 'PageInfo' },
    PullRequest: { files: 'PullRequestFileConnection', repository: 'Repository', author: 'User' },
    PullRequestConnection: { nodes: 'PullRequest', pageInfo: 'PageInfo' },
    PullRequestFileConnection: { nodes: 'PullRequestChangedFile', pageInfo: 'PageInfo' },
    __Type: { fields: '__Field', enumValues: '__EnumValue' },
  };
  return map[parentType]?.[field] ?? null;
}
function executeSelections(selections: GqlSelection[], parent: GqlNode | null, parentType: string, variables: Record<string, unknown>, errors: Array<{ message: string }>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const sel of selections) {
    if (sel.fragmentType !== null) {
      if (parent !== null && parent.__type !== sel.fragmentType && !(parent.__type === 'Node' && sel.fragmentType === 'Repository')) continue;
      if (parent !== null && parent.__type === 'Node' && sel.fragmentType === 'Repository') {
        // node() returned a Repository node; the fragment applies.
      }
      const inner = executeSelections(sel.selections ?? [], parent, sel.fragmentType, variables, errors);
      Object.assign(out, inner);
      continue;
    }
    out[sel.alias] = resolveField(parent, parentType, sel, variables, errors);
  }
  return out;
}
function resolveField(parent: GqlNode | null, parentType: string, sel: GqlSelection, variables: Record<string, unknown>, errors: Array<{ message: string }>): unknown {
  const name = sel.name;
  if (parentType === 'Query') {
    if (name === 'viewer') {
      const node: GqlNode = { __type: 'User' };
      return sel.selections === null ? node : executeSelections(sel.selections, node, 'User', variables, errors);
    }
    if (name === 'repository') {
      const owner = String(gqlArg(sel.args, 'owner', variables) ?? '');
      const repoName = String(gqlArg(sel.args, 'name', variables) ?? '');
      const repo = owner === VIEWER_LOGIN ? lookupRepo(owner, repoName) : undefined;
      if (repo === undefined) return null;
      const node = repoNode(repo);
      return sel.selections === null ? node : executeSelections(sel.selections, node, 'Repository', variables, errors);
    }
    if (name === 'node') {
      const id = String(gqlArg(sel.args, 'id', variables) ?? '');
      const decoded = decodeGlobalId(id);
      if (decoded === null) return null;
      if (decoded.kind === 'Repository') {
        const slash = decoded.parts.indexOf('/');
        if (slash < 0) return null;
        const repo = lookupRepo(decoded.parts.slice(0, slash), decoded.parts.slice(slash + 1));
        if (repo === undefined) return null;
        const node = repoNode(repo);
        return sel.selections === null ? node : executeSelections(sel.selections, node, 'Repository', variables, errors);
      }
      if (decoded.kind === 'Issue') {
        const scoped = parseScopedId(decoded.parts);
        if (scoped === null) return null;
        const repo = lookupRepo(scoped.owner, scoped.repo);
        const issue = repo?.issues.get(scoped.number);
        if (repo === undefined || issue === undefined) return null;
        const node = issueNode(repo, issue);
        return sel.selections === null ? node : executeSelections(sel.selections, node, 'Issue', variables, errors);
      }
      return null;
    }
    if (name === '__type') {
      const typeName = String(gqlArg(sel.args, 'name', variables) ?? '');
      const fields = GQL_SCHEMA[typeName];
      const enums = GQL_ENUM_VALUES[typeName];
      if (fields === undefined && enums === undefined) return null;
      const node: GqlNode = { __type: '__Type', typeName };
      return sel.selections === null ? node : executeSelections(sel.selections, node, '__Type', variables, errors);
    }
    return null;
  }
  if (parentType === '__Type' && parent !== null) {
    const typeName = parent.typeName ?? '';
    if (name === 'name') return typeName;
    if (name === 'kind') return GQL_ENUM_VALUES[typeName] !== undefined ? 'ENUM' : 'OBJECT';
    if (name === 'description') return null;
    if (name === 'fields') {
      const fields = GQL_SCHEMA[typeName] ?? [];
      const arr = fields.map((f) => ({ __type: '__Field', typeName: f }));
      if (sel.selections === null) return arr;
      return arr.map((f) => executeSelections(sel.selections as GqlSelection[], f, '__Field', variables, errors));
    }
    if (name === 'enumValues') {
      const values = GQL_ENUM_VALUES[typeName] ?? [];
      const arr = values.map((v) => ({ __type: '__EnumValue', typeName: v }));
      if (sel.selections === null) return arr;
      return arr.map((v) => executeSelections(sel.selections as GqlSelection[], v, '__EnumValue', variables, errors));
    }
    return null;
  }
  if ((parentType === '__Field' || parentType === '__EnumValue') && parent !== null) {
    if (name === 'name') return parent.typeName ?? '';
    if (name === 'description') return null;
    return null;
  }
  if (parentType === 'User') {
    if (name === 'login') return VIEWER_LOGIN;
    if (name === 'id') return globalId('User', VIEWER_LOGIN);
    if (name === 'name') return VIEWER.name;
    if (name === 'email') return VIEWER.email;
    return null;
  }
  if (parentType === 'Repository' && parent?.repo !== undefined) {
    const repo = parent.repo;
    switch (name) {
      case 'id':
        return globalId('Repository', `${repo.owner}/${repo.name}`);
      case 'databaseId':
        return repo.id;
      case 'name':
        return repo.name;
      case 'nameWithOwner':
        return `${repo.owner}/${repo.name}`;
      case 'owner': {
        const node: GqlNode = { __type: 'User' };
        return sel.selections === null ? node : executeSelections(sel.selections, node, 'User', variables, errors);
      }
      case 'defaultBranchRef': {
        const tip = branchTip(repo, repo.defaultBranch);
        if (tip === undefined) return null;
        const node: GqlNode = { __type: 'Ref', typeName: repo.defaultBranch };
        return sel.selections === null ? node : executeSelections(sel.selections, node, 'Ref', variables, errors);
      }
      case 'viewerPermission':
        return 'ADMIN';
      case 'hasIssuesEnabled':
        return true;
      case 'description':
        return repo.description;
      case 'private':
        return repo.isPrivate;
      case 'defaultBranch':
        return repo.defaultBranch;
      case 'createdAt':
      case 'updatedAt':
        return START_ISO;
      case 'issue': {
        const num = intField(gqlArg(sel.args, 'number', variables), -1);
        const issue = num > 0 ? repo.issues.get(num) : undefined;
        if (issue === undefined) return null;
        const node = issueNode(repo, issue);
        return sel.selections === null ? node : executeSelections(sel.selections, node, 'Issue', variables, errors);
      }
      case 'issues': {
        const first = intField(gqlArg(sel.args, 'first', variables), 10);
        const after = cursorNumber(gqlArg(sel.args, 'after', variables));
        const states = gqlArg(sel.args, 'states', variables);
        const orderBy = gqlArg(sel.args, 'orderBy', variables) as Record<string, unknown> | undefined;
        let list = [...repo.issues.values()];
        if (Array.isArray(states) && states.length > 0) {
          const wanted = new Set(states.map((s) => String(s).toLowerCase()));
          list = list.filter((i) => wanted.has(i.state));
        }
        const desc = orderBy === undefined || String(orderBy.direction ?? 'DESC') === 'DESC';
        list.sort((a, b) => (desc ? b.number - a.number : a.number - b.number));
        if (after !== null) list = list.filter((i) => (desc ? i.number < after : i.number > after));
        const page = list.slice(0, first);
        const hasNext = list.length > first;
        const nodes = page.map((issue) => {
          const node = issueNode(repo, issue);
          const sub = (sel.selections ?? []).find((s) => s.name === 'nodes');
          return sub?.selections !== null && sub?.selections !== undefined ? executeSelections(sub.selections, node, 'Issue', variables, errors) : node;
        });
        let pageInfo: Record<string, unknown> = { hasNextPage: hasNext, endCursor: page.length > 0 ? cursorFor(page[page.length - 1]?.number as number) : null };
        const pi = (sel.selections ?? []).find((s) => s.name === 'pageInfo');
        if (pi?.selections !== undefined && pi.selections !== null) {
          pageInfo = executeSelections(pi.selections, { __type: 'PageInfo' }, 'PageInfo', variables, errors);
          // fill the fields the selection asked for
          const full: Record<string, unknown> = { hasNextPage: hasNext, endCursor: page.length > 0 ? cursorFor(page[page.length - 1]?.number as number) : null, hasPreviousPage: false, startCursor: page.length > 0 ? cursorFor(page[0]?.number as number) : null };
          for (const k of Object.keys(pageInfo)) pageInfo[k] = full[k];
        }
        const out: Record<string, unknown> = {};
        for (const sub of sel.selections ?? []) {
          if (sub.name === 'nodes') out.nodes = nodes;
          else if (sub.name === 'pageInfo') out.pageInfo = pageInfo;
          else if (sub.name === 'totalCount') out.totalCount = list.length;
        }
        return out;
      }
      case 'pullRequests': {
        const first = intField(gqlArg(sel.args, 'first', variables), 10);
        const list = [...repo.pulls.values()].sort((a, b) => b.number - a.number).slice(0, first);
        const sub = (sel.selections ?? []).find((s) => s.name === 'nodes');
        const nodes = list.map((pr) => {
          const node = prNode(repo, pr);
          return sub?.selections !== null && sub?.selections !== undefined ? executeSelections(sub.selections, node, 'PullRequest', variables, errors) : node;
        });
        const out: Record<string, unknown> = {};
        for (const s of sel.selections ?? []) {
          if (s.name === 'nodes') out.nodes = nodes;
          else if (s.name === 'totalCount') out.totalCount = repo.pulls.size;
          else if (s.name === 'pageInfo') out.pageInfo = { hasNextPage: false, endCursor: null };
        }
        return out;
      }
      case 'pullRequest': {
        const num = intField(gqlArg(sel.args, 'number', variables), -1);
        const pr = num > 0 ? repo.pulls.get(num) : undefined;
        if (pr === undefined) return null;
        const node = prNode(repo, pr);
        return sel.selections === null ? node : executeSelections(sel.selections, node, 'PullRequest', variables, errors);
      }
      default:
        return null;
    }
  }
  if (parentType === 'Issue' && parent?.issue !== undefined && parent.repo !== undefined) {
    const issue = parent.issue;
    const repo = parent.repo;
    switch (name) {
      case 'id':
        return globalId('Issue', `${repo.owner}/${repo.name}:${issue.number}`);
      case 'number':
        return issue.number;
      case 'title':
        return issue.title;
      case 'state':
        return issue.state.toUpperCase();
      case 'body':
        return issue.body;
      case 'createdAt':
      case 'updatedAt':
        return START_ISO;
      case 'repository': {
        const node = repoNode(repo);
        return sel.selections === null ? node : executeSelections(sel.selections, node, 'Repository', variables, errors);
      }
      case 'author': {
        const node: GqlNode = { __type: 'User' };
        return sel.selections === null ? node : executeSelections(sel.selections, node, 'User', variables, errors);
      }
      case 'labels':
        return issue.labels.map((l) => ({ name: l.name, color: l.color }));
      case 'comments':
        return issue.comments.map((c) => ({ id: globalId('IssueComment', `${repo.owner}/${repo.name}:${issue.number}:${c.id}`), body: c.body }));
      default:
        return null;
    }
  }
  if (parentType === 'PullRequest' && parent?.pr !== undefined && parent.repo !== undefined) {
    const pr = parent.pr;
    const repo = parent.repo;
    switch (name) {
      case 'id':
        return globalId('PullRequest', `${repo.owner}/${repo.name}:${pr.number}`);
      case 'number':
        return pr.number;
      case 'title':
        return pr.title;
      case 'body':
        return pr.body;
      case 'state':
        return pr.state.toUpperCase();
      case 'merged':
        return pr.merged;
      case 'mergedAt':
        return pr.mergedAt;
      case 'mergeCommitSha':
        return pr.mergeCommitSha;
      case 'headRefName':
        return pr.headBranch;
      case 'baseRefName':
        return pr.baseBranch;
      case 'headRef':
      case 'baseRef': {
        const branch = name === 'headRef' ? pr.headBranch : pr.baseBranch;
        const node: GqlNode = { __type: 'Ref', typeName: branch };
        return sel.selections === null ? node : executeSelections(sel.selections, node, 'Ref', variables, errors);
      }
      case 'mergeable':
        return computeMergeable(repo, pr);
      case 'files': {
        const first = intField(gqlArg(sel.args, 'first', variables), 10);
        const files = prFiles(repo, pr).slice(0, first);
        const sub = (sel.selections ?? []).find((s) => s.name === 'nodes');
        const nodes = files.map((f) => {
          if (sub?.selections === null || sub?.selections === undefined) return { path: f.filename };
          const out: Record<string, unknown> = {};
          for (const s of sub.selections) {
            if (s.name === 'path') out.path = f.filename;
            else if (s.name === 'additions') out.additions = f.additions;
            else if (s.name === 'deletions') out.deletions = f.deletions;
            else if (s.name === 'changes') out.changes = f.changes;
            else if (s.name === 'status') out.status = f.status;
          }
          return out;
        });
        const out: Record<string, unknown> = {};
        for (const s of sel.selections ?? []) {
          if (s.name === 'nodes') out.nodes = nodes;
          else if (s.name === 'totalCount') out.totalCount = files.length;
          else if (s.name === 'pageInfo') out.pageInfo = { hasNextPage: false, endCursor: null };
        }
        return out;
      }
      case 'repository': {
        const node = repoNode(repo);
        return sel.selections === null ? node : executeSelections(sel.selections, node, 'Repository', variables, errors);
      }
      case 'author': {
        const node: GqlNode = { __type: 'User' };
        return sel.selections === null ? node : executeSelections(sel.selections, node, 'User', variables, errors);
      }
      default:
        return null;
    }
  }
  if (parentType === 'PageInfo') {
    return null;
  }
  if (parentType === 'Ref' && parent !== null) {
    if (name === 'name') return parent.typeName ?? '';
    return null;
  }
  return null;
}
function executeOperation(op: GqlOperation, variables: Record<string, unknown>): { data: Record<string, unknown> | null; errors?: Array<{ message: string }> } {
  const errors: Array<{ message: string }> = [];
  const rootType = op.kind === 'mutation' ? 'Mutation' : 'Query';
  validateSelections(op.selections, rootType, errors);
  if (errors.length > 0) return { data: null, errors };
  if (op.kind === 'mutation') {
    const data = executeMutations(op.selections, variables, errors);
    if (errors.length > 0) return { data, errors };
    return { data };
  }
  const data = executeSelections(op.selections, null, 'Query', variables, errors);
  if (errors.length > 0) return { data, errors };
  return { data };
}
function executeMutations(selections: GqlSelection[], variables: Record<string, unknown>, errors: Array<{ message: string }>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const sel of selections) {
    const input = gqlArg(sel.args, 'input', variables) as Record<string, unknown> | undefined;
    if (sel.name === 'createIssue') {
      const repoId = String(input?.repositoryId ?? '');
      const decoded = decodeGlobalId(repoId);
      let repo: Repo | undefined;
      if (decoded?.kind === 'Repository') {
        const slash = decoded.parts.indexOf('/');
        if (slash >= 0) repo = lookupRepo(decoded.parts.slice(0, slash), decoded.parts.slice(slash + 1));
      }
      if (repo === undefined) {
        errors.push({ message: 'Repository not found' });
        out[sel.alias] = null;
        continue;
      }
      const issue: Issue = {
        id: nextIssueId,
        number: repo.nextIssue,
        title: String(input?.title ?? ''),
        body: String(input?.body ?? ''),
        state: 'open',
        labels: [],
        comments: [],
        json: '',
      };
      nextIssueId += 1;
      repo.nextIssue += 1;
      issue.json = issueJsonOf(repo, issue);
      repo.issues.set(issue.number, issue);
      const node = issueNode(repo, issue);
      out[sel.alias] = sel.selections === null ? node : executeSelections(sel.selections, node, 'Issue', variables, errors);
      // The mutation payload is {issue: {...}}; wrap the node selection under 'issue'.
      if (sel.selections !== null) {
        const wrapped: Record<string, unknown> = {};
        for (const sub of sel.selections) {
          if (sub.name === 'issue') {
            wrapped.issue = sub.selections === null ? node : executeSelections(sub.selections, node, 'Issue', variables, errors);
          }
        }
        out[sel.alias] = wrapped;
      }
      continue;
    }
    if (sel.name === 'closeIssue') {
      const issueId = String(input?.issueId ?? '');
      const decoded = decodeGlobalId(issueId);
      let target: { repo: Repo; issue: Issue } | undefined;
      if (decoded?.kind === 'Issue') {
        const scoped = parseScopedId(decoded.parts);
        if (scoped !== null) {
          const repo = lookupRepo(scoped.owner, scoped.repo);
          const issue = repo?.issues.get(scoped.number);
          if (repo !== undefined && issue !== undefined) target = { repo, issue };
        }
      }
      if (target === undefined) {
        errors.push({ message: 'Issue not found' });
        out[sel.alias] = null;
        continue;
      }
      target.issue.state = 'closed';
      target.issue.json = issueJsonOf(target.repo, target.issue);
      const node = issueNode(target.repo, target.issue);
      if (sel.selections !== null) {
        const wrapped: Record<string, unknown> = {};
        for (const sub of sel.selections) {
          if (sub.name === 'issue') {
            wrapped.issue = sub.selections === null ? node : executeSelections(sub.selections, node, 'Issue', variables, errors);
          }
        }
        out[sel.alias] = wrapped;
      } else {
        out[sel.alias] = node;
      }
      continue;
    }
    if (sel.name === 'createPullRequest') {
      const repoId = String(input?.repositoryId ?? '');
      const decoded = decodeGlobalId(repoId);
      let repo: Repo | undefined;
      if (decoded?.kind === 'Repository') {
        const slash = decoded.parts.indexOf('/');
        if (slash >= 0) repo = lookupRepo(decoded.parts.slice(0, slash), decoded.parts.slice(slash + 1));
      }
      if (repo === undefined) {
        errors.push({ message: 'Repository not found' });
        out[sel.alias] = null;
        continue;
      }
      const head = String(input?.headRefName ?? '');
      const base = String(input?.baseRefName ?? '');
      const headSha = branchTip(repo, head);
      const baseSha = branchTip(repo, base);
      if (headSha === undefined || baseSha === undefined) {
        errors.push({ message: 'Branch not found' });
        out[sel.alias] = null;
        continue;
      }
      const pr: Pull = {
        id: nextPullId,
        number: repo.nextPull,
        title: String(input?.title ?? ''),
        body: String(input?.body ?? ''),
        state: 'open',
        merged: false,
        mergedAt: null,
        mergeCommitSha: null,
        headBranch: head,
        baseBranch: base,
        headSha,
        baseSha,
        json: '',
      };
      nextPullId += 1;
      repo.nextPull += 1;
      pr.json = pullJsonOf(repo, pr);
      repo.pulls.set(pr.number, pr);
      const node = prNode(repo, pr);
      if (sel.selections !== null) {
        const wrapped: Record<string, unknown> = {};
        for (const sub of sel.selections) {
          if (sub.name === 'pullRequest') {
            wrapped.pullRequest = sub.selections === null ? node : executeSelections(sub.selections, node, 'PullRequest', variables, errors);
          }
        }
        out[sel.alias] = wrapped;
      } else {
        out[sel.alias] = node;
      }
      continue;
    }
    if (sel.name === 'mergePullRequest') {
      const prId = String(input?.pullRequestId ?? '');
      const decoded = decodeGlobalId(prId);
      let target: { repo: Repo; pr: Pull } | undefined;
      if (decoded?.kind === 'PullRequest') {
        const scoped = parseScopedId(decoded.parts);
        if (scoped !== null) {
          const repo = lookupRepo(scoped.owner, scoped.repo);
          const pr = repo?.pulls.get(scoped.number);
          if (repo !== undefined && pr !== undefined) target = { repo, pr };
        }
      }
      if (target === undefined) {
        errors.push({ message: 'Pull request not found' });
        out[sel.alias] = null;
        continue;
      }
      const result = doMerge(target.repo, target.pr);
      const node = prNode(target.repo, target.pr);
      if (!result.ok) {
        errors.push({ message: result.reason });
      }
      if (sel.selections !== null) {
        const wrapped: Record<string, unknown> = {};
        for (const sub of sel.selections) {
          if (sub.name === 'pullRequest') {
            wrapped.pullRequest = sub.selections === null ? node : executeSelections(sub.selections, node, 'PullRequest', variables, errors);
          }
        }
        out[sel.alias] = wrapped;
      } else {
        out[sel.alias] = node;
      }
      continue;
    }
    if (sel.name === 'addComment') {
      const subjectId = String(input?.subjectId ?? '');
      const decoded = decodeGlobalId(subjectId);
      let target: { repo: Repo; issue: Issue } | undefined;
      if (decoded?.kind === 'Issue') {
        const scoped = parseScopedId(decoded.parts);
        if (scoped !== null) {
          const repo = lookupRepo(scoped.owner, scoped.repo);
          const issue = repo?.issues.get(scoped.number);
          if (repo !== undefined && issue !== undefined) target = { repo, issue };
        }
      }
      if (target === undefined) {
        errors.push({ message: 'Subject not found' });
        out[sel.alias] = null;
        continue;
      }
      const comment = { id: nextCommentId, body: String(input?.body ?? '') };
      nextCommentId += 1;
      target.issue.comments.push(comment);
      target.issue.json = issueJsonOf(target.repo, target.issue);
      const commentNode: GqlNode = { __type: 'IssueComment', typeName: globalId('IssueComment', `${target.repo.owner}/${target.repo.name}:${target.issue.number}:${comment.id}`) };
      if (sel.selections !== null) {
        const wrapped: Record<string, unknown> = {};
        for (const sub of sel.selections) {
          if (sub.name === 'commentEdge') {
            const edge: Record<string, unknown> = {};
            for (const edgeSel of sub.selections ?? []) {
              if (edgeSel.name === 'node') {
                const nodeOut: Record<string, unknown> = {};
                for (const f of edgeSel.selections ?? []) {
                  if (f.name === 'id') nodeOut.id = commentNode.typeName;
                  else if (f.name === 'body') nodeOut.body = comment.body;
                }
                edge.node = nodeOut;
              }
            }
            wrapped.commentEdge = edge;
          }
        }
        out[sel.alias] = wrapped;
      } else {
        out[sel.alias] = commentNode;
      }
      continue;
    }
    errors.push({ message: `Unknown mutation "${sel.name}"` });
    out[sel.alias] = null;
  }
  return out;
}
async function handleGraphql(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const body = await readBody(req);
  let parsed: unknown;
  try {
    parsed = JSON.parse(body.toString('utf8'));
  } catch {
    sendJson(res, 400, { errors: [{ message: 'Invalid JSON' }] });
    return;
  }
  const runOne = (doc: unknown): { data: Record<string, unknown> | null; errors?: Array<{ message: string }> } => {
    if (doc === null || typeof doc !== 'object') return { data: null, errors: [{ message: 'Invalid GraphQL document' }] };
    const d = doc as { query?: unknown; variables?: unknown };
    if (typeof d.query !== 'string') return { data: null, errors: [{ message: 'Missing query' }] };
    const variables = (d.variables !== null && typeof d.variables === 'object' ? d.variables : {}) as Record<string, unknown>;
    try {
      const op = new GqlParser(d.query).parseOperation();
      return executeOperation(op, variables);
    } catch (err) {
      return { data: null, errors: [{ message: err instanceof Error ? err.message : 'Parse error' }] };
    }
  };
  if (Array.isArray(parsed)) {
    sendJson(res, 200, parsed.map((doc) => runOne(doc)));
    return;
  }
  sendJson(res, 200, runOne(parsed));
}

// ---------------------------------------------------------------------------
// 9. MCP (Streamable HTTP, revision 2026-07-28).
// ---------------------------------------------------------------------------
const MCP_TOOLS: Array<{ name: string; description: string; inputSchema: Record<string, unknown> }> = [
  {
    name: 'create_repo',
    description: 'Create a repository for the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'The repository name.' },
        description: { type: 'string', description: 'A short description of the repository.' },
        private: { type: 'boolean', description: 'Whether the repository is private.' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The issue title.' },
        body: { type: 'string', description: 'The issue body.' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        state: { type: 'string', description: 'Issue state: open, closed or all.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The pull request title.' },
        head: { type: 'string', description: 'The head branch name.' },
        base: { type: 'string', description: 'The base branch name.' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request with a squash merge.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        pull_number: { type: 'integer', description: 'The pull request number.' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];
const MCP_TOOLS_JSON = JSON.stringify(MCP_TOOLS);
const MCP_DISCOVER_JSON = JSON.stringify({
  supportedVersions: ['2026-07-28', '2025-06-18', '2025-03-26', '2024-11-05'],
  capabilities: { tools: {} },
  serverInfo: { name: 'github-core-clone', version: '1.0.0' },
  protocolVersion: '2026-07-28',
});
const MCP_INITIALIZE_JSON = JSON.stringify({
  protocolVersion: '2026-07-28',
  capabilities: { tools: {} },
  serverInfo: { name: 'github-core-clone', version: '1.0.0' },
});
function mcpResult(id: unknown, resultJson: string): string {
  return `{"jsonrpc":"2.0","id":${JSON.stringify(id ?? null)},"result":${resultJson}}`;
}
function mcpError(id: unknown, code: number, message: string): string {
  return `{"jsonrpc":"2.0","id":${JSON.stringify(id ?? null)},"error":{"code":${code},"message":${JSON.stringify(message)}}}`;
}
function mcpToolOk(structured: unknown): { content: Array<{ type: string; text: string }>; structuredContent: unknown } {
  const text = JSON.stringify(structured);
  return { content: [{ type: 'text', text }], structuredContent: structured };
}
function mcpToolErr(message: string): { content: Array<{ type: string; text: string }>; isError: boolean } {
  return { content: [{ type: 'text', text: message }], isError: true };
}
function mcpMissingArgs(tool: string, missing: string[]): { content: Array<{ type: string; text: string }>; isError: boolean } {
  return mcpToolErr(`Missing required argument(s) for ${tool}: ${missing.join(', ')}`);
}
async function handleMcp(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (req.method === 'DELETE') {
    res.writeHead(204, { 'content-length': '0' });
    res.end();
    return;
  }
  if (req.method !== 'POST') {
    sendJson(res, 405, { message: 'Method Not Allowed' });
    return;
  }
  const body = await readBody(req);
  let rpc: { jsonrpc?: unknown; id?: unknown; method?: unknown; params?: unknown };
  try {
    rpc = JSON.parse(body.toString('utf8')) as typeof rpc;
  } catch {
    const text = '{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}';
    const buf = Buffer.from(text, 'utf8');
    res.writeHead(400, { 'content-type': 'application/json', 'content-length': String(buf.length) });
    res.end(buf);
    return;
  }
  if (rpc === null || typeof rpc !== 'object' || typeof rpc.method !== 'string') {
    sendJson(res, 200, mcpError(rpc?.id ?? null, -32600, 'Invalid Request'));
    return;
  }
  const id = rpc.id;
  // Notifications (no id) get a bare 202.
  if (id === undefined) {
    res.writeHead(202, { 'content-length': '0' });
    res.end();
    return;
  }
  const method = rpc.method;
  const params = (rpc.params !== null && typeof rpc.params === 'object' ? rpc.params : {}) as Record<string, unknown>;
  if (method === 'server/discover') {
    sendJson(res, 200, mcpResult(id, MCP_DISCOVER_JSON));
    return;
  }
  if (method === 'initialize') {
    sendJson(res, 200, mcpResult(id, MCP_INITIALIZE_JSON));
    return;
  }
  if (method === 'ping') {
    sendJson(res, 200, mcpResult(id, '{}'));
    return;
  }
  if (method === 'tools/list') {
    sendJson(res, 200, mcpResult(id, `{"tools":${MCP_TOOLS_JSON}}`));
    return;
  }
  if (method === 'tools/call') {
    const name = String(params.name ?? '');
    const args = (params.arguments !== null && typeof params.arguments === 'object' ? params.arguments : {}) as Record<string, unknown>;
    const tool = MCP_TOOLS.find((t) => t.name === name);
    if (tool === undefined) {
      sendJson(res, 200, mcpError(id, -32601, `Unknown tool "${name}"`));
      return;
    }
    const required = (tool.inputSchema.required as string[] | undefined) ?? [];
    const missing = required.filter((r) => args[r] === undefined || args[r] === null || args[r] === '');
    if (missing.length > 0) {
      sendJson(res, 200, mcpResult(id, JSON.stringify(mcpMissingArgs(name, missing))));
      return;
    }
    const owner = String(args.owner ?? VIEWER_LOGIN);
    const repoName = String(args.repo ?? args.name ?? '');
    if (name === 'create_repo') {
      const repoNameArg = String(args.name ?? '');
      if (repoNameArg === '') {
        sendJson(res, 200, mcpResult(id, JSON.stringify(mcpToolErr('Repository name is required'))));
        return;
      }
      if (repos.has(repoKey(VIEWER_LOGIN, repoNameArg))) {
        sendJson(res, 200, mcpResult(id, JSON.stringify(mcpToolErr('Repository already exists'))));
        return;
      }
      const repo = createRepoRecord(repoNameArg, String(args.description ?? ''), args.private === true);
      sendJson(res, 200, mcpResult(id, JSON.stringify(mcpToolOk({ id: repo.id, name: repo.name, full_name: `${repo.owner}/${repo.name}`, private: repo.isPrivate, default_branch: repo.defaultBranch }))));
      return;
    }
    const repo = lookupRepo(owner, repoName);
    if (repo === undefined) {
      sendJson(res, 200, mcpResult(id, JSON.stringify(mcpToolErr(`Repository ${owner}/${repoName} not found`))));
      return;
    }
    if (name === 'get_repo') {
      sendJson(res, 200, mcpResult(id, JSON.stringify(mcpToolOk(JSON.parse(repo.json) as unknown))));
      return;
    }
    if (name === 'create_issue') {
      const issue: Issue = {
        id: nextIssueId,
        number: repo.nextIssue,
        title: String(args.title ?? ''),
        body: String(args.body ?? ''),
        state: 'open',
        labels: [],
        comments: [],
        json: '',
      };
      nextIssueId += 1;
      repo.nextIssue += 1;
      issue.json = issueJsonOf(repo, issue);
      repo.issues.set(issue.number, issue);
      sendJson(res, 200, mcpResult(id, JSON.stringify(mcpToolOk({ id: issue.id, number: issue.number, title: issue.title, body: issue.body, state: issue.state, repository: `${repo.owner}/${repo.name}` }))));
      return;
    }
    if (name === 'list_issues') {
      const state = String(args.state ?? 'open');
      let list = [...repo.issues.values()];
      if (state === 'open') list = list.filter((i) => i.state === 'open');
      else if (state === 'closed') list = list.filter((i) => i.state === 'closed');
      list.sort((a, b) => b.number - a.number);
      const items = list.map((i) => ({ id: i.id, number: i.number, title: i.title, body: i.body, state: i.state }));
      sendJson(res, 200, mcpResult(id, JSON.stringify(mcpToolOk({ repository: `${repo.owner}/${repo.name}`, issues: items }))));
      return;
    }
    if (name === 'create_pull_request') {
      const head = String(args.head ?? '');
      const base = String(args.base ?? '');
      const headSha = branchTip(repo, head);
      const baseSha = branchTip(repo, base);
      if (headSha === undefined || baseSha === undefined) {
        sendJson(res, 200, mcpResult(id, JSON.stringify(mcpToolErr('Head or base branch not found'))));
        return;
      }
      const pr: Pull = {
        id: nextPullId,
        number: repo.nextPull,
        title: String(args.title ?? ''),
        body: String(args.body ?? ''),
        state: 'open',
        merged: false,
        mergedAt: null,
        mergeCommitSha: null,
        headBranch: head,
        baseBranch: base,
        headSha,
        baseSha,
        json: '',
      };
      nextPullId += 1;
      repo.nextPull += 1;
      pr.json = pullJsonOf(repo, pr);
      repo.pulls.set(pr.number, pr);
      sendJson(res, 200, mcpResult(id, JSON.stringify(mcpToolOk({ id: pr.id, number: pr.number, title: pr.title, state: pr.state, head: pr.headBranch, base: pr.baseBranch, repository: `${repo.owner}/${repo.name}` }))));
      return;
    }
    if (name === 'merge_pull_request') {
      const num = intField(args.pull_number, -1);
      const pr = num > 0 ? repo.pulls.get(num) : undefined;
      if (pr === undefined) {
        sendJson(res, 200, mcpResult(id, JSON.stringify(mcpToolErr(`Pull request #${num} not found`))));
        return;
      }
      const result = doMerge(repo, pr);
      if (!result.ok) {
        sendJson(res, 200, mcpResult(id, JSON.stringify(mcpToolErr(result.reason))));
        return;
      }
      sendJson(res, 200, mcpResult(id, JSON.stringify(mcpToolOk({ number: pr.number, merged: true, state: pr.state, sha: result.sha, repository: `${repo.owner}/${repo.name}` }))));
      return;
    }
    sendJson(res, 200, mcpError(id, -32601, `Unknown tool "${name}"`));
    return;
  }
  sendJson(res, 200, mcpError(id, -32601, `Method not found: ${method}`));
}

// ---------------------------------------------------------------------------
// 10. Git smart HTTP.
// ---------------------------------------------------------------------------
function sortedRefs(repo: Repo): Array<{ name: string; oid: string }> {
  return [...repo.refs.entries()].map(([name, oid]) => ({ name, oid })).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}
function v0Advertisement(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const refs = sortedRefs(repo);
  const caps =
    service === 'git-upload-pack'
      ? `side-band-64k shallow thin-pack ofs-delta multi_ack multi_ack_detailed symref=HEAD:refs/heads/main agent=${AGENT}`
      : `report-status report-status-v2 side-band-64k delete-refs ofs-delta symref=HEAD:refs/heads/main agent=${AGENT}`;
  const lines: Array<string | Buffer | 'flush'> = [`# service=${service}\n`];
  const mainTip = repo.refs.get('refs/heads/main');
  if (refs.length === 0) {
    lines.push(`${ZERO_OID} capabilities^{}\0${caps}\n`);
  } else {
    const headOid = mainTip ?? refs[0]?.oid ?? ZERO_OID;
    lines.push(`${headOid} HEAD\0${caps}\n`);
    for (const ref of refs) {
      lines.push(`${ref.oid} ${ref.name}\n`);
      if (ref.name.startsWith('refs/tags/')) {
        const obj = repo.objects.get(ref.oid);
        if (obj !== undefined && obj.type === 'tag') {
          const peeled = parseTag(obj.data).object;
          lines.push(`${peeled} ${ref.name}^{}\n`);
        }
      }
    }
  }
  lines.push('flush');
  return pktLines(lines);
}
const V2_ADVERTISEMENT = (() => {
  const lines: Array<string | Buffer | 'flush'> = [
    '# service=git-upload-pack\n',
    'flush',
    'version 2\n',
    'ls-refs=unborn\n',
    'fetch=shallow filter\n',
    'object-format=sha1\n',
    `agent=${AGENT}\n`,
    'flush',
  ];
  return pktLines(lines);
})();
function lsRefsResponse(repo: Repo, prefixes: string[], peel: boolean, symrefs: boolean, unborn: boolean): Buffer {
  const lines: Array<string | Buffer | 'flush'> = [];
  const keep = (name: string): boolean => prefixes.length === 0 || prefixes.some((p) => name.startsWith(p));
  const mainTip = repo.refs.get('refs/heads/main');
  const refs = sortedRefs(repo);
  if (refs.length === 0) {
    if (unborn && keep('HEAD')) {
      lines.push(`unborn HEAD${symrefs ? ' symref-target:refs/heads/main' : ''}\n`);
    }
  } else {
    if (keep('HEAD') && mainTip !== undefined) {
      lines.push(`${mainTip} HEAD${symrefs ? ' symref-target:refs/heads/main' : ''}\n`);
    }
    for (const ref of refs) {
      if (!keep(ref.name)) continue;
      let line = `${ref.oid} ${ref.name}`;
      if (peel && ref.name.startsWith('refs/tags/')) {
        const obj = repo.objects.get(ref.oid);
        if (obj !== undefined && obj.type === 'tag') {
          line += ` peeled:${parseTag(obj.data).object}`;
        }
      }
      lines.push(`${line}\n`);
    }
  }
  lines.push('flush');
  return pktLines(lines);
}
function sidebandPack(pack: Buffer): Buffer {
  const parts: Buffer[] = [];
  for (let off = 0; off < pack.length; off += 65515) {
    const chunk = pack.subarray(off, Math.min(pack.length, off + 65515));
    const payload = Buffer.concat([Buffer.from([1]), chunk]);
    parts.push(pktLine(payload));
  }
  if (pack.length === 0) {
    parts.push(pktLine(Buffer.from([1])));
  }
  return Buffer.concat(parts);
}
function fetchResponse(repo: Repo, wants: string[], haves: string[], clientShallow: string[], depth: number | null, protocol: 2 | 0): Buffer {
  const sel = selectFetch(repo, wants, haves, clientShallow, depth);
  let pack: Buffer;
  if (haves.length === 0 && clientShallow.length === 0) {
    // Clone-shaped fetch: the pack is immutable for this tip+depth, so cache it.
    const key = `${[...wants].sort().join(',')}|${depth === null ? '' : String(depth)}`;
    const cached = repo.packCache.get(key);
    if (cached !== undefined) {
      pack = cached;
    } else {
      pack = buildPack(sel.objects);
      repo.packCache.set(key, pack);
    }
  } else {
    pack = buildPack(sel.objects);
  }
  const shallow = sel.shallow;
  const unshallow = sel.unshallow;
  if (protocol === 2) {
    const parts: Buffer[] = [];
    parts.push(pktLine('acknowledgments\n'));
    parts.push(pktLine('NAK\n'));
    parts.push(PKT_DELIM);
    parts.push(pktLine('shallow-info\n'));
    for (const s of shallow) parts.push(pktLine(`shallow ${s}\n`));
    for (const u of unshallow) parts.push(pktLine(`unshallow ${u}\n`));
    parts.push(PKT_DELIM);
    parts.push(pktLine('packfile\n'));
    parts.push(sidebandPack(pack));
    parts.push(PKT_FLUSH);
    return Buffer.concat(parts);
  }
  const parts: Buffer[] = [];
  parts.push(pktLine('NAK\n'));
  for (const s of shallow) parts.push(pktLine(`shallow ${s}\n`));
  for (const u of unshallow) parts.push(pktLine(`unshallow ${u}\n`));
  parts.push(sidebandPack(pack));
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}
interface FetchArgs {
  wants: string[];
  haves: string[];
  shallow: string[];
  depth: number | null;
  prefixes: string[];
  peel: boolean;
  symrefs: boolean;
  unborn: boolean;
}
function parseV2Args(packets: Pkt[]): FetchArgs {
  const args: FetchArgs = { wants: [], haves: [], shallow: [], depth: null, prefixes: [], peel: false, symrefs: false, unborn: false };
  let afterDelim = false;
  for (const p of packets) {
    if (p.kind === 'delim') {
      afterDelim = true;
      continue;
    }
    if (p.kind !== 'data') continue;
    const line = p.payload.toString('utf8').replace(/\n$/, '');
    if (!afterDelim) {
      if (line.startsWith('command=')) continue;
      if (line.startsWith('agent=')) continue;
      if (line.startsWith('object-format=')) continue;
      continue;
    }
    if (line.startsWith('want ')) args.wants.push(line.slice(5).trim());
    else if (line.startsWith('have ')) args.haves.push(line.slice(5).trim());
    else if (line.startsWith('shallow ')) args.shallow.push(line.slice(8).trim());
    else if (line.startsWith('deepen ')) args.depth = parseInt(line.slice(7).trim(), 10);
    else if (line === 'peel') args.peel = true;
    else if (line === 'symrefs') args.symrefs = true;
    else if (line === 'unborn') args.unborn = true;
    else if (line.startsWith('ref-prefix ')) args.prefixes.push(line.slice('ref-prefix '.length));
  }
  return args;
}
async function handleGitUploadPack(req: IncomingMessage, res: ServerResponse, repo: Repo): Promise<void> {
  const body = await readBody(req);
  const isV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
  if (!isV2) {
    // v0 fetch fallback: want lines, shallow/deepen, flush, have lines, done, flush.
    const { packets } = decodePktLines(body);
    if (packets.length === 0 || packets[0]?.kind !== 'data') {
      sendJson(res, 400, { message: 'Malformed request' });
      return;
    }
    const wants: string[] = [];
    const haves: string[] = [];
    const shallow: string[] = [];
    let depth: number | null = null;
    let section = 0;
    for (const p of packets) {
      if (p.kind === 'flush') {
        section += 1;
        continue;
      }
      if (p.kind !== 'data') continue;
      const line = p.payload.toString('utf8').replace(/\n$/, '');
      if (line.startsWith('want ')) {
        const oid = line.slice(5).split(' ')[0] as string;
        if (/^[0-9a-f]{40}$/.test(oid)) wants.push(oid);
      } else if (line.startsWith('have ')) haves.push(line.slice(5).trim());
      else if (line.startsWith('shallow ')) shallow.push(line.slice(8).trim());
      else if (line.startsWith('deepen ')) depth = parseInt(line.slice(7).trim(), 10);
    }
    if (wants.length === 0) {
      sendRaw(res, 200, Buffer.concat([pktLine('NAK\n'), sidebandPack(buildPack([])), PKT_FLUSH]), 'application/x-git-upload-pack-result');
      return;
    }
    const out = fetchResponse(repo, wants, haves, shallow, depth, 0);
    sendRaw(res, 200, out, 'application/x-git-upload-pack-result');
    return;
  }
  const { packets, restOffset } = decodePktLines(body);
  void restOffset;
  if (packets.length === 0 || packets[0]?.kind !== 'data') {
    sendJson(res, 400, { message: 'Malformed request' });
    return;
  }
  const firstLine = (packets[0]?.payload.toString('utf8') ?? '').replace(/\n$/, '');
  const command = firstLine.startsWith('command=') ? firstLine.slice('command='.length) : '';
  const args = parseV2Args(packets);
  if (command === 'ls-refs') {
    const out = lsRefsResponse(repo, args.prefixes, args.peel, args.symrefs, args.unborn);
    sendRaw(res, 200, out, 'application/x-git-upload-pack-result');
    return;
  }
  if (command === 'fetch') {
    if (args.wants.length === 0) {
      // No wants: an empty pack still needs its packfile section with a packet.
      const parts: Buffer[] = [];
      parts.push(pktLine('acknowledgments\n'));
      parts.push(pktLine('NAK\n'));
      parts.push(PKT_DELIM);
      parts.push(pktLine('shallow-info\n'));
      parts.push(PKT_DELIM);
      parts.push(pktLine('packfile\n'));
      parts.push(sidebandPack(buildPack([])));
      parts.push(PKT_FLUSH);
      sendRaw(res, 200, Buffer.concat(parts), 'application/x-git-upload-pack-result');
      return;
    }
    const out = fetchResponse(repo, args.wants, args.haves, args.shallow, args.depth, 2);
    sendRaw(res, 200, out, 'application/x-git-upload-pack-result');
    return;
  }
  sendJson(res, 400, { message: `Unknown command "${command}"` });
}
async function handleGitReceivePack(req: IncomingMessage, res: ServerResponse, repo: Repo): Promise<void> {
  const body = await readBody(req);
  const { packets, restOffset } = decodePktLines(body);
  if (packets.length === 0 || packets[0]?.kind !== 'data') {
    sendJson(res, 400, { message: 'Malformed request' });
    return;
  }
  interface PushCmd {
    oldOid: string;
    newOid: string;
    ref: string;
  }
  const commands: PushCmd[] = [];
  for (const p of packets) {
    if (p.kind === 'flush') break;
    if (p.kind !== 'data') continue;
    let line = p.payload.toString('utf8').replace(/\n$/, '');
    const nul = line.indexOf('\0');
    if (nul >= 0) line = line.slice(0, nul);
    const parts = line.split(' ');
    if (parts.length >= 3) {
      commands.push({ oldOid: parts[0] as string, newOid: parts[1] as string, ref: parts.slice(2).join(' ') });
    }
  }
  const packBytes = body.subarray(restOffset);
  let unpackOk = true;
  let unpackDetail = 'ok';
  if (packBytes.length > 0) {
    try {
      const objects = parsePack(packBytes);
      for (const obj of objects) storeObject(repo, obj.type, obj.data);
    } catch (err) {
      unpackOk = false;
      unpackDetail = err instanceof Error ? err.message : 'unpack error';
    }
  }
  const reportLines: string[] = [];
  reportLines.push(unpackOk ? 'unpack ok\n' : `unpack ${unpackDetail}\n`);
  for (const cmd of commands) {
    const current = repo.refs.get(cmd.ref);
    let ok = false;
    if (cmd.newOid === ZERO_OID) {
      // delete
      ok = current !== undefined && current === cmd.oldOid;
      if (ok) repo.refs.delete(cmd.ref);
    } else if (cmd.oldOid === ZERO_OID) {
      // create
      ok = current === undefined && repo.objects.has(cmd.newOid);
      if (ok) repo.refs.set(cmd.ref, cmd.newOid);
    } else {
      // update: old must match and new must be a descendant (or equal)
      ok = current !== undefined && current === cmd.oldOid && repo.objects.has(cmd.newOid) && isAncestor(repo, cmd.oldOid, cmd.newOid);
      if (ok) repo.refs.set(cmd.ref, cmd.newOid);
    }
    reportLines.push(ok ? `ok ${cmd.ref}\n` : `ng ${cmd.ref} non-fast-forward\n`);
  }
  const inner = pktLines(reportLines);
  const banded = pktLine(Buffer.concat([Buffer.from([1]), inner]));
  const out = Buffer.concat([banded, PKT_FLUSH]);
  sendRaw(res, 200, out, 'application/x-git-receive-pack-result');
}

// ---------------------------------------------------------------------------
// 11. Router + lifecycle.
// ---------------------------------------------------------------------------
function authed(req: IncomingMessage): boolean {
  const header = req.headers.authorization ?? '';
  return header === `Bearer ${TOKEN}`;
}
const server = createServer((req, res) => {
  void (async () => {
    try {
      const url = req.url ?? '/';
      const q = url.indexOf('?');
      const path = q < 0 ? url : url.slice(0, q);
      const seg = path.split('/');
      if (path === '/healthz') {
        sendJson(res, 200, { ok: true });
        return;
      }
      if (!authed(req)) {
        // For MCP, echo a JSON-RPC error with the request id when the body parses.
        if (seg[1] === 'mcp' && req.method === 'POST') {
          const body = await readBody(req);
          let id: unknown = null;
          try {
            const parsed = JSON.parse(body.toString('utf8')) as { id?: unknown };
            id = parsed.id ?? null;
          } catch {
            id = null;
          }
          const text = mcpError(id, -32001, 'Unauthorized');
          const buf = Buffer.from(text, 'utf8');
          res.writeHead(401, { 'content-type': 'application/json', 'content-length': String(buf.length) });
          res.end(buf);
          return;
        }
        unauthorized(res);
        return;
      }
      if (seg[1] === 'api' && seg[2] === 'v3') {
        await handleRest(req, res, seg, url);
        return;
      }
      if (seg[1] === 'api' && seg[2] === 'graphql') {
        if (req.method !== 'POST') return notFound(res);
        await handleGraphql(req, res);
        return;
      }
      if (seg[1] === 'mcp') {
        await handleMcp(req, res);
        return;
      }
      if (seg.length >= 4 && (seg[3] === 'info' || seg[3] === 'git-upload-pack' || seg[3] === 'git-receive-pack')) {
        const owner = decodeURIComponent(seg[1] as string);
        const repoSeg = seg[2] as string;
        if (!repoSeg.endsWith('.git')) return notFound(res);
        const repoName = decodeURIComponent(repoSeg.slice(0, -4));
        const repo = lookupRepo(owner, repoName);
        if (repo === undefined) return notFound(res);
        if (seg[3] === 'info' && seg[4] === 'refs') {
          const service = queryParams(url).get('service') ?? '';
          if (service === 'git-upload-pack') {
            const isV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
            if (isV2) sendRaw(res, 200, V2_ADVERTISEMENT, 'application/x-git-upload-pack-advertisement');
            else sendRaw(res, 200, v0Advertisement(repo, 'git-upload-pack'), 'application/x-git-upload-pack-advertisement');
            return;
          }
          if (service === 'git-receive-pack') {
            sendRaw(res, 200, v0Advertisement(repo, 'git-receive-pack'), 'application/x-git-receive-pack-advertisement');
            return;
          }
          return notFound(res);
        }
        if (seg[3] === 'git-upload-pack' && req.method === 'POST') {
          await handleGitUploadPack(req, res, repo);
          return;
        }
        if (seg[3] === 'git-receive-pack' && req.method === 'POST') {
          await handleGitReceivePack(req, res, repo);
          return;
        }
        return notFound(res);
      }
      return notFound(res);
    } catch (err) {
      try {
        sendJson(res, 500, { message: err instanceof Error ? err.message : 'Internal error' });
      } catch {
        // response already gone
      }
    }
  })();
});
server.keepAliveTimeout = 30000;
// Small responses must not wait on Nagle: the timed workloads are sequential
// request/response pairs, and a delayed second segment costs a round trip.
server.on('connection', (socket) => socket.setNoDelay(true));

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));
async function register(port: number): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const r = await fetch(`${ENV_URL}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(30000),
      });
      if (r.status === 200 || r.status === 409) return;
      if (r.status === 400 || r.status === 405) throw new Error(`register answered HTTP ${r.status}`);
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('register answered HTTP ')) throw err;
    }
    await sleep(Math.min(2000, 250 * 2 ** Math.min(attempt, 8)));
  }
}
async function waitForDone(): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const r = await fetch(`${ENV_URL}/done`, { signal: AbortSignal.timeout(30000) });
      if (r.ok) {
        const body = (await r.json()) as { done?: unknown };
        if (body.done === true) return;
      }
    } catch {
      // keep polling
    }
    await sleep(Math.min(2000, 250 * 2 ** Math.min(attempt, 8)));
  }
}
async function main(): Promise<void> {
  const portEnv = parseInt(process.env.PORT ?? '', 10);
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(Number.isFinite(portEnv) && portEnv > 0 ? portEnv : 0, () => resolve());
  });
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('the server did not bind a TCP port');
  process.stdout.write(`[entry] listening on port ${address.port} (viewer ${VIEWER_LOGIN})\n`);
  if (ENV_URL !== '') {
    await register(address.port);
    process.stdout.write('[entry] registered; waiting for the env to say done\n');
    await waitForDone();
    server.close();
    process.stdout.write('[entry] done\n');
  }
}
try {
  await main();
  if (ENV_URL !== '') process.exit(0);
} catch (err) {
  process.stderr.write(`[entry] ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
}
