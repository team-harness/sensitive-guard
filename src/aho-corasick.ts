/**
 * Aho–Corasick multi-pattern matcher. O(n + matches) per scan regardless of
 * how many patterns are loaded, so a 50k-word list costs about the same as 50.
 */

interface Node {
  next: Map<string, number>;
  fail: number;
  /** Indices into `patterns` of words ending at this node (incl. via fail links). */
  out: number[];
  depth: number;
}

export interface AcMatch {
  /** Index of the matched pattern as passed to the constructor. */
  pattern: number;
  /** Start / end (exclusive) offsets in the scanned string (UTF-16). */
  start: number;
  end: number;
}

export class AhoCorasick {
  private readonly nodes: Node[] = [{ next: new Map(), fail: 0, out: [], depth: 0 }];
  readonly patterns: readonly string[];

  constructor(patterns: readonly string[]) {
    this.patterns = patterns;
    patterns.forEach((p, idx) => {
      if (!p) return;
      let cur = 0;
      for (const ch of p) {
        let nxt = this.nodes[cur]!.next.get(ch);
        if (nxt === undefined) {
          nxt = this.nodes.length;
          this.nodes.push({ next: new Map(), fail: 0, out: [], depth: this.nodes[cur]!.depth + ch.length });
          this.nodes[cur]!.next.set(ch, nxt);
        }
        cur = nxt;
      }
      this.nodes[cur]!.out.push(idx);
    });
    this.build();
  }

  private build(): void {
    const queue: number[] = [];
    for (const child of this.nodes[0]!.next.values()) queue.push(child);
    for (let qi = 0; qi < queue.length; qi++) {
      const u = queue[qi]!;
      const node = this.nodes[u]!;
      for (const [ch, v] of node.next) {
        let f = node.fail;
        while (f !== 0 && !this.nodes[f]!.next.has(ch)) f = this.nodes[f]!.fail;
        const cand = this.nodes[f]!.next.get(ch);
        const vNode = this.nodes[v]!;
        vNode.fail = cand !== undefined && cand !== v ? cand : 0;
        vNode.out.push(...this.nodes[vNode.fail]!.out);
        queue.push(v);
      }
    }
  }

  /** Return every (possibly overlapping) occurrence of every pattern. */
  search(text: string): AcMatch[] {
    const res: AcMatch[] = [];
    let state = 0;
    let i = 0;
    for (const ch of text) {
      while (state !== 0 && !this.nodes[state]!.next.has(ch)) state = this.nodes[state]!.fail;
      state = this.nodes[state]!.next.get(ch) ?? 0;
      i += ch.length;
      for (const p of this.nodes[state]!.out) {
        const len = this.patterns[p]!.length;
        res.push({ pattern: p, start: i - len, end: i });
      }
    }
    return res;
  }
}
