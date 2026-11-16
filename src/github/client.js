'use strict';

const { filePath, MAX_FILES, MAX_FILE_BYTES } = require('../security/payload');

const enc = encodeURIComponent;

// Records what would have been sent. Used when no token is configured so the
// whole pipeline can run offline, in tests and in the demo.
class DryRunGitHub {
  constructor() {
    this.mode = 'dry-run';
    this.calls = [];
  }

  async getPullRequestFiles() {
    throw new Error('payload carried no files and no GITHUB_TOKEN is configured to fetch them');
  }

  async openFixPullRequest(req) {
    this.calls.push({ op: 'openFixPullRequest', ...req });
    return { number: null, url: null, branch: req.branch };
  }

  async setStatus(req) {
    this.calls.push({ op: 'setStatus', ...req });
  }

  async comment(req) {
    this.calls.push({ op: 'comment', ...req });
  }
}

// Thin client over the GitHub REST API. owner/repo/ref values reaching this
// class have already passed the webhook schema, and are still URL-encoded
// here so a future caller cannot turn one into a different endpoint.
class RestGitHub {
  constructor({ token, apiUrl = 'https://api.github.com', fetchImpl = fetch }) {
    this.mode = 'live';
    this.token = token;
    this.apiUrl = apiUrl.replace(/\/$/, '');
    this.fetch = fetchImpl;
  }

  async #request(method, path, body) {
    const res = await this.fetch(`${this.apiUrl}${path}`, {
      method,
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${this.token}`,
        'x-github-api-version': '2022-11-28',
        'user-agent': 'iac-guardian',
        ...(body ? { 'content-type': 'application/json' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
      // Never follow a redirect with the token attached.
      redirect: 'error',
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) {
      // The response body can echo request data; keep it out of error text.
      throw new Error(`GitHub ${method} ${path.split('?')[0]} failed with ${res.status}`);
    }
    return res.status === 204 ? null : res.json();
  }

  /** Fetches the IaC files a pull request touches, at the PR's head commit. */
  async getPullRequestFiles({ owner, repo, number, sha }) {
    const base = `/repos/${enc(owner)}/${enc(repo)}`;
    const listed = await this.#request('GET', `${base}/pulls/${number}/files?per_page=100`);
    const wanted = listed
      .filter((f) => f.status !== 'removed' && filePath.safeParse(f.filename).success)
      .slice(0, MAX_FILES);

    const files = [];
    for (const f of wanted) {
      const path = f.filename.split('/').map(enc).join('/');
      const blob = await this.#request('GET', `${base}/contents/${path}?ref=${enc(sha)}`);
      if (blob.encoding !== 'base64' || blob.size > MAX_FILE_BYTES) continue;
      files.push({ path: f.filename, content: Buffer.from(blob.content, 'base64').toString('utf8') });
    }
    return files;
  }

  // Uses the Git data API so all patched files land in one commit. The fix is
  // proposed as a pull request into the contributor's branch: a human still
  // has to review and merge it, the agent never pushes to a protected branch.
  async openFixPullRequest({ owner, repo, headRef, headSha, branch, files, title, body }) {
    const base = `/repos/${enc(owner)}/${enc(repo)}`;
    const parent = await this.#request('GET', `${base}/git/commits/${enc(headSha)}`);
    const tree = await this.#request('POST', `${base}/git/trees`, {
      base_tree: parent.tree.sha,
      tree: files.map((f) => ({ path: f.path, mode: '100644', type: 'blob', content: f.content })),
    });
    const commit = await this.#request('POST', `${base}/git/commits`, {
      message: title,
      tree: tree.sha,
      parents: [headSha],
    });
    await this.#request('POST', `${base}/git/refs`, { ref: `refs/heads/${branch}`, sha: commit.sha });
    const pr = await this.#request('POST', `${base}/pulls`, { title, body, head: branch, base: headRef });
    return { number: pr.number, url: pr.html_url, branch };
  }

  async setStatus({ owner, repo, sha, state, description }) {
    await this.#request('POST', `/repos/${enc(owner)}/${enc(repo)}/statuses/${enc(sha)}`, {
      state,
      description: description.slice(0, 140),
      context: 'iac-guardian/policy-gate',
    });
  }

  async comment({ owner, repo, number, body }) {
    await this.#request('POST', `/repos/${enc(owner)}/${enc(repo)}/issues/${number}/comments`, { body });
  }
}

module.exports = { DryRunGitHub, RestGitHub };
